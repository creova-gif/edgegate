use http::header::{HeaderName, HeaderValue, CONNECTION, HOST, PROXY_AUTHORIZATION};
use http::HeaderMap;

use crate::auth::WORKLOAD_TOKEN_HEADER;
use crate::config::CompiledRoute;
use crate::policy::path_matches_prefix;
use crate::EdgeGateError;

/// Standard RFC 9110 hop-by-hop headers (excluding `content-length` and `transfer-encoding`,
/// which are framing headers managed by `hyper` v1).
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// Fail-closed pre-policy path validator.
/// Rejects raw or percent-encoded dot-segments, backslashes, null bytes, control chars,
/// and unnormalized double slashes with `400 Bad Request` before route/policy evaluation.
pub fn validate_request_path(path: &str) -> Result<(), EdgeGateError> {
    if !path.starts_with('/') {
        return Err(EdgeGateError::BadRequest(
            "request path must start with '/'".to_string(),
        ));
    }
    if path.contains("//") || path.contains('\\') || path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(EdgeGateError::BadRequest(
            "invalid path characters or double slash".to_string(),
        ));
    }

    let lower = path.to_ascii_lowercase();
    if lower.contains("%00") || lower.contains("%5c") || lower.contains("%2f") {
        return Err(EdgeGateError::BadRequest(
            "encoded null byte, backslash, or slash rejected".to_string(),
        ));
    }

    for segment in lower.split('/') {
        if segment == "."
            || segment == ".."
            || segment == "%2e"
            || segment == "%2e%2e"
            || segment == ".%2e"
            || segment == "%2e."
        {
            return Err(EdgeGateError::BadRequest(
                "dot-segment path traversal rejected".to_string(),
            ));
        }
    }

    Ok(())
}

/// Deterministic L7 route table matching explicit path prefixes (longest-prefix first) and optional Host.
#[derive(Debug, Clone)]
pub struct Router {
    routes: Vec<CompiledRoute>,
}

impl Router {
    pub fn new(routes: Vec<CompiledRoute>) -> Self {
        Self { routes }
    }

    pub fn match_route(&self, path: &str, host: Option<&str>) -> Option<&CompiledRoute> {
        let req_host = host.map(|h| h.split(':').next().unwrap_or(h).trim().to_ascii_lowercase());

        for route in &self.routes {
            if let Some(ref expected_host) = route.host {
                if req_host.as_deref() != Some(expected_host.as_str()) {
                    continue;
                }
            }
            if path_matches_prefix(path, &route.path_prefix) {
                return Some(route);
            }
        }
        None
    }
}

/// Computes the outbound upstream path + optional query after optional `strip_prefix`.
pub fn rewrite_upstream_path_and_query(
    path: &str,
    query: Option<&str>,
    route: &CompiledRoute,
) -> String {
    let rewritten = if route.strip_prefix {
        let prefix = route.path_prefix.trim_end_matches('/');
        if prefix.is_empty() {
            path
        } else {
            let stripped = path.strip_prefix(prefix).unwrap_or(path);
            if stripped.is_empty() {
                "/"
            } else {
                stripped
            }
        }
    } else {
        path
    };

    match query {
        Some(q) if !q.is_empty() => format!("{rewritten}?{q}"),
        _ => rewritten.to_string(),
    }
}

/// Sanitizes outbound request headers:
/// 1. Strips RFC 9110 hop-by-hop headers AND every header named in incoming `Connection` headers
///    (while preserving `content-length` and `transfer-encoding` managed by `hyper` v1).
/// 2. Unconditionally strips `X-EdgeGate-Token`, `Proxy-Authorization`, and the route's target
///    credential header (if configured) so workloads cannot smuggle or override upstream auth.
/// 3. Unconditionally rewrites `Host` to the selected upstream backend's configured authority.
pub fn sanitize_outbound_headers(
    incoming: &HeaderMap,
    backend_authority: &str,
    target_credential_header: Option<&HeaderName>,
) -> Result<HeaderMap, EdgeGateError> {
    let mut dynamic_hop_headers: Vec<String> = Vec::new();
    for val in incoming.get_all(CONNECTION) {
        if let Ok(s) = val.to_str() {
            for token in s.split(',') {
                let name = token.trim().to_ascii_lowercase();
                if !name.is_empty() && name != "content-length" && name != "transfer-encoding" {
                    dynamic_hop_headers.push(name);
                }
            }
        }
    }

    let mut out = HeaderMap::with_capacity(incoming.len() + 2);
    for (name, value) in incoming {
        let lower = name.as_str();
        if lower == WORKLOAD_TOKEN_HEADER
            || name == PROXY_AUTHORIZATION
            || name == HOST
            || HOP_BY_HOP_HEADERS.contains(&lower)
            || dynamic_hop_headers.iter().any(|h| h == lower)
            || target_credential_header.is_some_and(|target| target == name)
        {
            continue;
        }
        out.append(name.clone(), value.clone());
    }

    let host_val = HeaderValue::from_str(backend_authority).map_err(|e| {
        EdgeGateError::Internal(format!(
            "invalid backend authority '{backend_authority}': {e}"
        ))
    })?;
    out.insert(HOST, host_val);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use http::header::{AUTHORIZATION, CONTENT_LENGTH, TRANSFER_ENCODING};

    use super::*;

    #[test]
    fn rejects_traversal_variants_fail_closed() {
        for bad in [
            "/v1/github/../admin",
            "/v1/github/%2e%2e/admin",
            "/v1/github/%2E%2E/admin",
            "/v1/github/.%2e/admin",
            "/v1/github/%2e./admin",
            "/v1/github/./repos",
            "/v1/github//repos",
            "/v1/github\\admin",
            "/v1/github/%5cadmin",
            "/v1/github/%00admin",
        ] {
            assert!(
                matches!(
                    validate_request_path(bad),
                    Err(EdgeGateError::BadRequest(_))
                ),
                "expected 400 for path '{bad}'"
            );
        }
        assert!(validate_request_path("/v1/github/repos/edgegate").is_ok());
    }

    #[test]
    fn strips_hop_by_hop_connection_listed_and_target_cred_headers_while_preserving_framing() {
        let mut incoming = HeaderMap::new();
        incoming.insert(HOST, HeaderValue::from_static("spoofed.evil"));
        incoming.insert(WORKLOAD_TOKEN_HEADER, HeaderValue::from_static("tok-1"));
        incoming.insert(PROXY_AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        incoming.insert(AUTHORIZATION, HeaderValue::from_static("Bearer forged"));
        incoming.insert("x-api-key", HeaderValue::from_static("forged-key"));
        incoming.insert(
            CONNECTION,
            HeaderValue::from_static("x-custom-hop, keep-alive"),
        );
        incoming.insert("x-custom-hop", HeaderValue::from_static("drop-me"));
        incoming.insert("x-trace-id", HeaderValue::from_static("keep-me"));
        incoming.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        incoming.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));

        let target = HeaderName::from_static("x-api-key");
        let sanitized = sanitize_outbound_headers(&incoming, "upstream-a:9001", Some(&target))
            .unwrap_or_else(|e| panic!("unexpected err: {e}"));

        assert_eq!(
            sanitized.get(HOST).and_then(|v| v.to_str().ok()),
            Some("upstream-a:9001")
        );
        assert!(sanitized.get(WORKLOAD_TOKEN_HEADER).is_none());
        assert!(sanitized.get(PROXY_AUTHORIZATION).is_none());
        assert!(sanitized.get("x-api-key").is_none());
        assert!(sanitized.get(CONNECTION).is_none());
        assert!(sanitized.get("x-custom-hop").is_none());
        assert_eq!(
            sanitized.get("x-trace-id").and_then(|v| v.to_str().ok()),
            Some("keep-me")
        );
        assert!(sanitized.get(CONTENT_LENGTH).is_some());
        assert!(sanitized.get(TRANSFER_ENCODING).is_some());
    }
}
