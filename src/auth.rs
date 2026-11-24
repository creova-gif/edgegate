use std::collections::HashMap;

use http::HeaderMap;
use subtle::ConstantTimeEq;

use crate::config::{sha256_digest, CompiledWorkload};
use crate::EdgeGateError;

/// Locked Milestone 1 workload authentication header (unconditionally stripped before upstream forwarding).
pub const WORKLOAD_TOKEN_HEADER: &str = "x-edgegate-token";

/// Verified workload identity for Milestone 1 (`roles` deferred to M2 RBAC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadIdentity {
    pub workload_id: String,
    pub org_id: String,
}

/// Trait seam for workload authentication (M1 header token; M2 Boxlet UDS/socket peer identity).
pub trait WorkloadAuthenticator: Send + Sync {
    fn authenticate(&self, headers: &HeaderMap) -> Result<WorkloadIdentity, EdgeGateError>;
}

/// Constant-time SHA-256 token authenticator backed by `CompiledConfig.workloads`.
#[derive(Debug, Clone)]
pub struct HeaderTokenAuthenticator {
    workloads: HashMap<[u8; 32], CompiledWorkload>,
}

impl HeaderTokenAuthenticator {
    pub fn new(workloads: HashMap<[u8; 32], CompiledWorkload>) -> Self {
        Self { workloads }
    }
}

impl WorkloadAuthenticator for HeaderTokenAuthenticator {
    fn authenticate(&self, headers: &HeaderMap) -> Result<WorkloadIdentity, EdgeGateError> {
        let header_val = headers
            .get(WORKLOAD_TOKEN_HEADER)
            .ok_or_else(|| EdgeGateError::Unauthorized("missing X-EdgeGate-Token".to_string()))?;

        let raw_token = header_val
            .to_str()
            .map_err(|_| EdgeGateError::Unauthorized("non-ASCII X-EdgeGate-Token".to_string()))?
            .trim();

        if raw_token.is_empty() {
            return Err(EdgeGateError::Unauthorized(
                "empty X-EdgeGate-Token".to_string(),
            ));
        }

        let candidate_digest = sha256_digest(raw_token.as_bytes());
        if let Some((stored_digest, workload)) = self.workloads.get_key_value(&candidate_digest) {
            if bool::from(stored_digest.ct_eq(&candidate_digest)) {
                return Ok(WorkloadIdentity {
                    workload_id: workload.workload_id.clone(),
                    org_id: workload.org_id.clone(),
                });
            }
        }

        Err(EdgeGateError::Unauthorized(
            "invalid workload token".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::*;

    fn test_auth() -> HeaderTokenAuthenticator {
        let mut map = HashMap::new();
        map.insert(
            sha256_digest(b"secret-workload-token"),
            CompiledWorkload {
                workload_id: "agent-1".to_string(),
                org_id: "org-alpha".to_string(),
            },
        );
        HeaderTokenAuthenticator::new(map)
    }

    #[test]
    fn authenticates_valid_token() {
        let auth = test_auth();
        let mut headers = HeaderMap::new();
        headers.insert(
            WORKLOAD_TOKEN_HEADER,
            HeaderValue::from_static("secret-workload-token"),
        );

        let id = auth
            .authenticate(&headers)
            .unwrap_or_else(|e| panic!("expected ok: {e}"));
        assert_eq!(id.workload_id, "agent-1");
        assert_eq!(id.org_id, "org-alpha");
    }

    #[test]
    fn rejects_missing_or_invalid_token() {
        let auth = test_auth();
        let empty = HeaderMap::new();
        assert!(matches!(
            auth.authenticate(&empty),
            Err(EdgeGateError::Unauthorized(_))
        ));

        let mut wrong = HeaderMap::new();
        wrong.insert(
            WORKLOAD_TOKEN_HEADER,
            HeaderValue::from_static("wrong-token"),
        );
        assert!(matches!(
            auth.authenticate(&wrong),
            Err(EdgeGateError::Unauthorized(_))
        ));
    }
}
