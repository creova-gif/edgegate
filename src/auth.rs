use std::collections::{HashMap, HashSet};

use http::HeaderMap;
use subtle::ConstantTimeEq;

use crate::config::{sha256_digest, CompiledWorkload};
use crate::EdgeGateError;

/// Locked workload authentication header (unconditionally stripped before upstream forwarding).
pub const WORKLOAD_TOKEN_HEADER: &str = "x-edgegate-token";

/// Verified workload identity with RBAC roles (`Milestone 2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadIdentity {
    pub workload_id: String,
    pub org_id: String,
    pub roles: HashSet<String>,
}

/// Trait seam for workload authentication (header token or transport-bound UDS socket).
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
                    roles: workload.roles.clone(),
                });
            }
        }

        Err(EdgeGateError::Unauthorized(
            "invalid workload token".to_string(),
        ))
    }
}

/// Zero-token transport-bound authenticator used by dedicated per-sandbox Unix domain socket listeners.
#[derive(Debug, Clone)]
pub struct TransportBoundAuthenticator {
    identity: WorkloadIdentity,
}

impl TransportBoundAuthenticator {
    pub fn new(workload: CompiledWorkload) -> Self {
        Self {
            identity: WorkloadIdentity {
                workload_id: workload.workload_id,
                org_id: workload.org_id,
                roles: workload.roles,
            },
        }
    }
}

impl WorkloadAuthenticator for TransportBoundAuthenticator {
    fn authenticate(&self, _headers: &HeaderMap) -> Result<WorkloadIdentity, EdgeGateError> {
        Ok(self.identity.clone())
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
                roles: ["repo:read".to_string()].into_iter().collect(),
            },
        );
        HeaderTokenAuthenticator::new(map)
    }

    #[test]
    fn authenticates_valid_token_with_roles() {
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
        assert!(id.roles.contains("repo:read"));
    }

    #[test]
    fn transport_bound_authenticator_requires_zero_headers() {
        let auth = TransportBoundAuthenticator::new(CompiledWorkload {
            workload_id: "boxlet-sandbox-1".to_string(),
            org_id: "org-alpha".to_string(),
            roles: ["inference:call".to_string()].into_iter().collect(),
        });
        let id = auth
            .authenticate(&HeaderMap::new())
            .unwrap_or_else(|e| panic!("expected ok: {e}"));
        assert_eq!(id.workload_id, "boxlet-sandbox-1");
        assert!(id.roles.contains("inference:call"));
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
