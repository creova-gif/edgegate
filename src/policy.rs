use http::Method;

use crate::auth::WorkloadIdentity;
use crate::config::CompiledPolicyRule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
}

/// Trait seam for authorization policy evaluation.
pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        identity: &WorkloadIdentity,
        route_id: &str,
        method: &Method,
        path: &str,
    ) -> PolicyDecision;
}

/// Default-deny policy engine checking `(org_id, workload_id, route_id, method, path_prefix)`.
#[derive(Debug, Clone)]
pub struct DefaultDenyPolicyEngine {
    rules: Vec<CompiledPolicyRule>,
}

impl DefaultDenyPolicyEngine {
    pub fn new(rules: Vec<CompiledPolicyRule>) -> Self {
        Self { rules }
    }
}

impl PolicyEngine for DefaultDenyPolicyEngine {
    fn evaluate(
        &self,
        identity: &WorkloadIdentity,
        route_id: &str,
        method: &Method,
        path: &str,
    ) -> PolicyDecision {
        for rule in &self.rules {
            if rule.org_id != identity.org_id {
                continue;
            }
            if let Some(ref allowed_workload) = rule.workload_id {
                if allowed_workload != &identity.workload_id {
                    continue;
                }
            }
            if rule.route_id != route_id {
                continue;
            }
            if !rule.methods.contains(method) {
                continue;
            }
            if path_matches_prefix(path, &rule.path_prefix) {
                return PolicyDecision::Allow;
            }
        }

        PolicyDecision::Deny {
            reason: format!(
                "default-deny: org '{}' workload '{}' not authorized for {} {} on route '{}'",
                identity.org_id, identity.workload_id, method, path, route_id
            ),
        }
    }
}

/// Segment-boundary-safe prefix check so `/v1/repos` matches `/v1/repos` and `/v1/repos/foo`,
/// but NEVER `/v1/repos-admin`.
pub fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    let trimmed = prefix.trim_end_matches('/');
    if path == trimmed {
        return true;
    }
    path.strip_prefix(trimmed)
        .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn sample_engine() -> DefaultDenyPolicyEngine {
        let mut methods = HashSet::new();
        methods.insert(Method::GET);
        DefaultDenyPolicyEngine::new(vec![CompiledPolicyRule {
            org_id: "org-alpha".to_string(),
            workload_id: Some("agent-1".to_string()),
            route_id: "github".to_string(),
            methods,
            path_prefix: "/v1/github/repos".to_string(),
        }])
    }

    #[test]
    fn allows_exact_org_workload_route_method_and_prefix() {
        let engine = sample_engine();
        let id = WorkloadIdentity {
            workload_id: "agent-1".to_string(),
            org_id: "org-alpha".to_string(),
        };
        assert_eq!(
            engine.evaluate(&id, "github", &Method::GET, "/v1/github/repos/edgegate"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn denies_cross_tenant_and_prefix_boundary_bypass() {
        let engine = sample_engine();
        let other_org = WorkloadIdentity {
            workload_id: "agent-1".to_string(),
            org_id: "org-beta".to_string(),
        };
        assert!(matches!(
            engine.evaluate(&other_org, "github", &Method::GET, "/v1/github/repos"),
            PolicyDecision::Deny { .. }
        ));

        let alpha = WorkloadIdentity {
            workload_id: "agent-1".to_string(),
            org_id: "org-alpha".to_string(),
        };
        assert!(matches!(
            engine.evaluate(&alpha, "github", &Method::GET, "/v1/github/repos-admin"),
            PolicyDecision::Deny { .. }
        ));
        assert!(matches!(
            engine.evaluate(&alpha, "github", &Method::DELETE, "/v1/github/repos"),
            PolicyDecision::Deny { .. }
        ));
    }
}
