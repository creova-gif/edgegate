use std::sync::{Arc, Mutex};
use std::time::Instant;

use http::{HeaderMap, Method};

use crate::auth::WorkloadIdentity;
use crate::config::CompiledPolicyRule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    RateLimited { reason: String },
}

/// Trait seam for authorization policy evaluation.
pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        identity: &WorkloadIdentity,
        route_id: &str,
        method: &Method,
        path: &str,
    ) -> PolicyDecision {
        self.evaluate_with_headers(identity, route_id, method, path, &HeaderMap::new())
    }

    fn evaluate_with_headers(
        &self,
        identity: &WorkloadIdentity,
        route_id: &str,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
    ) -> PolicyDecision;
}

/// Token-bucket rate limiter per policy rule (`Milestone 4`).
#[derive(Debug)]
struct TokenBucket {
    rate_per_sec: f64,
    capacity: f64,
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    fn new(rps: u32, burst: u32) -> Self {
        let capacity = f64::from(burst.max(1));
        Self {
            rate_per_sec: f64::from(rps.max(1)),
            capacity,
            state: Mutex::new((capacity, Instant::now())),
        }
    }

    fn try_acquire(&self) -> bool {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let elapsed = now.duration_since(guard.1).as_secs_f64();
        guard.0 = (guard.0 + elapsed * self.rate_per_sec).min(self.capacity);
        guard.1 = now;
        if guard.0 >= 1.0 {
            guard.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
struct PolicyRuleEntry {
    rule: CompiledPolicyRule,
    limiter: Option<Arc<TokenBucket>>,
}

/// Default-deny policy engine checking `(org_id, workload_id, required_roles, route_id, method, path_prefix)`
/// and enforcing optional per-rule token-bucket rate limits.
#[derive(Debug, Clone)]
pub struct DefaultDenyPolicyEngine {
    entries: Vec<PolicyRuleEntry>,
}

impl DefaultDenyPolicyEngine {
    pub fn new(rules: Vec<CompiledPolicyRule>) -> Self {
        let entries = rules
            .into_iter()
            .map(|rule| {
                let limiter = match (rule.rate_limit_rps, rule.rate_limit_burst) {
                    (Some(rps), Some(burst)) => Some(Arc::new(TokenBucket::new(rps, burst))),
                    (Some(rps), None) => Some(Arc::new(TokenBucket::new(rps, rps))),
                    (None, Some(burst)) => Some(Arc::new(TokenBucket::new(burst, burst))),
                    (None, None) => None,
                };
                PolicyRuleEntry { rule, limiter }
            })
            .collect();
        Self { entries }
    }
}

impl PolicyEngine for DefaultDenyPolicyEngine {
    fn evaluate_with_headers(
        &self,
        identity: &WorkloadIdentity,
        route_id: &str,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
    ) -> PolicyDecision {
        for entry in &self.entries {
            let rule = &entry.rule;
            if rule.org_id != identity.org_id {
                continue;
            }
            if let Some(ref allowed_workload) = rule.workload_id {
                if allowed_workload != &identity.workload_id {
                    continue;
                }
            }
            if !rule
                .required_roles
                .iter()
                .all(|req_role| identity.roles.contains(req_role))
            {
                continue;
            }
            if rule.route_id != route_id {
                continue;
            }
            if !rule.methods.contains(method) {
                continue;
            }
            if !path_matches_prefix(path, &rule.path_prefix) {
                continue;
            }
            if !rule.required_headers.iter().all(|(k, expected_v)| {
                headers.get(k.as_str()).and_then(|v| v.to_str().ok()) == Some(expected_v.as_str())
            }) {
                continue;
            }
            if let Some(ref bucket) = entry.limiter {
                if !bucket.try_acquire() {
                    return PolicyDecision::RateLimited {
                        reason: format!(
                            "rate-limited: org '{}' workload '{}' exceeded token bucket on route '{}'",
                            identity.org_id, identity.workload_id, route_id
                        ),
                    };
                }
            }
            return PolicyDecision::Allow;
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
    use std::collections::{HashMap, HashSet};

    use super::*;

    fn sample_engine() -> DefaultDenyPolicyEngine {
        let mut methods = HashSet::new();
        methods.insert(Method::GET);
        DefaultDenyPolicyEngine::new(vec![CompiledPolicyRule {
            org_id: "org-alpha".to_string(),
            workload_id: Some("agent-1".to_string()),
            required_roles: ["repo:read".to_string()].into_iter().collect(),
            route_id: "github".to_string(),
            methods,
            path_prefix: "/v1/github/repos".to_string(),
            required_headers: HashMap::new(),
            rate_limit_rps: None,
            rate_limit_burst: None,
        }])
    }

    #[test]
    fn allows_exact_org_workload_roles_route_method_and_prefix() {
        let engine = sample_engine();
        let id = WorkloadIdentity {
            workload_id: "agent-1".to_string(),
            org_id: "org-alpha".to_string(),
            roles: ["repo:read".to_string()].into_iter().collect(),
        };
        assert_eq!(
            engine.evaluate(&id, "github", &Method::GET, "/v1/github/repos/edgegate"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn denies_missing_required_role() {
        let engine = sample_engine();
        let id = WorkloadIdentity {
            workload_id: "agent-1".to_string(),
            org_id: "org-alpha".to_string(),
            roles: HashSet::new(),
        };
        assert!(matches!(
            engine.evaluate(&id, "github", &Method::GET, "/v1/github/repos/edgegate"),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn denies_cross_tenant_and_prefix_boundary_bypass() {
        let engine = sample_engine();
        let other_org = WorkloadIdentity {
            workload_id: "agent-1".to_string(),
            org_id: "org-beta".to_string(),
            roles: ["repo:read".to_string()].into_iter().collect(),
        };
        assert!(matches!(
            engine.evaluate(&other_org, "github", &Method::GET, "/v1/github/repos"),
            PolicyDecision::Deny { .. }
        ));

        let alpha = WorkloadIdentity {
            workload_id: "agent-1".to_string(),
            org_id: "org-alpha".to_string(),
            roles: ["repo:read".to_string()].into_iter().collect(),
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
