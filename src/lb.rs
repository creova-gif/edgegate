use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{CompiledBackend, CompiledPool, LbStrategyConfig};
use crate::EdgeGateError;

/// RAII lease returned by `LoadBalancer::select`.
/// Decrements the backend's in-flight counter automatically on `Drop` so `LeastConnections`
/// never leaks counts on early error or client disconnect.
#[derive(Debug)]
pub struct BackendLease {
    pub pool_name: String,
    pub backend: CompiledBackend,
    pub allow_private_ip: bool,
    in_flight: Arc<AtomicUsize>,
}

impl Drop for BackendLease {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Trait seam for load balancing + passive/active backend health tracking.
pub trait LoadBalancer: Send + Sync {
    fn select(&self, pool_name: &str) -> Result<BackendLease, EdgeGateError>;
    fn record_success(&self, pool_name: &str, backend_id: &str);
    /// Record a passive backend failure (`502` connect/transport, `504` timeout, or upstream `5xx`).
    /// NEVER call this on local `503` pool exhaustion.
    fn record_failure(&self, pool_name: &str, backend_id: &str);
    /// Updates active health status from background HTTP health probes (`Milestone 2`).
    fn set_active_health(&self, pool_name: &str, backend_id: &str, healthy: bool);
}

#[derive(Debug)]
struct BackendState {
    config: CompiledBackend,
    in_flight: Arc<AtomicUsize>,
    active_healthy: AtomicBool,
    health: Mutex<PassiveHealth>,
}

#[derive(Debug)]
struct PassiveHealth {
    consecutive_failures: u32,
    ejected_until: Option<Instant>,
}

impl BackendState {
    fn is_healthy(&self, now: Instant) -> bool {
        if !self.active_healthy.load(Ordering::Acquire) {
            return false;
        }
        let mut guard = match self.health.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(until) = guard.ejected_until {
            if now < until {
                return false;
            }
            guard.ejected_until = None;
            guard.consecutive_failures = 0;
        }
        true
    }

    fn on_success(&self) {
        let mut guard = match self.health.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.consecutive_failures = 0;
        guard.ejected_until = None;
    }

    fn on_failure(&self, threshold: u32, cooldown: Duration, now: Instant) {
        let mut guard = match self.health.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
        if guard.consecutive_failures >= threshold {
            guard.ejected_until = Some(now + cooldown);
        }
    }
}

#[derive(Debug)]
struct PoolState {
    name: String,
    strategy: LbStrategyConfig,
    allow_private_ip: bool,
    passive_failure_threshold: u32,
    passive_cooldown: Duration,
    rr_cursor: AtomicUsize,
    backends: Vec<BackendState>,
}

/// Pool-aware load balancer supporting both `RoundRobin` and `LeastConnections`
/// plus passive error-based ejection and active probe health state.
#[derive(Debug)]
pub struct PoolLoadBalancer {
    pools: HashMap<String, PoolState>,
}

impl PoolLoadBalancer {
    pub fn from_pools(compiled: &HashMap<String, CompiledPool>) -> Self {
        let mut pools = HashMap::with_capacity(compiled.len());
        for (name, pool) in compiled {
            let backends = pool
                .backends
                .iter()
                .map(|b| BackendState {
                    config: b.clone(),
                    in_flight: Arc::new(AtomicUsize::new(0)),
                    active_healthy: AtomicBool::new(true),
                    health: Mutex::new(PassiveHealth {
                        consecutive_failures: 0,
                        ejected_until: None,
                    }),
                })
                .collect();
            pools.insert(
                name.clone(),
                PoolState {
                    name: pool.name.clone(),
                    strategy: pool.strategy,
                    allow_private_ip: pool.allow_private_ip,
                    passive_failure_threshold: pool.passive_failure_threshold,
                    passive_cooldown: pool.passive_cooldown,
                    rr_cursor: AtomicUsize::new(0),
                    backends,
                },
            );
        }
        Self { pools }
    }
}

impl LoadBalancer for PoolLoadBalancer {
    fn select(&self, pool_name: &str) -> Result<BackendLease, EdgeGateError> {
        let pool = self.pools.get(pool_name).ok_or_else(|| {
            EdgeGateError::ServiceUnavailable(format!("unknown upstream pool '{pool_name}'"))
        })?;
        let now = Instant::now();
        let len = pool.backends.len();
        if len == 0 {
            return Err(EdgeGateError::ServiceUnavailable(format!(
                "upstream pool '{pool_name}' has no backends"
            )));
        }

        let selected: Option<&BackendState> = match pool.strategy {
            LbStrategyConfig::RoundRobin => {
                let start = pool.rr_cursor.fetch_add(1, Ordering::Relaxed);
                (0..len)
                    .map(|offset| &pool.backends[(start + offset) % len])
                    .find(|b| b.is_healthy(now))
            }
            LbStrategyConfig::LeastConnections => {
                let start = pool.rr_cursor.fetch_add(1, Ordering::Relaxed);
                let mut best: Option<(&BackendState, usize)> = None;
                for offset in 0..len {
                    let candidate = &pool.backends[(start + offset) % len];
                    if !candidate.is_healthy(now) {
                        continue;
                    }
                    let active = candidate.in_flight.load(Ordering::Acquire);
                    match best {
                        None => best = Some((candidate, active)),
                        Some((_, best_active)) if active < best_active => {
                            best = Some((candidate, active));
                        }
                        _ => {}
                    }
                }
                best.map(|(b, _)| b)
            }
        };

        let backend = selected.ok_or_else(|| {
            EdgeGateError::ServiceUnavailable(format!(
                "all backends in pool '{pool_name}' are unhealthy or in passive failure cooldown"
            ))
        })?;

        backend.in_flight.fetch_add(1, Ordering::AcqRel);
        Ok(BackendLease {
            pool_name: pool.name.clone(),
            backend: backend.config.clone(),
            allow_private_ip: pool.allow_private_ip,
            in_flight: Arc::clone(&backend.in_flight),
        })
    }

    fn record_success(&self, pool_name: &str, backend_id: &str) {
        if let Some(pool) = self.pools.get(pool_name) {
            if let Some(b) = pool.backends.iter().find(|b| b.config.id == backend_id) {
                b.on_success();
            }
        }
    }

    fn record_failure(&self, pool_name: &str, backend_id: &str) {
        if let Some(pool) = self.pools.get(pool_name) {
            if let Some(b) = pool.backends.iter().find(|b| b.config.id == backend_id) {
                b.on_failure(
                    pool.passive_failure_threshold,
                    pool.passive_cooldown,
                    Instant::now(),
                );
            }
        }
    }

    fn set_active_health(&self, pool_name: &str, backend_id: &str, healthy: bool) {
        if let Some(pool) = self.pools.get(pool_name) {
            if let Some(b) = pool.backends.iter().find(|b| b.config.id == backend_id) {
                b.active_healthy.store(healthy, Ordering::Release);
                if healthy {
                    b.on_success();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool(strategy: LbStrategyConfig, threshold: u32, cooldown_ms: u64) -> PoolLoadBalancer {
        let mut pools = HashMap::new();
        pools.insert(
            "api".to_string(),
            CompiledPool {
                name: "api".to_string(),
                strategy,
                backends: vec![
                    CompiledBackend {
                        id: "a".to_string(),
                        host: "127.0.0.1".to_string(),
                        port: 9001,
                        authority: "127.0.0.1:9001".to_string(),
                        tls: false,
                        tls_sni: "127.0.0.1".to_string(),
                    },
                    CompiledBackend {
                        id: "b".to_string(),
                        host: "127.0.0.1".to_string(),
                        port: 9002,
                        authority: "127.0.0.1:9002".to_string(),
                        tls: false,
                        tls_sni: "127.0.0.1".to_string(),
                    },
                ],
                max_connections_per_upstream: 8,
                idle_ttl: Duration::from_secs(30),
                passive_failure_threshold: threshold,
                passive_cooldown: Duration::from_millis(cooldown_ms),
                allow_private_ip: true,
                custom_ca_certs: Vec::new(),
                health_check_path: None,
                health_check_interval: Duration::from_secs(5),
            },
        );
        PoolLoadBalancer::from_pools(&pools)
    }

    #[test]
    fn round_robin_alternates_across_backends() {
        let lb = make_pool(LbStrategyConfig::RoundRobin, 3, 5_000);
        let l1 = lb.select("api").unwrap_or_else(|e| panic!("err: {e}"));
        let l2 = lb.select("api").unwrap_or_else(|e| panic!("err: {e}"));
        let l3 = lb.select("api").unwrap_or_else(|e| panic!("err: {e}"));
        assert_eq!(l1.backend.id, "a");
        assert_eq!(l2.backend.id, "b");
        assert_eq!(l3.backend.id, "a");
    }

    #[test]
    fn least_connections_routes_to_idle_backend_and_releases_on_drop() {
        let lb = make_pool(LbStrategyConfig::LeastConnections, 3, 5_000);
        let held = lb.select("api").unwrap_or_else(|e| panic!("err: {e}"));
        assert_eq!(held.backend.id, "a");

        let second = lb.select("api").unwrap_or_else(|e| panic!("err: {e}"));
        assert_eq!(second.backend.id, "b");
        drop(second);

        let third = lb.select("api").unwrap_or_else(|e| panic!("err: {e}"));
        assert_eq!(third.backend.id, "b");
        drop(held);
        drop(third);
    }

    #[test]
    fn passive_and_active_health_skip_unhealthy_backends() {
        let lb = make_pool(LbStrategyConfig::RoundRobin, 2, 5_000);
        lb.set_active_health("api", "a", false);
        let lease = lb.select("api").unwrap_or_else(|e| panic!("err: {e}"));
        assert_eq!(lease.backend.id, "b");

        lb.set_active_health("api", "a", true);
        lb.record_failure("api", "a");
        lb.record_failure("api", "a");

        for _ in 0..4 {
            let lease = lb.select("api").unwrap_or_else(|e| panic!("err: {e}"));
            assert_eq!(lease.backend.id, "b");
        }

        lb.record_failure("api", "b");
        lb.record_failure("api", "b");
        assert!(matches!(
            lb.select("api"),
            Err(EdgeGateError::ServiceUnavailable(_))
        ));
    }
}
