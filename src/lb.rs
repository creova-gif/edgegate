use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{CompiledBackend, CompiledPool, LbStrategyConfig};
use crate::EdgeGateError;

/// Three-state circuit breaker status (`Milestone 3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal traffic admitted; trips to `Open` after `passive_failure_threshold` consecutive failures.
    Closed { consecutive_failures: u32 },
    /// Traffic rejected until `until`; transitions to `HalfOpen` once `now >= until`.
    Open { until: Instant },
    /// Admits at most ONE trial probe request (`probe_in_flight`).
    /// Success transitions to `Closed`; failure immediately re-trips to `Open`.
    HalfOpen { probe_in_flight: bool },
}

/// RAII lease returned by `LoadBalancer::select`.
/// Decrements the backend's in-flight counter automatically on `Drop` and releases
/// any unsettled `HalfOpen` probe flag if the request was aborted before recording a result.
#[derive(Debug)]
pub struct BackendLease {
    pub pool_name: String,
    pub backend: CompiledBackend,
    pub allow_private_ip: bool,
    in_flight: Arc<AtomicUsize>,
    half_open_probe: Option<Arc<Mutex<CircuitState>>>,
}

impl BackendLease {
    fn clear_probe_guard(&mut self) {
        self.half_open_probe = None;
    }
}

impl Drop for BackendLease {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        if let Some(ref circuit) = self.half_open_probe {
            let mut guard = match circuit.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if matches!(
                *guard,
                CircuitState::HalfOpen {
                    probe_in_flight: true
                }
            ) {
                *guard = CircuitState::HalfOpen {
                    probe_in_flight: false,
                };
            }
        }
    }
}

/// Trait seam for load balancing (`RoundRobin`, `LeastConnections`, `ConsistentHash`, `LatencyAware`)
/// + three-state circuit breaker (`Closed`/`Open`/`HalfOpen`) + active health tracking.
pub trait LoadBalancer: Send + Sync {
    fn select(&self, pool_name: &str) -> Result<BackendLease, EdgeGateError> {
        self.select_with_key(pool_name, None)
    }
    fn select_with_key(
        &self,
        pool_name: &str,
        routing_key: Option<&str>,
    ) -> Result<BackendLease, EdgeGateError>;
    fn record_success(&self, pool_name: &str, backend_id: &str, latency_us: u64);
    /// Record a backend failure (`502` connect/transport, `504` timeout, or upstream `5xx`).
    /// NEVER call this on local `503` pool exhaustion.
    fn record_failure(&self, pool_name: &str, backend_id: &str);
    /// Updates active health status from background HTTP health probes.
    fn set_active_health(&self, pool_name: &str, backend_id: &str, healthy: bool);
    /// Serializes live per-pool strategy, backend health, weights, EWMA latency, and circuit-breaker state (`Milestone 8`).
    fn pools_status_json(&self) -> String {
        "{\"pools\":[]}".to_string()
    }
}

#[derive(Debug)]
struct BackendState {
    config: CompiledBackend,
    in_flight: Arc<AtomicUsize>,
    active_healthy: AtomicBool,
    ewma_latency_us: AtomicU64,
    circuit: Arc<Mutex<CircuitState>>,
}

impl BackendState {
    /// Checks if the backend can accept a request now.
    /// If transitioning into `HalfOpen` (or already `HalfOpen` with no probe in flight),
    /// claims the single-flight trial probe slot and returns `Some(true)` (`is_half_open_probe = true`).
    fn try_admit(&self, now: Instant) -> Option<bool> {
        if !self.active_healthy.load(Ordering::Acquire) {
            return None;
        }
        let mut guard = match self.circuit.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match *guard {
            CircuitState::Closed { .. } => Some(false),
            CircuitState::Open { until } => {
                if now >= until {
                    *guard = CircuitState::HalfOpen {
                        probe_in_flight: true,
                    };
                    Some(true)
                } else {
                    None
                }
            }
            CircuitState::HalfOpen { probe_in_flight } => {
                if probe_in_flight {
                    None
                } else {
                    *guard = CircuitState::HalfOpen {
                        probe_in_flight: true,
                    };
                    Some(true)
                }
            }
        }
    }

    fn on_success(&self, latency_us: u64) {
        let mut guard = match self.circuit.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = CircuitState::Closed {
            consecutive_failures: 0,
        };
        drop(guard);

        // Update EWMA latency (alpha = 0.25 -> 3/4 old + 1/4 new).
        let prev = self.ewma_latency_us.load(Ordering::Relaxed);
        let next = if prev == 0 {
            latency_us.max(1)
        } else {
            ((prev * 3) + latency_us.max(1)) / 4
        };
        self.ewma_latency_us.store(next, Ordering::Relaxed);
    }

    fn on_failure(&self, threshold: u32, cooldown: Duration, now: Instant) {
        let mut guard = match self.circuit.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match *guard {
            CircuitState::Closed {
                consecutive_failures,
            } => {
                let next = consecutive_failures.saturating_add(1);
                if next >= threshold {
                    *guard = CircuitState::Open {
                        until: now + cooldown,
                    };
                } else {
                    *guard = CircuitState::Closed {
                        consecutive_failures: next,
                    };
                }
            }
            CircuitState::HalfOpen { .. } | CircuitState::Open { .. } => {
                // Failed HalfOpen trial probe immediately re-opens circuit for full cooldown.
                *guard = CircuitState::Open {
                    until: now + cooldown,
                };
            }
        }
    }
}

#[derive(Debug)]
struct PoolState {
    name: String,
    strategy: LbStrategyConfig,
    mtls_enabled: bool,
    allow_private_ip: bool,
    passive_failure_threshold: u32,
    passive_cooldown: Duration,
    rr_cursor: AtomicUsize,
    weighted_schedule: Vec<usize>,
    backends: Vec<BackendState>,
}

/// Pool-aware load balancer supporting `RoundRobin`, `LeastConnections`, `ConsistentHash`,
/// and `LatencyAware` (EWMA), backed by a three-state `Closed`/`Open`/`HalfOpen` circuit breaker.
#[derive(Debug)]
pub struct PoolLoadBalancer {
    pools: HashMap<String, PoolState>,
}

impl PoolLoadBalancer {
    pub fn from_pools(compiled: &HashMap<String, CompiledPool>) -> Self {
        let mut pools = HashMap::with_capacity(compiled.len());
        for (name, pool) in compiled {
            let mut weighted_schedule = Vec::new();
            for (idx, b) in pool.backends.iter().enumerate() {
                let reps = b.weight.clamp(1, 100) as usize;
                for _ in 0..reps {
                    weighted_schedule.push(idx);
                }
            }
            let backends = pool
                .backends
                .iter()
                .map(|b| BackendState {
                    config: b.clone(),
                    in_flight: Arc::new(AtomicUsize::new(0)),
                    active_healthy: AtomicBool::new(true),
                    ewma_latency_us: AtomicU64::new(0),
                    circuit: Arc::new(Mutex::new(CircuitState::Closed {
                        consecutive_failures: 0,
                    })),
                })
                .collect();
            pools.insert(
                name.clone(),
                PoolState {
                    name: pool.name.clone(),
                    strategy: pool.strategy,
                    mtls_enabled: !pool.client_cert_chain.is_empty()
                        && pool.client_key_pem.is_some(),
                    allow_private_ip: pool.allow_private_ip,
                    passive_failure_threshold: pool.passive_failure_threshold,
                    passive_cooldown: pool.passive_cooldown,
                    rr_cursor: AtomicUsize::new(0),
                    weighted_schedule,
                    backends,
                },
            );
        }
        Self { pools }
    }
}

impl LoadBalancer for PoolLoadBalancer {
    fn select_with_key(
        &self,
        pool_name: &str,
        routing_key: Option<&str>,
    ) -> Result<BackendLease, EdgeGateError> {
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

        let selected: Option<(&BackendState, bool)> = match pool.strategy {
            LbStrategyConfig::RoundRobin => {
                let sched_len = pool.weighted_schedule.len().max(1);
                let start = pool.rr_cursor.fetch_add(1, Ordering::Relaxed);
                (0..sched_len).find_map(|offset| {
                    let idx = pool.weighted_schedule[(start + offset) % sched_len];
                    let b = &pool.backends[idx];
                    b.try_admit(now).map(|is_probe| (b, is_probe))
                })
            }
            LbStrategyConfig::ConsistentHash => {
                let start = match routing_key {
                    Some(key) if !key.is_empty() => (fnv1a_64(key.as_bytes()) as usize) % len,
                    _ => pool.rr_cursor.fetch_add(1, Ordering::Relaxed) % len,
                };
                (0..len).find_map(|offset| {
                    let b = &pool.backends[(start + offset) % len];
                    b.try_admit(now).map(|is_probe| (b, is_probe))
                })
            }
            LbStrategyConfig::LeastConnections => {
                let start = pool.rr_cursor.fetch_add(1, Ordering::Relaxed);
                let mut best: Option<(&BackendState, bool, usize)> = None;
                for offset in 0..len {
                    let candidate = &pool.backends[(start + offset) % len];
                    let active = candidate.in_flight.load(Ordering::Acquire);
                    if best.is_some_and(|(_, _, best_active)| active >= best_active) {
                        continue;
                    }
                    if let Some(is_probe) = candidate.try_admit(now) {
                        // Release any previously claimed half-open probe if we found a better candidate.
                        if let Some((prev, true, _)) = best {
                            release_half_open_probe(&prev.circuit);
                        }
                        best = Some((candidate, is_probe, active));
                    }
                }
                best.map(|(b, is_probe, _)| (b, is_probe))
            }
            LbStrategyConfig::LatencyAware => {
                let start = pool.rr_cursor.fetch_add(1, Ordering::Relaxed);
                let mut best: Option<(&BackendState, bool, u64)> = None;
                for offset in 0..len {
                    let candidate = &pool.backends[(start + offset) % len];
                    let ewma = candidate.ewma_latency_us.load(Ordering::Relaxed);
                    if best.is_some_and(|(_, _, best_ewma)| ewma >= best_ewma) {
                        continue;
                    }
                    if let Some(is_probe) = candidate.try_admit(now) {
                        if let Some((prev, true, _)) = best {
                            release_half_open_probe(&prev.circuit);
                        }
                        best = Some((candidate, is_probe, ewma));
                    }
                }
                best.map(|(b, is_probe, _)| (b, is_probe))
            }
        };

        let (backend, is_probe) = selected.ok_or_else(|| {
            EdgeGateError::ServiceUnavailable(format!(
                "all backends in pool '{pool_name}' have open circuit breakers or are unhealthy"
            ))
        })?;

        backend.in_flight.fetch_add(1, Ordering::AcqRel);
        Ok(BackendLease {
            pool_name: pool.name.clone(),
            backend: backend.config.clone(),
            allow_private_ip: pool.allow_private_ip,
            in_flight: Arc::clone(&backend.in_flight),
            half_open_probe: if is_probe {
                Some(Arc::clone(&backend.circuit))
            } else {
                None
            },
        })
    }

    fn record_success(&self, pool_name: &str, backend_id: &str, latency_us: u64) {
        if let Some(pool) = self.pools.get(pool_name) {
            if let Some(b) = pool.backends.iter().find(|b| b.config.id == backend_id) {
                b.on_success(latency_us);
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
                    b.on_success(100);
                }
            }
        }
    }

    fn pools_status_json(&self) -> String {
        let now = Instant::now();
        let mut names: Vec<&String> = self.pools.keys().collect();
        names.sort();
        let mut pool_items = Vec::with_capacity(names.len());
        for name in names {
            let Some(pool) = self.pools.get(name) else {
                continue;
            };
            let strategy_str = match pool.strategy {
                LbStrategyConfig::RoundRobin => "round_robin",
                LbStrategyConfig::LeastConnections => "least_connections",
                LbStrategyConfig::ConsistentHash => "consistent_hash",
                LbStrategyConfig::LatencyAware => "latency_aware",
            };
            let mut backend_items = Vec::with_capacity(pool.backends.len());
            for b in &pool.backends {
                let circuit_state = {
                    let guard = match b.circuit.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    match *guard {
                        CircuitState::Closed { .. } => "closed",
                        CircuitState::Open { until } => {
                            if now >= until {
                                "half_open"
                            } else {
                                "open"
                            }
                        }
                        CircuitState::HalfOpen { .. } => "half_open",
                    }
                };
                backend_items.push(format!(
                    "{{\"id\":\"{}\",\"authority\":\"{}\",\"weight\":{},\"active_healthy\":{},\"in_flight\":{},\"ewma_latency_us\":{},\"circuit_state\":\"{}\"}}",
                    escape_lb_json(&b.config.id),
                    escape_lb_json(&b.config.authority),
                    b.config.weight,
                    b.active_healthy.load(Ordering::Acquire),
                    b.in_flight.load(Ordering::Acquire),
                    b.ewma_latency_us.load(Ordering::Relaxed),
                    circuit_state
                ));
            }
            pool_items.push(format!(
                "{{\"name\":\"{}\",\"strategy\":\"{}\",\"mtls_enabled\":{},\"backends\":[{}]}}",
                escape_lb_json(&pool.name),
                strategy_str,
                pool.mtls_enabled,
                backend_items.join(",")
            ));
        }
        format!("{{\"pools\":[{}]}}", pool_items.join(","))
    }
}

fn escape_lb_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c < '\x20' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn release_half_open_probe(circuit: &Mutex<CircuitState>) {
    let mut guard = match circuit.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if matches!(
        *guard,
        CircuitState::HalfOpen {
            probe_in_flight: true
        }
    ) {
        *guard = CircuitState::HalfOpen {
            probe_in_flight: false,
        };
    }
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

impl BackendLease {
    /// Marks the lease's circuit probe settled so `Drop` does not reset a completed transition.
    pub fn settle_probe(&mut self) {
        self.clear_probe_guard();
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
                        weight: 1,
                        tls: false,
                        tls_sni: "127.0.0.1".to_string(),
                        http2: false,
                    },
                    CompiledBackend {
                        id: "b".to_string(),
                        host: "127.0.0.1".to_string(),
                        port: 9002,
                        authority: "127.0.0.1:9002".to_string(),
                        weight: 1,
                        tls: false,
                        tls_sni: "127.0.0.1".to_string(),
                        http2: false,
                    },
                ],
                max_connections_per_upstream: 8,
                idle_ttl: Duration::from_secs(30),
                passive_failure_threshold: threshold,
                passive_cooldown: Duration::from_millis(cooldown_ms),
                allow_private_ip: true,
                custom_ca_certs: Vec::new(),
                client_cert_chain: Vec::new(),
                client_key_pem: None,
                health_check_path: None,
                health_check_interval: Duration::from_secs(5),
                max_idempotent_retries: 0,
                dns_cache_ttl: Duration::from_secs(10),
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
    fn consistent_hash_pins_same_key_and_latency_aware_prefers_faster_backend() {
        let ch = make_pool(LbStrategyConfig::ConsistentHash, 3, 5_000);
        let first = ch
            .select_with_key("api", Some("tenant-42"))
            .unwrap_or_else(|e| panic!("err: {e}"))
            .backend
            .id
            .clone();
        for _ in 0..5 {
            let next = ch
                .select_with_key("api", Some("tenant-42"))
                .unwrap_or_else(|e| panic!("err: {e}"))
                .backend
                .id
                .clone();
            assert_eq!(first, next);
        }

        let lat = make_pool(LbStrategyConfig::LatencyAware, 3, 5_000);
        lat.record_success("api", "a", 5_000); // 5ms
        lat.record_success("api", "b", 200); // 0.2ms
        let picked = lat.select("api").unwrap_or_else(|e| panic!("err: {e}"));
        assert_eq!(picked.backend.id, "b");
    }

    #[test]
    fn three_state_circuit_breaker_admits_single_half_open_probe_before_closing() {
        let lb = make_pool(LbStrategyConfig::RoundRobin, 1, 20);
        // Trip `a` and `b` into Open state (20ms cooldown).
        lb.record_failure("api", "a");
        lb.record_failure("api", "b");
        assert!(lb.select("api").is_err());

        std::thread::sleep(Duration::from_millis(30));

        // Now `a` and `b` are eligible for HalfOpen, but each admits at most 1 trial probe!
        let mut probe_a = lb.select("api").unwrap_or_else(|e| panic!("probe a: {e}"));
        let _probe_b = lb.select("api").unwrap_or_else(|e| panic!("probe b: {e}"));
        // Third concurrent request while both HalfOpen probes are in-flight must be rejected!
        assert!(lb.select("api").is_err());

        // Settle `probe_a` as succeeded -> its backend transitions back to Closed!
        let settled_id = probe_a.backend.id.clone();
        probe_a.settle_probe();
        lb.record_success("api", &settled_id, 100);
        drop(probe_a);

        let after = lb.select("api").unwrap_or_else(|e| panic!("after: {e}"));
        assert_eq!(after.backend.id, settled_id);
    }
}
