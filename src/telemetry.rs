use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tracing::info;

/// Sanitized flight-recorder entry for failed (`5xx`/`502`/`503`/`504`), rate-limited (`429`), or shadow-mismatched requests.
/// Strictly excludes request/response headers, bodies, and secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRecord {
    pub request_id: u64,
    pub trace_id: String,
    pub org_id: String,
    pub workload_id: String,
    pub method: String,
    pub path: String,
    pub route: String,
    pub upstream: String,
    pub status: u16,
    pub shadow_status: Option<u16>,
    pub reason: String,
    pub latency_us: u64,
}

/// Atomic request, decision, rate-limit, shadow, reload, retry, reflection-guard, and flight-recorder telemetry (`Milestone 5`).
#[derive(Debug)]
pub struct Telemetry {
    request_seq: AtomicU64,
    allowed_total: AtomicU64,
    blocked_total: AtomicU64,
    rate_limited_total: AtomicU64,
    upstream_errors_total: AtomicU64,
    reloads_total: AtomicU64,
    reload_failures_total: AtomicU64,
    config_generation: AtomicU64,
    shadow_requests_total: AtomicU64,
    shadow_mismatches_total: AtomicU64,
    secret_reflections_blocked_total: AtomicU64,
    retries_total: AtomicU64,
    in_flight_requests: AtomicU64,
    replay_capacity: usize,
    replay_ring: Mutex<VecDeque<ReplayRecord>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetrySnapshot {
    pub allowed_total: u64,
    pub blocked_total: u64,
    pub rate_limited_total: u64,
    pub upstream_errors_total: u64,
    pub reloads_total: u64,
    pub reload_failures_total: u64,
    pub config_generation: u64,
    pub shadow_requests_total: u64,
    pub shadow_mismatches_total: u64,
    pub secret_reflections_blocked_total: u64,
    pub retries_total: u64,
    pub in_flight_requests: u64,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::with_replay_capacity(64)
    }
}

impl Telemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_replay_capacity(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            request_seq: AtomicU64::new(0),
            allowed_total: AtomicU64::new(0),
            blocked_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            upstream_errors_total: AtomicU64::new(0),
            reloads_total: AtomicU64::new(0),
            reload_failures_total: AtomicU64::new(0),
            config_generation: AtomicU64::new(1),
            shadow_requests_total: AtomicU64::new(0),
            shadow_mismatches_total: AtomicU64::new(0),
            secret_reflections_blocked_total: AtomicU64::new(0),
            retries_total: AtomicU64::new(0),
            in_flight_requests: AtomicU64::new(0),
            replay_capacity: cap,
            replay_ring: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    pub fn next_request_id(&self) -> u64 {
        self.request_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn inc_in_flight(&self) {
        self.in_flight_requests.fetch_add(1, Ordering::AcqRel);
    }

    pub fn dec_in_flight(&self) {
        self.in_flight_requests.fetch_sub(1, Ordering::AcqRel);
    }

    pub fn in_flight_count(&self) -> u64 {
        self.in_flight_requests.load(Ordering::Acquire)
    }

    pub fn record_retry(&self) {
        self.retries_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_secret_reflection_blocked(&self) {
        self.secret_reflections_blocked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reload_success(&self) -> u64 {
        self.reloads_total.fetch_add(1, Ordering::Relaxed);
        self.config_generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn record_reload_failure(&self) {
        self.reload_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_shadow_outcome(&self, matched: bool) {
        self.shadow_requests_total.fetch_add(1, Ordering::Relaxed);
        if !matched {
            self.shadow_mismatches_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_replay(&self, entry: ReplayRecord) {
        let mut guard = match self.replay_ring.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.len() >= self.replay_capacity {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    pub fn replay_records(&self) -> Vec<ReplayRecord> {
        let guard = match self.replay_ring.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.iter().cloned().collect()
    }

    pub fn replay_to_json(&self) -> String {
        let records = self.replay_records();
        let mut items = Vec::with_capacity(records.len());
        for r in records {
            let shadow = match r.shadow_status {
                Some(code) => code.to_string(),
                None => "null".to_string(),
            };
            items.push(format!(
                "{{\"request_id\":{},\"trace_id\":\"{}\",\"org_id\":\"{}\",\"workload_id\":\"{}\",\"method\":\"{}\",\"path\":\"{}\",\"route\":\"{}\",\"upstream\":\"{}\",\"status\":{},\"shadow_status\":{},\"reason\":\"{}\",\"latency_us\":{}}}",
                r.request_id,
                escape_json(&r.trace_id),
                escape_json(&r.org_id),
                escape_json(&r.workload_id),
                escape_json(&r.method),
                escape_json(&r.path),
                escape_json(&r.route),
                escape_json(&r.upstream),
                r.status,
                shadow,
                escape_json(&r.reason),
                r.latency_us
            ));
        }
        format!("{{\"records\":[{}]}}", items.join(","))
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            allowed_total: self.allowed_total.load(Ordering::Relaxed),
            blocked_total: self.blocked_total.load(Ordering::Relaxed),
            rate_limited_total: self.rate_limited_total.load(Ordering::Relaxed),
            upstream_errors_total: self.upstream_errors_total.load(Ordering::Relaxed),
            reloads_total: self.reloads_total.load(Ordering::Relaxed),
            reload_failures_total: self.reload_failures_total.load(Ordering::Relaxed),
            config_generation: self.config_generation.load(Ordering::Acquire),
            shadow_requests_total: self.shadow_requests_total.load(Ordering::Relaxed),
            shadow_mismatches_total: self.shadow_mismatches_total.load(Ordering::Relaxed),
            secret_reflections_blocked_total: self
                .secret_reflections_blocked_total
                .load(Ordering::Relaxed),
            retries_total: self.retries_total.load(Ordering::Relaxed),
            in_flight_requests: self.in_flight_requests.load(Ordering::Acquire),
        }
    }

    pub fn to_json(&self) -> String {
        let s = self.snapshot();
        format!(
            "{{\"allowed_total\":{},\"blocked_total\":{},\"rate_limited_total\":{},\"upstream_errors_total\":{},\"reloads_total\":{},\"reload_failures_total\":{},\"config_generation\":{},\"shadow_requests_total\":{},\"shadow_mismatches_total\":{},\"secret_reflections_blocked_total\":{},\"retries_total\":{},\"in_flight_requests\":{}}}",
            s.allowed_total,
            s.blocked_total,
            s.rate_limited_total,
            s.upstream_errors_total,
            s.reloads_total,
            s.reload_failures_total,
            s.config_generation,
            s.shadow_requests_total,
            s.shadow_mismatches_total,
            s.secret_reflections_blocked_total,
            s.retries_total,
            s.in_flight_requests
        )
    }

    /// Renders standard Prometheus text format (`# HELP` / `# TYPE`) for all counters and gauges (`Milestone 5`).
    pub fn to_prometheus(&self) -> String {
        let s = self.snapshot();
        format!(
            "# HELP edgegate_requests_allowed_total Total requests allowed by EdgeGate policy.\n\
             # TYPE edgegate_requests_allowed_total counter\n\
             edgegate_requests_allowed_total {}\n\
             # HELP edgegate_requests_blocked_total Total requests blocked by EdgeGate authentication or policy.\n\
             # TYPE edgegate_requests_blocked_total counter\n\
             edgegate_requests_blocked_total {}\n\
             # HELP edgegate_requests_rate_limited_total Total requests rejected by EdgeGate token-bucket rate limiter.\n\
             # TYPE edgegate_requests_rate_limited_total counter\n\
             edgegate_requests_rate_limited_total {}\n\
             # HELP edgegate_upstream_errors_total Total upstream 5xx or transport errors.\n\
             # TYPE edgegate_upstream_errors_total counter\n\
             edgegate_upstream_errors_total {}\n\
             # HELP edgegate_reloads_total Total successful atomic configuration reloads.\n\
             # TYPE edgegate_reloads_total counter\n\
             edgegate_reloads_total {}\n\
             # HELP edgegate_reload_failures_total Total rejected configuration reload attempts.\n\
             # TYPE edgegate_reload_failures_total counter\n\
             edgegate_reload_failures_total {}\n\
             # HELP edgegate_config_generation Active atomic configuration generation number.\n\
             # TYPE edgegate_config_generation gauge\n\
             edgegate_config_generation {}\n\
             # HELP edgegate_shadow_requests_total Total asynchronous shadow requests dispatched.\n\
             # TYPE edgegate_shadow_requests_total counter\n\
             edgegate_shadow_requests_total {}\n\
             # HELP edgegate_shadow_mismatches_total Total shadow responses whose status differed from primary.\n\
             # TYPE edgegate_shadow_mismatches_total counter\n\
             edgegate_shadow_mismatches_total {}\n\
             # HELP edgegate_secret_reflections_blocked_total Total upstream responses blocked due to reflected injected secret.\n\
             # TYPE edgegate_secret_reflections_blocked_total counter\n\
             edgegate_secret_reflections_blocked_total {}\n\
             # HELP edgegate_retries_total Total controlled idempotent upstream failover retries.\n\
             # TYPE edgegate_retries_total counter\n\
             edgegate_retries_total {}\n\
             # HELP edgegate_in_flight_requests Current number of in-flight requests being processed.\n\
             # TYPE edgegate_in_flight_requests gauge\n\
             edgegate_in_flight_requests {}\n",
            s.allowed_total,
            s.blocked_total,
            s.rate_limited_total,
            s.upstream_errors_total,
            s.reloads_total,
            s.reload_failures_total,
            s.config_generation,
            s.shadow_requests_total,
            s.shadow_mismatches_total,
            s.secret_reflections_blocked_total,
            s.retries_total,
            s.in_flight_requests
        )
    }

    /// Emits one structured JSON audit/request log line.
    /// Strictly excludes request/response headers, bodies, and secret material.
    #[allow(clippy::too_many_arguments)]
    pub fn record_request(
        &self,
        request_id: u64,
        trace_id: &str,
        org_id: &str,
        workload_id: &str,
        route: &str,
        upstream: &str,
        decision: &str,
        status: u16,
        latency_us: u64,
    ) {
        match decision {
            "ALLOWED" => {
                self.allowed_total.fetch_add(1, Ordering::Relaxed);
                if status >= 500 {
                    self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
                }
            }
            "BLOCKED" => {
                self.blocked_total.fetch_add(1, Ordering::Relaxed);
            }
            "RATE_LIMITED" => {
                self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
            }
        }

        info!(
            target: "edgegate::audit",
            request_id = request_id,
            trace_id = trace_id,
            org_id = org_id,
            workload_id = workload_id,
            route = route,
            upstream = upstream,
            decision = decision,
            status = status,
            latency_us = latency_us,
            "edgegate_request"
        );
    }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn init_json_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .with_span_list(false)
        .try_init();
}
