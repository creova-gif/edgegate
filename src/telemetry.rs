use std::sync::atomic::{AtomicU64, Ordering};

use tracing::info;

/// Atomic request, decision, and config-reload counters for EdgeGate observability.
#[derive(Debug)]
pub struct Telemetry {
    request_seq: AtomicU64,
    allowed_total: AtomicU64,
    blocked_total: AtomicU64,
    upstream_errors_total: AtomicU64,
    reloads_total: AtomicU64,
    reload_failures_total: AtomicU64,
    config_generation: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetrySnapshot {
    pub allowed_total: u64,
    pub blocked_total: u64,
    pub upstream_errors_total: u64,
    pub reloads_total: u64,
    pub reload_failures_total: u64,
    pub config_generation: u64,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl Telemetry {
    pub fn new() -> Self {
        Self {
            request_seq: AtomicU64::new(0),
            allowed_total: AtomicU64::new(0),
            blocked_total: AtomicU64::new(0),
            upstream_errors_total: AtomicU64::new(0),
            reloads_total: AtomicU64::new(0),
            reload_failures_total: AtomicU64::new(0),
            config_generation: AtomicU64::new(1),
        }
    }

    pub fn next_request_id(&self) -> u64 {
        self.request_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_reload_success(&self) -> u64 {
        self.reloads_total.fetch_add(1, Ordering::Relaxed);
        self.config_generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn record_reload_failure(&self) {
        self.reload_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            allowed_total: self.allowed_total.load(Ordering::Relaxed),
            blocked_total: self.blocked_total.load(Ordering::Relaxed),
            upstream_errors_total: self.upstream_errors_total.load(Ordering::Relaxed),
            reloads_total: self.reloads_total.load(Ordering::Relaxed),
            reload_failures_total: self.reload_failures_total.load(Ordering::Relaxed),
            config_generation: self.config_generation.load(Ordering::Acquire),
        }
    }

    pub fn to_json(&self) -> String {
        let s = self.snapshot();
        format!(
            "{{\"allowed_total\":{},\"blocked_total\":{},\"upstream_errors_total\":{},\"reloads_total\":{},\"reload_failures_total\":{},\"config_generation\":{}}}",
            s.allowed_total,
            s.blocked_total,
            s.upstream_errors_total,
            s.reloads_total,
            s.reload_failures_total,
            s.config_generation
        )
    }

    /// Emits one structured JSON audit/request log line.
    /// Strictly excludes request/response headers, bodies, and secret material.
    #[allow(clippy::too_many_arguments)]
    pub fn record_request(
        &self,
        request_id: u64,
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
            _ => {
                self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
            }
        }

        info!(
            target: "edgegate::audit",
            request_id = request_id,
            org_id = org_id,
            workload_id = org_id_or_workload(workload_id),
            route = route,
            upstream = upstream,
            decision = decision,
            status = status,
            latency_us = latency_us,
            "edgegate_request"
        );
    }
}

fn org_id_or_workload(val: &str) -> &str {
    val
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
