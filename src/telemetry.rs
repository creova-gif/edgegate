use std::sync::atomic::{AtomicU64, Ordering};

use tracing::info;

/// Atomic request & decision counters for Milestone 1 observability.
#[derive(Debug, Default)]
pub struct Telemetry {
    request_seq: AtomicU64,
    allowed_total: AtomicU64,
    blocked_total: AtomicU64,
    upstream_errors_total: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub struct TelemetrySnapshot {
    pub allowed_total: u64,
    pub blocked_total: u64,
    pub upstream_errors_total: u64,
}

impl Telemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_request_id(&self) -> u64 {
        self.request_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            allowed_total: self.allowed_total.load(Ordering::Relaxed),
            blocked_total: self.blocked_total.load(Ordering::Relaxed),
            upstream_errors_total: self.upstream_errors_total.load(Ordering::Relaxed),
        }
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

/// Initializes structured JSON tracing subscriber (best-effort if already initialized in tests).
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
