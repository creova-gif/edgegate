use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use tracing::info;

const GENESIS_AUDIT_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Cryptographic SHA-256 hash-chained audit ledger entry (`Milestone 7`).
/// Strictly excludes request/response headers, bodies, and secret material.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditChainEntry {
    pub seq: u64,
    pub request_id: u64,
    pub trace_id: String,
    pub org_id: String,
    pub workload_id: String,
    pub route: String,
    pub decision: String,
    pub status: u16,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug)]
struct AuditLedgerState {
    seq: u64,
    last_audit_hash: String,
    entries: VecDeque<AuditChainEntry>,
}

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

/// Atomic request, decision, rate-limit, shadow, reload, retry, reflection-guard, secret-rotation,
/// latency histogram, flight-recorder, and SHA-256 hash-chained audit ledger telemetry (`Milestone 7`).
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
    secret_rotations_total: AtomicU64,
    dlp_blocked_total: AtomicU64,
    bulkhead_rejected_total: AtomicU64,
    jsonrpc_blocked_total: AtomicU64,
    retries_total: AtomicU64,
    in_flight_requests: AtomicU64,
    signed_requests_total: AtomicU64,
    latency_le_100us: AtomicU64,
    latency_le_500us: AtomicU64,
    latency_le_1000us: AtomicU64,
    latency_le_5000us: AtomicU64,
    latency_le_10000us: AtomicU64,
    latency_le_50000us: AtomicU64,
    latency_sum_us: AtomicU64,
    latency_count: AtomicU64,
    replay_capacity: usize,
    replay_ring: Mutex<VecDeque<ReplayRecord>>,
    audit_ledger: Mutex<AuditLedgerState>,
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
    pub secret_rotations_total: u64,
    pub dlp_blocked_total: u64,
    pub bulkhead_rejected_total: u64,
    pub jsonrpc_blocked_total: u64,
    pub retries_total: u64,
    pub in_flight_requests: u64,
    pub signed_requests_total: u64,
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
            secret_rotations_total: AtomicU64::new(0),
            dlp_blocked_total: AtomicU64::new(0),
            bulkhead_rejected_total: AtomicU64::new(0),
            jsonrpc_blocked_total: AtomicU64::new(0),
            retries_total: AtomicU64::new(0),
            in_flight_requests: AtomicU64::new(0),
            signed_requests_total: AtomicU64::new(0),
            latency_le_100us: AtomicU64::new(0),
            latency_le_500us: AtomicU64::new(0),
            latency_le_1000us: AtomicU64::new(0),
            latency_le_5000us: AtomicU64::new(0),
            latency_le_10000us: AtomicU64::new(0),
            latency_le_50000us: AtomicU64::new(0),
            latency_sum_us: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            replay_capacity: cap,
            replay_ring: Mutex::new(VecDeque::with_capacity(cap)),
            audit_ledger: Mutex::new(AuditLedgerState {
                seq: 0,
                last_audit_hash: GENESIS_AUDIT_HASH.to_string(),
                entries: VecDeque::with_capacity(cap),
            }),
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

    pub fn record_signed_request(&self) {
        self.signed_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_secret_reflection_blocked(&self) {
        self.secret_reflections_blocked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_secret_rotation(&self) {
        self.secret_rotations_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dlp_blocked(&self) {
        self.dlp_blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bulkhead_rejected(&self) {
        self.bulkhead_rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_jsonrpc_blocked(&self) {
        self.jsonrpc_blocked_total.fetch_add(1, Ordering::Relaxed);
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
            secret_rotations_total: self.secret_rotations_total.load(Ordering::Relaxed),
            dlp_blocked_total: self.dlp_blocked_total.load(Ordering::Relaxed),
            bulkhead_rejected_total: self.bulkhead_rejected_total.load(Ordering::Relaxed),
            jsonrpc_blocked_total: self.jsonrpc_blocked_total.load(Ordering::Relaxed),
            retries_total: self.retries_total.load(Ordering::Relaxed),
            in_flight_requests: self.in_flight_requests.load(Ordering::Acquire),
            signed_requests_total: self.signed_requests_total.load(Ordering::Relaxed),
        }
    }

    pub fn to_json(&self) -> String {
        let s = self.snapshot();
        let audit_valid = self.verify_audit_chain();
        format!(
            "{{\"allowed_total\":{},\"blocked_total\":{},\"rate_limited_total\":{},\"upstream_errors_total\":{},\"reloads_total\":{},\"reload_failures_total\":{},\"config_generation\":{},\"shadow_requests_total\":{},\"shadow_mismatches_total\":{},\"secret_reflections_blocked_total\":{},\"secret_rotations_total\":{},\"dlp_blocked_total\":{},\"bulkhead_rejected_total\":{},\"jsonrpc_blocked_total\":{},\"retries_total\":{},\"in_flight_requests\":{},\"signed_requests_total\":{},\"audit_chain_valid\":{}}}",
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
            s.secret_rotations_total,
            s.dlp_blocked_total,
            s.bulkhead_rejected_total,
            s.jsonrpc_blocked_total,
            s.retries_total,
            s.in_flight_requests,
            s.signed_requests_total,
            audit_valid
        )
    }

    /// Renders standard Prometheus text format (`# HELP` / `# TYPE`) for all counters, gauges, and latency histograms (`Milestone 7`).
    pub fn to_prometheus(&self) -> String {
        let s = self.snapshot();
        let b100 = self.latency_le_100us.load(Ordering::Relaxed);
        let b500 = self.latency_le_500us.load(Ordering::Relaxed);
        let b1000 = self.latency_le_1000us.load(Ordering::Relaxed);
        let b5000 = self.latency_le_5000us.load(Ordering::Relaxed);
        let b10000 = self.latency_le_10000us.load(Ordering::Relaxed);
        let b50000 = self.latency_le_50000us.load(Ordering::Relaxed);
        let l_sum = self.latency_sum_us.load(Ordering::Relaxed);
        let l_count = self.latency_count.load(Ordering::Relaxed);
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
             # HELP edgegate_secret_rotations_total Total live in-memory secret rotations.\n\
             # TYPE edgegate_secret_rotations_total counter\n\
             edgegate_secret_rotations_total {}\n\
             # HELP edgegate_dlp_blocked_total Total outbound requests blocked by EdgeGate DLP payload inspection.\n\
             # TYPE edgegate_dlp_blocked_total counter\n\
             edgegate_dlp_blocked_total {}\n\
             # HELP edgegate_bulkhead_rejected_total Total requests rejected by per-workload concurrency bulkhead quotas.\n\
             # TYPE edgegate_bulkhead_rejected_total counter\n\
             edgegate_bulkhead_rejected_total {}\n\
             # HELP edgegate_jsonrpc_blocked_total Total requests blocked by JSON-RPC method allowlist policy.\n\
             # TYPE edgegate_jsonrpc_blocked_total counter\n\
             edgegate_jsonrpc_blocked_total {}\n\
             # HELP edgegate_retries_total Total controlled idempotent upstream failover retries.\n\
             # TYPE edgegate_retries_total counter\n\
             edgegate_retries_total {}\n\
             # HELP edgegate_in_flight_requests Current number of in-flight requests being processed.\n\
             # TYPE edgegate_in_flight_requests gauge\n\
             edgegate_in_flight_requests {}\n\
             # HELP edgegate_signed_requests_total Total outbound requests cryptographically signed with HMAC-SHA256.\n\
             # TYPE edgegate_signed_requests_total counter\n\
             edgegate_signed_requests_total {}\n\
             # HELP edgegate_request_duration_microseconds Request latency histogram in microseconds.\n\
             # TYPE edgegate_request_duration_microseconds histogram\n\
             edgegate_request_duration_microseconds_bucket{{le=\"100\"}} {}\n\
             edgegate_request_duration_microseconds_bucket{{le=\"500\"}} {}\n\
             edgegate_request_duration_microseconds_bucket{{le=\"1000\"}} {}\n\
             edgegate_request_duration_microseconds_bucket{{le=\"5000\"}} {}\n\
             edgegate_request_duration_microseconds_bucket{{le=\"10000\"}} {}\n\
             edgegate_request_duration_microseconds_bucket{{le=\"50000\"}} {}\n\
             edgegate_request_duration_microseconds_bucket{{le=\"+Inf\"}} {}\n\
             edgegate_request_duration_microseconds_sum {}\n\
             edgegate_request_duration_microseconds_count {}\n",
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
            s.secret_rotations_total,
            s.dlp_blocked_total,
            s.bulkhead_rejected_total,
            s.jsonrpc_blocked_total,
            s.retries_total,
            s.in_flight_requests,
            s.signed_requests_total,
            b100,
            b500,
            b1000,
            b5000,
            b10000,
            b50000,
            l_count,
            l_sum,
            l_count
        )
    }

    pub fn audit_entries(&self) -> Vec<AuditChainEntry> {
        let guard = match self.audit_ledger.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.entries.iter().cloned().collect()
    }

    /// Verifies that every retained entry in the hash-chained audit ledger matches its recomputed
    /// SHA-256 digest AND that each entry's `prev_hash` equals the preceding entry's `entry_hash`.
    pub fn verify_audit_chain(&self) -> bool {
        let guard = match self.audit_ledger.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.entries.is_empty() {
            return guard.last_audit_hash == GENESIS_AUDIT_HASH;
        }
        let mut expected_prev: Option<&str> = None;
        for entry in &guard.entries {
            if entry.seq == 1 && entry.prev_hash != GENESIS_AUDIT_HASH {
                return false;
            }
            if let Some(prev) = expected_prev {
                if entry.prev_hash != prev {
                    return false;
                }
            }
            let recomputed = compute_audit_entry_hash(
                &entry.prev_hash,
                entry.seq,
                entry.request_id,
                &entry.trace_id,
                &entry.org_id,
                &entry.workload_id,
                &entry.route,
                &entry.decision,
                entry.status,
            );
            if entry.entry_hash != recomputed {
                return false;
            }
            expected_prev = Some(&entry.entry_hash);
        }
        guard
            .entries
            .back()
            .is_some_and(|last| last.entry_hash == guard.last_audit_hash)
    }

    pub fn audit_to_json(&self) -> String {
        let valid = self.verify_audit_chain();
        let entries = self.audit_entries();
        let mut items = Vec::with_capacity(entries.len());
        for e in entries {
            items.push(format!(
                "{{\"seq\":{},\"request_id\":{},\"trace_id\":\"{}\",\"org_id\":\"{}\",\"workload_id\":\"{}\",\"route\":\"{}\",\"decision\":\"{}\",\"status\":{},\"prev_hash\":\"{}\",\"entry_hash\":\"{}\"}}",
                e.seq,
                e.request_id,
                escape_json(&e.trace_id),
                escape_json(&e.org_id),
                escape_json(&e.workload_id),
                escape_json(&e.route),
                escape_json(&e.decision),
                e.status,
                escape_json(&e.prev_hash),
                escape_json(&e.entry_hash)
            ));
        }
        format!("{{\"valid\":{},\"entries\":[{}]}}", valid, items.join(","))
    }

    /// Emits one structured JSON audit/request log line, updates lock-free latency histograms,
    /// and appends a SHA-256 hash-chained entry to the audit ledger.
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
        self.record_request_with_trace(
            request_id,
            trace_id,
            org_id,
            workload_id,
            route,
            upstream,
            decision,
            status,
            latency_us,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_request_with_trace(
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

        if latency_us <= 100 {
            self.latency_le_100us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 500 {
            self.latency_le_500us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 1_000 {
            self.latency_le_1000us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 5_000 {
            self.latency_le_5000us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 10_000 {
            self.latency_le_10000us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 50_000 {
            self.latency_le_50000us.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);

        {
            let mut guard = match self.audit_ledger.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let seq = guard.seq.saturating_add(1);
            let prev_hash = guard.last_audit_hash.clone();
            let entry_hash = compute_audit_entry_hash(
                &prev_hash,
                seq,
                request_id,
                trace_id,
                org_id,
                workload_id,
                route,
                decision,
                status,
            );
            guard.seq = seq;
            guard.last_audit_hash = entry_hash.clone();
            if guard.entries.len() >= self.replay_capacity {
                guard.entries.pop_front();
            }
            guard.entries.push_back(AuditChainEntry {
                seq,
                request_id,
                trace_id: trace_id.to_string(),
                org_id: org_id.to_string(),
                workload_id: workload_id.to_string(),
                route: route.to_string(),
                decision: decision.to_string(),
                status,
                prev_hash,
                entry_hash,
            });
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

#[allow(clippy::too_many_arguments)]
fn compute_audit_entry_hash(
    prev_hash: &str,
    seq: u64,
    request_id: u64,
    trace_id: &str,
    org_id: &str,
    workload_id: &str,
    route: &str,
    decision: &str,
    status: u16,
) -> String {
    let payload = format!(
        "{prev_hash}|{seq}|{request_id}|{trace_id}|{org_id}|{workload_id}|{route}|{decision}|{status}"
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

fn escape_json(s: &str) -> String {
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

/// Verifies a raw JSON audit response string from `/_edgegate/admin/audit` cryptographically.
/// Returns the number of verified entries on success, or an error description.
pub fn verify_audit_json(raw_json: &str) -> Result<usize, String> {
    #[derive(serde::Deserialize)]
    struct AuditResponse {
        valid: bool,
        entries: Vec<AuditChainEntry>,
    }

    let parsed: AuditResponse =
        serde_json::from_str(raw_json).map_err(|e| format!("failed to parse audit JSON: {e}"))?;

    if !parsed.valid {
        return Err("server reported valid=false".to_string());
    }

    let mut prev_entry: Option<&AuditChainEntry> = None;
    for entry in &parsed.entries {
        if entry.seq == 1 && entry.prev_hash != GENESIS_AUDIT_HASH {
            return Err(format!(
                "entry seq 1 has invalid prev_hash '{}' (expected genesis hash)",
                entry.prev_hash
            ));
        }
        if let Some(prev) = prev_entry {
            if entry.prev_hash != prev.entry_hash {
                return Err(format!(
                    "entry seq {} prev_hash '{}' does not match previous entry_hash '{}'",
                    entry.seq, entry.prev_hash, prev.entry_hash
                ));
            }
            if entry.seq != prev.seq + 1 {
                return Err(format!(
                    "entry seq {} is not sequential after previous seq {}",
                    entry.seq, prev.seq
                ));
            }
        }
        let recomputed = compute_audit_entry_hash(
            &entry.prev_hash,
            entry.seq,
            entry.request_id,
            &entry.trace_id,
            &entry.org_id,
            &entry.workload_id,
            &entry.route,
            &entry.decision,
            entry.status,
        );
        if entry.entry_hash != recomputed {
            return Err(format!(
                "entry seq {} entry_hash '{}' does not match recomputed hash '{}'",
                entry.seq, entry.entry_hash, recomputed
            ));
        }
        prev_entry = Some(entry);
    }

    Ok(parsed.entries.len())
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
