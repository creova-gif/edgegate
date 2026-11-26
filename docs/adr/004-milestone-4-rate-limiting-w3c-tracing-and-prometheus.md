# ADR-004: Milestone 4 — Token-Bucket Rate Limiting, W3C Trace Context Propagation, and Prometheus Exposition
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Following Milestone 3 (HTTP/2 multiplexing, three-state circuit breakers, consistent/latency-aware load balancing, asynchronous traffic shadowing, sanitized flight-recorder replay, and dynamic Boxlet UDS attachment), production deployments require three additional operational capabilities:
1. Per-policy-rule rate limiting to prevent runaway or noisy-neighbor AI/sandbox workloads from exhausting upstream API quotas.
2. End-to-end W3C Trace Context (`traceparent`) validation, generation, upstream propagation, and response/audit correlation.
3. Native Prometheus text-format exposition (`# HELP` / `# TYPE`) on `/_edgegate/metrics` alongside the existing JSON snapshot format.

## Decision
1. **Per-Rule Token-Bucket Rate Limiting (`src/config.rs`, `src/policy.rs`, `src/proxy.rs`, `src/lib.rs`):**
   - `PolicyRuleConfig` and `CompiledPolicyRule` accept optional `rate_limit_rps: Option<u32>` and `rate_limit_burst: Option<u32>` (validated `> 0` at config compile time).
   - `DefaultDenyPolicyEngine` attaches a `TokenBucket` (`Mutex<(f64, Instant)>` with poison-safe recovery) to each policy rule that configures a rate limit.
   - When a matching rule's token bucket is exhausted, `DefaultDenyPolicyEngine::evaluate` returns `PolicyDecision::RateLimited { reason }`, which `EdgeGateProxy` maps to `EdgeGateError::TooManyRequests` (`429 Too Many Requests`) with `retry-after: 1`, decision `"RATE_LIMITED"`, and increments `rate_limited_total`.
2. **W3C `traceparent` Validation, Generation & Correlation (`src/router.rs`, `src/proxy.rs`, `src/telemetry.rs`):**
   - `resolve_or_generate_traceparent(incoming, request_id)` validates incoming `traceparent` headers against the W3C specification (`00-<32 hex>-<16 hex>-<2 hex>` with non-zero trace and parent IDs). If absent or malformed, it generates a deterministic W3C `traceparent` and 32-hex `trace_id` from the nanosecond timestamp and monotonic `request_id`.
   - `EdgeGateProxy` sets the normalized `traceparent` on outbound upstream requests, attaches `x-edgegate-trace-id` to every response, and records `trace_id` in structured audit logs and `ReplayRecord` flight-recorder entries.
3. **Prometheus Metrics Exposition (`src/telemetry.rs`, `src/proxy.rs`):**
   - `Telemetry::to_prometheus()` renders standard Prometheus text format (`0.0.4`) with `# HELP` and `# TYPE` annotations for all counters (`edgegate_requests_allowed_total`, `edgegate_requests_blocked_total`, `edgegate_requests_rate_limited_total`, `edgegate_upstream_errors_total`, `edgegate_reloads_total`, `edgegate_reload_failures_total`, `edgegate_shadow_requests_total`, `edgegate_shadow_mismatches_total`) and the `edgegate_config_generation` gauge.
   - `GET /_edgegate/metrics` serves Prometheus format when the query string includes `format=prometheus` or `Accept` includes `text/plain`, while preserving JSON output by default.

## Alternatives Considered
- **Global Per-Server Rate Limiting Only:** Rejected because multi-tenant workloads require per-policy (`org_id`, `workload_id`, `route_id`) isolation so one tenant cannot starve another.
- **External OpenTelemetry Collector Dependency on Hot Path:** Rejected to keep the data plane zero-allocation/minimal-overhead and dependency-light while remaining 100% wire-compatible with W3C Trace Context and Prometheus scrapers.

## Consequences & Failure Modes
- **Positive:** Protects upstream SaaS/LLM quotas from bursty sandbox agents, correlates every request across client -> EdgeGate -> upstream -> `/_edgegate/replay` via `trace_id`, and integrates directly with Prometheus scrapers.
- **Failure Modes Mitigated:** Malformed or spoofed `traceparent` headers are replaced with valid W3C trace contexts; poisoned mutexes recover without panicking (zero `.unwrap()`/`.expect()` in production paths).
