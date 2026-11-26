# ADR-007: Milestone 7 — Authenticated Admin Control Plane API, Cryptographic SHA-256 Hash-Chained Tamper-Evident Audit Ledger, Weighted Canary Load Balancing, Per-Rule Query-Param & Payload Resource Guards, and Lock-Free Prometheus Latency Histograms
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Following Milestone 6 (scoped credential rotation & fail-closed TTL expiry, programmable request-attribute policy matching via `required_headers`, zero-downtime dual workload token rollover, and CLI `status` / `replay` subcommands), production multi-tenant deployments of EdgeGate (`v0.7.0`) governing **Boxlet** (execution sandboxes), **Keelway** (MCP tool governance), and **IoRa** (RAG and inference compliance workflows) require five additional control-plane, cryptographic compliance, traffic engineering, L7 security, and observability capabilities:

1. **Authenticated Admin Control Plane API (`/_edgegate/admin/reload`, `/_edgegate/admin/secrets/rotate`, `/_edgegate/admin/audit`):**
   While Milestone 6 introduced programmatic Rust APIs (`reload_from_toml_str`, `rotate_secret`) and OS signal handling (`SIGHUP`), remote control planes, secret-management sidecars, and compliance auditors need an authenticated HTTP control-plane API to trigger atomic live configuration reloads, rotate or revoke tenant secrets on the fly, and inspect/verify the tamper-evident audit ledger. To preserve EdgeGate's strict zero-trust posture, these endpoints must fail closed by default whenever `server.admin_token` and `server.admin_token_sha256` are unset, and must authenticate presented `X-EdgeGate-Admin-Token` headers in constant time.

2. **Cryptographic SHA-256 Hash-Chained Tamper-Evident Audit Ledger (`INV-16`):**
   Standard in-memory flight-recorder buffers (`/_edgegate/replay`) provide operational visibility, but regulated `IoRa` inference pipelines and enterprise security compliance require cryptographic tamper-evidence over every gateway decision. Every request processed by EdgeGate must append a monotonically sequenced record whose `entry_hash` is cryptographically chained to the preceding record's hash (`prev_hash`), beginning from a deterministic genesis digest (`64` hex zeros), with continuous chain verification (`verify_audit_chain()`) exposed both programmatically and over `/_edgegate/admin/audit`.

3. **Weighted Canary Load Balancing (`weight` on `[[pools.backends]]`):**
   Equal-weight round-robin across backend pool members could not express staged canary rollouts (such as `90/10` or `75/25` traffic splits between stable and canary model endpoints or upstream regions). Operators need deterministic weighted round-robin scheduling (`weight: u32`, defaulting to `1`, rejecting `0`) that composes cleanly with EdgeGate's per-backend three-state circuit breakers (`Closed` / `Open` / `HalfOpen`).

4. **Per-Rule Query-Param & Payload Resource Guards (`INV-17`, `forbidden_query_params`, `max_body_bytes`):**
   L7 policy enforcement needed two finer-grained guards before any upstream connection or credential vault lookup occurs:
   - Query parameter blocklisting (`forbidden_query_params` on `[[policy.rules]]`) to block dangerous query flags (e.g., `?debug=1`, `?admin=true`, `?raw_prompt=1`, or URL-encoded variants) with `403 Forbidden`.
   - Per-rule / per-tenant payload size caps (`max_body_bytes` on `[[policy.rules]]`) so individual routes or tenants can enforce stricter request payload limits than the global `server.max_body_bytes` ceiling, failing closed with `413 Payload Too Large` before upstream egress.

5. **Lock-Free Prometheus Latency Histograms (`edgegate_request_duration_microseconds`):**
   Counter-only telemetry could not quantify p50 / p95 / p99 gateway latency SLOs under load. EdgeGate requires lock-free (`AtomicU64`) Prometheus histogram buckets in microseconds (`le="100"` through `le="50000"` plus `le="+Inf"`), alongside `_sum` and `_count`, updated on every completed request without mutex contention on the hot path.

## Decision
1. **Authenticated Admin Control Plane API (`src/config.rs`, `src/proxy.rs`, `src/telemetry.rs`):**
   - Extend `[server]` (`ServerConfig`) with optional `admin_token: Option<String>` and `admin_token_sha256: Option<String>`, compiled into `admin_token_sha256: Option<[u8; 32]>` on `CompiledConfig` (rejecting empty tokens, invalid SHA-256 hex digests, or mismatched plaintext/digest pairs at config validation time).
   - Gate all `/_edgegate/admin/*` endpoints behind constant-time SHA-256 verification (`subtle::ConstantTimeEq`) of the `X-EdgeGate-Admin-Token` request header:
     - If no admin token is configured on the server, all `/_edgegate/admin/*` requests fail closed with `403 Forbidden` (`admin control plane is disabled`) and increment `edgegate_admin_requests_unauthorized_total`.
     - If `X-EdgeGate-Admin-Token` is missing or its SHA-256 digest does not match in constant time, respond with `401 Unauthorized` and increment `edgegate_admin_requests_unauthorized_total`.
   - Expose three admin endpoints:
     - `POST /_edgegate/admin/reload`: Parses the request body as TOML configuration and atomically swaps the live `ArcSwap<CompiledConfig>` via `reload_from_toml_str`.
     - `POST /_edgegate/admin/secrets/rotate`: Accepts `key=value` lines (`org_id`, `credential_ref`, `value`, optional `ttl_ms`, or `revoke=true`) to rotate or revoke scoped tenant credentials in memory without restarting or reloading the proxy.
     - `GET /_edgegate/admin/audit`: Returns a JSON payload containing `"verified": verify_audit_chain()`, `"chain_length"`, and the `"entries"` array of hash-chained `AuditEntry` records.

2. **Cryptographic SHA-256 Hash-Chained Tamper-Evident Audit Ledger (`INV-16`, `src/telemetry.rs`, `src/proxy.rs`):**
   - Introduce `AuditEntry` and `AuditLedger` in `src/telemetry.rs`.
   - Each appended entry computes:
     `entry_hash = SHA256(prev_hash || seq || request_id || trace_id || org_id || workload_id || route || decision || status)`
     using domain-separated fields and starting from genesis `prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"` (`64` hex zeros).
   - Maintain a monotonic sequence number (`seq`) and the latest `head_hash` across the bounded ring buffer so every recorded decision is cryptographically linked to its predecessor.
   - Provide `AuditLedger::verify_chain()` and `EdgeGateProxy::verify_audit_chain()` to recompute every entry's SHA-256 digest and verify contiguous `prev_hash -> entry_hash` linkage from the earliest retained entry through the head of the chain.

3. **Weighted Canary Load Balancing (`src/config.rs`, `src/proxy.rs`):**
   - Add `#[serde(default = "default_backend_weight")] pub weight: u32` (default `1`) to `BackendEndpointConfig` (`[[pools.backends]]`).
   - Validate during `CompiledConfig::compile` that every backend has `weight >= 1` and that the total pool weight is non-zero.
   - Precompute a deterministic weighted selection schedule (`weighted_schedule: Vec<usize>`) per `CompiledBackendPool` (capped with GCD normalization so large weights such as `90` and `10` reduce cleanly to minimal deterministic schedules while preserving exact traffic ratios).
   - During upstream selection, step through the weighted schedule via the pool's atomic cursor while skipping any backend whose circuit breaker is currently `Open`, falling back cleanly across remaining healthy backends.

4. **Per-Rule Query-Param & Payload Resource Guards (`INV-17`, `src/config.rs`, `src/policy.rs`, `src/proxy.rs`, `src/telemetry.rs`):**
   - Extend `PolicyRuleConfig` (`[[policy.rules]]`) and `CompiledPolicyRule` with:
     - `#[serde(default)] pub forbidden_query_params: Vec<String>` (normalized to lowercase during compilation, rejecting empty parameter names).
     - `#[serde(default)] pub max_body_bytes: Option<usize>` (rejecting `Some(0)` at validation time).
   - Extend `PolicyEngine::evaluate_full(&self, identity, route_id, method, path, query, headers)` to parse the raw URI query string (including URL-decoded parameter names, case-insensitively) and reject requests containing any parameter listed in `forbidden_query_params` (`PolicyDecision::Deny` -> `403 Forbidden`), while returning `matched_max_body_bytes` on `PolicyDecision::Allow`.
   - Enforce `matched_max_body_bytes` on the inbound request body in `EdgeGateProxy::handle_request`: if the collected body exceeds the matched policy rule's `max_body_bytes`, fail closed with `413 Payload Too Large`, increment `edgegate_payload_too_large_blocked_total`, record a flight-recorder replay entry (`reason = "policy_max_body_bytes_exceeded"`), and append to the hash-chained audit ledger before any secret lookup or upstream socket connection.

5. **Lock-Free Prometheus Latency Histograms (`src/telemetry.rs`, `src/proxy.rs`):**
   - Add lock-free `AtomicU64` latency histogram counters to `MetricsRegistry` covering upper-bound microsecond buckets `100`, `250`, `500`, `1000`, `2500`, `5000`, `10000`, `25000`, `50000`, and `+Inf`, plus `edgegate_request_duration_microseconds_sum` and `edgegate_request_duration_microseconds_count`.
   - Record request duration in microseconds on every request path and render cumulative Prometheus histogram buckets (`edgegate_request_duration_microseconds_bucket{le="..."}`) alongside `edgegate_admin_requests_total`, `edgegate_admin_requests_unauthorized_total`, `edgegate_payload_too_large_blocked_total`, and `edgegate_audit_chain_length` on `/_edgegate/metrics`.

## Alternatives Considered
- **Separate unauthenticated local-only admin socket vs. token-authenticated in-band HTTP control plane:** While Unix Domain Sockets can restrict local access, containerized and Kubernetes control planes frequently require remote HTTP orchestration over mTLS/TLS. Enforcing fail-closed default-disable when `admin_token` / `admin_token_sha256` is unset and verifying `X-EdgeGate-Admin-Token` with `subtle::ConstantTimeEq` over SHA-256 digests secures in-band management without opening an unauthenticated surface.
- **External append-only database on the request hot path for audit logging:** Synchronous network writes to an external ledger on every proxied request would violate EdgeGate's sub-millisecond latency budget. Computing SHA-256 hash chains in-memory (`AuditLedger`) and exposing cryptographic verification via `GET /_edgegate/admin/audit` provides tamper-evident ordering with microsecond overhead, allowing asynchronous compliance shippers to poll and verify snapshots.
- **Floating-point random sampling (PRNG) for canary weights:** Probabilistic PRNG selection introduces variance on small request volumes and complicates deterministic unit testing. Precomputing GCD-normalized weighted round-robin schedules guarantees exact `90/10` or `75/25` distribution over every $N$ requests and remains completely lock-free (`AtomicUsize::fetch_add`).

## Consequences & Failure Modes
- **Positive:**
  - Operators can trigger zero-downtime TOML reloads, rotate/revoke individual tenant secrets, and pull verified cryptographic audit trails remotely via `/_edgegate/admin/*`.
  - Every allow/deny/error gateway decision is recorded in a SHA-256 hash-chained ledger (`INV-16`) whose integrity can be cryptographically verified at any time (`verify_audit_chain()`).
  - Weighted canary pools allow gradual rollout of new upstream model endpoints or regional backends while preserving automatic circuit-breaker failover.
  - Fine-grained per-rule `forbidden_query_params` (`403`) and `max_body_bytes` (`413`) guards (`INV-17`) stop malicious query flags and oversized tenant payloads at the L7 policy layer before secrets or upstreams are accessed.
  - Lock-free microsecond histograms (`edgegate_request_duration_microseconds`) provide real-time tail-latency observability in Prometheus without lock contention.
- **Failure Modes & Mitigations:**
  - *Unconfigured admin token in production:* By design, omitting `admin_token` and `admin_token_sha256` causes all `/_edgegate/admin/*` endpoints to fail closed (`403 Forbidden`), ensuring no accidental open control plane.
  - *Bounded audit ring buffer wrap-around:* When the in-memory `AuditLedger` exceeds its configured capacity and evicts the oldest entry, `verify_chain()` validates internal `prev_hash == predecessor.entry_hash` and recomputes SHA-256 digests across all retained entries (and additionally verifies genesis `000...000` when `seq == 1` is present).
  - *Extreme backend weight values (e.g., `weight = 100000` vs `weight = 1`):* GCD reduction followed by schedule bounding prevents excessive memory allocation in `CompiledBackendPool` while preserving proportional canary routing.
