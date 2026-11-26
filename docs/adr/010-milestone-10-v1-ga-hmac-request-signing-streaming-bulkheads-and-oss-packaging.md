# ADR-010: Milestone 10 — v1.0.0 GA: Outbound Cryptographic Request Signing (HMAC-SHA256), Stream-Lifetime Bulkheads & Drain Guards, Trailer-Preserving Response Caps, Strict JSON-RPC Envelope Enforcement, and Production Hardening
- **Status:** Accepted
- **Date:** 2026-11-26
- **Owner:** Justin Mafie

## Context
With Milestones 1 through 9 delivering core L7 proxying, outbound/inbound TLS termination, HTTP/2 multiplexing, three-state circuit breakers, token-bucket rate limiting, response credential reflection guards, scoped credential TTL rotation, tamper-evident audit chains, outbound mTLS client authentication, egress DLP payload guards, workload concurrency bulkheads, and JSON-RPC / MCP allowlists, EdgeGate has reached its General Availability (`v1.0.0` GA) milestone.

Production deployment across distributed agent execution environments and high-security enterprises revealed five critical capabilities and hardening requirements necessary for `v1.0.0` GA:

1. **Outbound Cryptographic Request Signing — HMAC-SHA256 (`INV-23`, `[routes.request_signing]`):**
   Upstream APIs, webhooks, and modern AI tool backends increasingly require cryptographically signed requests (analogous to GitHub Webhook signatures, AWS Signature Version 4, or Slack request verification) to authenticate the origin and verify payload integrity. When untrusted agent sandboxes issue requests to external webhook receivers or internal microservices, the sandbox cannot hold the shared HMAC secret without violating the zero-secret invariant. Furthermore, malicious or buggy sandboxes might forge `X-EdgeGate-Signature-256` or `X-EdgeGate-Timestamp` headers to bypass downstream checks. EdgeGate requires a pure-Rust, RFC 2104 compliant HMAC-SHA256 request signing mechanism that strips caller-forged signature/timestamp headers, validates org-scoped secret TTLs fail-closed, and injects tamper-proof timestamp and hex signatures on outbound dispatches.

2. **Stream-Lifetime Workload Bulkhead & Graceful-Drain Guards (`INV-20` Hardening):**
   In Milestone 9, workload bulkhead permits (`max_concurrent_requests`) and server in-flight request gauges (`in_flight_requests`) were acquired during request arrival. However, streaming protocols—such as Server-Sent Events (SSE), gRPC streams, and chunked HTTP/1.1 or HTTP/2 transfers—frequently keep connections open for seconds, minutes, or hours after initial response headers arrive. If bulkhead permits or drain guards are released upon header receipt, an active streaming connection escapes concurrency tracking, allowing rogue sandboxes to bypass `max_concurrent_requests` and causing server shutdown draining (`drain_timeout_ms`) to terminate prematurely while active streams are still in transit. Additionally, atomic active counters (`Arc<AtomicUsize>`) must persist across live `ArcSwap` hot reloads to avoid resetting in-flight tallies.

3. **Trailer-Preserving Response Size Caps & Circuit-Breaker Fault Isolation (`INV-21` Hardening):**
   When `max_response_body_bytes` is enforced on streaming responses, HTTP/2 and gRPC streams communicate terminal status via trailing headers (trailers, e.g., `grpc-status`, `grpc-message`). Truncating response bodies must not drop trailers for valid streams, and `strip_response_headers` must be applied consistently to trailers in `BufferedBodyWithTrailers`. Crucially, when an upstream response exceeds `max_response_body_bytes`, returning `502 Bad Gateway` is a client/route SLA policy violation, not an upstream transport crash. Treating payload limit violations as backend faults caused circuit breakers to falsely trip from `Closed` to `Open`, disrupting unrelated requests sharing the pool. EdgeGate must distinguish `http_body_util::LengthLimitError` from transport failures to isolate circuit breaker state.

4. **Strict JSON-RPC 2.0 Envelope Validation & Explicit Empty Allowlist (`INV-22` Hardening):**
   In MCP tool routing, an explicit empty allowlist (`allowed_jsonrpc_methods = []`) must mean "deny all methods fail-closed (`403 Forbidden`)", distinct from omitting the property (`None`), which disables JSON-RPC inspection. Furthermore, single and batch JSON-RPC requests must strictly carry `"jsonrpc": "2.0"` to reject legacy JSON-RPC 1.0 or malformed envelope smuggling.

5. **CLI Cleartext Admin Credential Protection:**
   The `edgegate audit` CLI tool transmits the highly sensitive administrative token (`X-EdgeGate-Admin-Token`) to fetch and verify the cryptographic audit ledger. Transmitting this token over unencrypted `http://` across public or non-loopback networks exposes administrative credentials to passive interception. The CLI must refuse cleartext transport to non-loopback hosts unless an operator explicitly passes `--allow-insecure-http`, and must reject `--ca-cert` on `http://` URLs where TLS verification is inapplicable.

---

## Decision

### 1. Outbound Cryptographic Request Signing — HMAC-SHA256 (`INV-23`, [../../src/config.rs](../../src/config.rs), [../../src/router.rs](../../src/router.rs), [../../src/proxy.rs](../../src/proxy.rs), [../../src/telemetry.rs](../../src/telemetry.rs))
- **Configuration Model:**
  Extend `RouteConfig` (`[[routes]]`) and `CompiledRoute` with `request_signing: Option<RequestSigningConfig>`:
  ```toml
  [routes.request_signing]
  credential_ref = "webhook_hmac_key"          # Resolves org-scoped secret in [[secrets]]
  signature_header = "X-EdgeGate-Signature-256" # Header receiving sha256=<hex_digest>
  timestamp_header = "X-EdgeGate-Timestamp"     # Header receiving Unix epoch seconds
  ```
- **Forged Header Stripping:**
  In `sanitize_outbound_headers` ([../../src/router.rs](../../src/router.rs)), unconditionally strip both `signature_header` (`X-EdgeGate-Signature-256`) and `timestamp_header` (`X-EdgeGate-Timestamp`) from incoming requests prior to signing so callers cannot inject forged signatures or manipulate timestamp windows.
- **Canonical Payload & Signature Computation:**
  - Retrieve the signing key using `SecretProvider::get_secret(&identity.org_id, &signing.credential_ref)`. Verify that `expires_at_epoch_s` has not elapsed; if missing or expired, fail closed with `403 Forbidden`.
  - Capture current Unix epoch seconds `timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()`.
  - Canonicalize the signing input as `<timestamp>.<raw_body>` (using empty byte slice for empty bodies).
  - Compute RFC 2104 HMAC-SHA256 using `ring::hmac` or `hmac` + `sha2`. Format the resulting digest as `sha256=<lowercase_hex_string>`.
  - Inject `X-EdgeGate-Timestamp: <timestamp>` and `X-EdgeGate-Signature-256: sha256=<hex>` into outbound request headers before upstream pool dispatch.
- **Observability:**
  Increment atomic telemetry counter `signed_requests_total` (`edgegate_signed_requests_total` in Prometheus exposition format) upon every successful signature injection.

### 2. Stream-Lifetime Workload Bulkhead & Graceful-Drain Guards (`INV-20` Hardening, [../../src/auth.rs](../../src/auth.rs), [../../src/proxy.rs](../../src/proxy.rs))
- **Live-Reload Persistent Counters:**
  Workload concurrency is tracked via `Arc<AtomicUsize>` active counters keyed by `(org_id, workload_id)` in `WorkloadAuthenticator`. When `RuntimeSnapshot` is atomically swapped via `ArcSwap`, active counter instances for surviving workloads are preserved, preventing counter resets or permit leaks across configuration hot reloads.
- **`GuardedResponseBody` Wrapper:**
  Wrap upstream response bodies in `GuardedResponseBody`:
  ```rust
  pub struct GuardedResponseBody<B> {
      inner: B,
      _bulkhead_guard: Option<WorkloadBulkheadGuard>,
      _in_flight_guard: Option<InFlightGuard>,
  }
  ```
  Both `WorkloadBulkheadGuard` (decrementing active workload count) and `InFlightGuard` (decrementing `in_flight_requests`) are retained inside `GuardedResponseBody` until `inner.poll_frame()` returns `Poll::Ready(None)` (clean stream EOF) or `GuardedResponseBody` is dropped (client disconnect, cancellation, or error). This ensures SSE, gRPC, and chunked streams remain accounted against concurrency quotas and server shutdown drains for their full operational lifetime.

### 3. Trailer-Preserving Response Size Caps & Circuit-Breaker Fault Isolation (`INV-21` Hardening, [../../src/proxy.rs](../../src/proxy.rs), [../../src/lb.rs](../../src/lb.rs))
- **Trailer-Preserving Bounded Stream:**
  When `max_response_body_bytes` is configured, EdgeGate bounds response frames using `BufferedBodyWithTrailers` that accumulates frames up to the limit while capturing HTTP/2 trailers (e.g., `grpc-status`, `grpc-message`). Configured `strip_response_headers` are stripped from both initial response headers and trailing headers.
- **Circuit-Breaker Fault Isolation:**
  When an upstream response violates `max_response_body_bytes` (`http_body_util::LengthLimitError`), EdgeGate aborts the transfer with `502 Bad Gateway` (`{"error":"upstream response exceeded maximum allowed body size"}`) and increments `upstream_errors_total`. However, EdgeGate explicitly bypasses `CircuitBreaker::record_failure` on `LengthLimitError`. A route-level payload overflow represents a payload policy boundary, not an upstream node crash, preventing false breaker trips from affecting sibling traffic.

### 4. Strict JSON-RPC 2.0 Envelope Validation & Explicit Empty Allowlist (`INV-22` Hardening, [../../src/policy.rs](../../src/policy.rs), [../../src/config.rs](../../src/config.rs))
- **Option Representation:**
  Represent `allowed_jsonrpc_methods` in `PolicyRuleConfig` and `CompiledPolicyRule` as `Option<Vec<String>>`:
  - `None`: JSON-RPC inspection is disabled; arbitrary payloads are permitted.
  - `Some(methods)`: JSON-RPC inspection is active. If `methods` is empty (`[]`), all JSON-RPC methods are denied fail-closed (`403 Forbidden`).
- **Strict Protocol Enforcement:**
  Both single JSON-RPC objects and items within batch arrays must carry `"jsonrpc": "2.0"`. Any object missing `"jsonrpc": "2.0"` or specifying another version is rejected fail-closed with `400 Bad Request` or `403 Forbidden`.

### 5. CLI Cleartext Admin Credential Protection ([../../src/main.rs](../../src/main.rs))
- **Transport Security Enforcement in `edgegate audit`:**
  - If `--url` uses the `http://` scheme and targets a non-loopback host (not `127.0.0.1`, `localhost`, or `::1`), `edgegate audit` refuses execution with an explicit security error unless `--allow-insecure-http` is explicitly passed.
  - If `--ca-cert` is supplied with an `http://` URL, execution is rejected immediately as a contradictory configuration.

---

## Alternatives Considered

1. **HMAC Signing via Custom Token Format vs. RFC 2104 / Standardized `sha256=` Scheme:**
   Using bespoke token framing creates vendor lock-in and requires custom upstream parsers. Standardizing on `X-EdgeGate-Timestamp: <unix_s>` and `X-EdgeGate-Signature-256: sha256=<hex>` over `<timestamp>.<raw_body>` mirrors industry standards (GitHub Webhooks, Slack, Stripe), enabling native compatibility with existing upstream signature verification libraries.
2. **Releasing Bulkhead Permits on Response Header Arrival vs. Body EOF:**
   Releasing permits as soon as initial HTTP headers arrive frees up concurrency slots earlier. However, for streaming AI responses (SSE token streams lasting tens of seconds), this permits a single sandbox to maintain hundreds of active streaming sockets concurrently, saturating host TCP file descriptors and defeating the core objective of bulkhead isolation (`INV-20`). Holding permits across the full body lifetime via `GuardedResponseBody` is the only safe invariant.
3. **Tripping Circuit Breakers on Body Size Violations:**
   Treating `LengthLimitError` as an upstream fault treats a route policy constraint as a backend outage. A single large file download request would trip the circuit breaker and black-hole all subsequent requests to that backend. Isolating body limit errors protects pool availability.
4. **Boolean Flag vs. `Option<Vec<String>>` for JSON-RPC Enforcement:**
   Using a separate boolean flag (e.g. `enforce_jsonrpc = true`) alongside `allowed_jsonrpc_methods: Vec<String>` introduces redundant state. Utilizing `Option<Vec<String>>` provides clean serde semantics where omitted field = disabled, while `allowed_jsonrpc_methods = []` cleanly represents a zero-method default-deny configuration.

---

## Consequences & Failure Modes

### Positive Consequences
- Untrusted workloads can invoke webhook and API destinations requiring HMAC-SHA256 signatures with zero shared secrets in the sandbox (`INV-23`).
- Streaming workloads (SSE, gRPC, chunked HTTP) cannot escape concurrency bulkheads or truncate during server graceful shutdown (`INV-20`).
- Route response body size limits protect gateway memory without risking false-positive circuit breaker trips (`INV-21`).
- MCP tool endpoints can be completely locked down or strictly allowlisted with guaranteed JSON-RPC 2.0 conformance (`INV-22`).
- Operator credentials are protected against cleartext network snooping during CLI audit operations.

### Failure Modes & Mitigations
- **Timestamp Drift on Signed Requests:**
  If the gateway host's clock drifts significantly, upstream signature verifiers that enforce strict timestamp windows (e.g. ±5 minutes) will reject signatures. *Mitigation:* Operators must synchronize host clocks via NTP.
- **Large Streaming Responses Blocking Bulkheads:**
  Sandboxes executing many concurrent long-lived SSE connections may reach `max_concurrent_requests` and receive `429 Too Many Requests`. *Mitigation:* Workload owners should configure appropriate bulkhead quotas for streaming workloads, and clients should respect `Retry-After: 1`.
- **Payload Cap Rejection on Large Legitimate Responses:**
  Legitimate large payloads exceeding `max_response_body_bytes` receive `502 Bad Gateway`. *Mitigation:* Route owners should set dedicated `max_response_body_bytes` on large data routes or utilize upstream pagination.
