# ADR-009: Milestone 9 — Workload Bulkheads, JSON-RPC 2.0 / MCP Tool Method Allowlists, Route Timeout SLAs, and Protocol & Control-Plane Hardening
- **Status:** Accepted
- **Date:** 2026-11-26
- **Owner:** Justin Mafie

## Context
Following Milestone 8 (`v0.8.0`, outbound mTLS client certificate authentication, egress DLP payload filtering, programmable response header stripping/injection, and admin pool topology introspection), production deployments of EdgeGate (`v0.9.0`) require four architectural capabilities to defend against noisy-neighbor starvation, enforce granular route service-level agreements (SLAs), prevent model/tool execution hijacking via Model Context Protocol (MCP) JSON-RPC 2.0 requests, and harden L7 protocols and control-plane auditing:

1. **Per-Workload Concurrency Quotas / Bulkhead Isolation (`INV-20`, `max_concurrent_requests`):**
   In multi-tenant AI agent deployments, autonomous agents frequently execute looping sub-tasks or unconstrained concurrent tool calls. While token-bucket rate limits (`rate_limit_rps` / `rate_limit_burst`) throttle request arrival rates, slow upstream endpoints (such as LLM generation or complex database tools) allow an aggressive or stalled sandbox to accumulate dozens or hundreds of concurrent in-flight connections. This saturates shared upstream connection pool semaphores (`max_connections_per_upstream`), starving well-behaved neighbor workloads. EdgeGate requires per-workload concurrency bulkhead isolation across both token-authenticated TCP workloads and zero-token Unix domain socket listeners to strictly partition concurrency capacity.

2. **Per-Route Request Timeout Overrides & Upstream Response Body Size Caps (`INV-21`, `timeout_ms`, `max_response_body_bytes`):**
   Different upstream services exhibit wildly divergent latency profiles and payload dimensions. A global gateway timeout (`server.response_timeout_ms`, e.g. 10 seconds) is either too short for long-running streaming inference/MCP tool pipelines or dangerously permissive for sub-second microservices. Furthermore, unconstrained upstream response bodies allow a misconfigured or compromised backend to stream gigabytes of unbounded data, threatening gateway heap exhaustion. EdgeGate requires route-level response timeout overrides (`timeout_ms`) and upstream response body size limits (`max_response_body_bytes`) enforced fail-closed (`502 Bad Gateway` on response payload overflow).

3. **JSON-RPC 2.0 / MCP Tool-Call Method Allowlisting (`INV-22`, `allowed_jsonrpc_methods`):**
   Modern AI agent platforms increasingly standardize on JSON-RPC 2.0 and the Model Context Protocol (MCP) for tool execution and resource retrieval. While HTTP path and header policies (`required_headers = { "x-mcp-tool" = "..." }`) govern simple REST endpoints, true MCP servers multiplex all tool calls, resource queries, and prompt retrievals over a single HTTP endpoint (`POST /mcp` or `POST /jsonrpc`) using JSON-RPC 2.0 payloads (`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"..."}}`). Attackers or rogue agents can bypass URI-level controls or smuggle unauthorized method calls inside JSON-RPC batch arrays (`[{"method":"tools/list"}, {"method":"tools/delete_database"}]`). EdgeGate requires deep, conformant RFC 8259 syntactic inspection of incoming JSON-RPC payloads to validate all single and batch method calls against an explicit allowlist before backend checkout.

4. **Protocol & Control-Plane Hardening:**
   - **Active HTTP/2 Health Probing:** Health check probes configured with `health_check_path` previously established basic HTTP/1.1 connections. Backends configured for HTTP/2 (`http2 = true`) with plaintext `h2c` or TLS/mTLS ALPN `h2` require proactive health checks using genuine HTTP/2 streams to verify multiplexing health prior to production traffic routing.
   - **HTTP/2 Response Trailer Scrubbing:** While Milestone 8 stripped sensitive or fingerprinting response headers (`strip_response_headers`), HTTP/2 framing permits trailing headers (trailers) delivered after the response body. If an upstream emits stripped header names as trailers, sensitive metadata could bypass the gateway boundary.
   - **Hardened Operator Audit CLI (`edgegate audit`):** The `edgegate audit` verification tool must securely interact with production gateways over verified HTTPS (`--ca-cert`), support automated secret injection via environment variables (`EDGEGATE_ADMIN_TOKEN`), and perform client-side SHA-256 hash-chain verification from genesis to the ledger head.

## Decision

1. **Per-Workload Concurrency Quotas / Bulkhead Isolation (`INV-20`, [src/config.rs](src/config.rs), [src/auth.rs](src/auth.rs), [src/proxy.rs](src/proxy.rs), [src/telemetry.rs](src/telemetry.rs)):**
   - Extend `WorkloadConfig` (`[[workloads]]`), `UnixListenerConfig` (`[[server.unix_listeners]]`), and `CompiledWorkload` with optional `max_concurrent_requests: Option<usize>`, validating that values must be `> 0`.
   - Maintain a dedicated in-memory registry of concurrency semaphores keyed by `(org_id, workload_id)` inside `WorkloadAuthenticator` or runtime state.
   - During `EdgeGateProxy::handle_request_with_auth`, immediately following workload identity resolution and before routing or rate limiting, acquire an `OwnedSemaphorePermit` (or speculative permit) if `max_concurrent_requests` is configured for the workload.
   - If the workload has exhausted its permitted concurrency quota:
     - Reject the request immediately with `429 Too Many Requests`.
     - Include header `Retry-After: 1`.
     - Return JSON error payload: `{"error":"workload concurrency limit exceeded"}`.
     - Increment Prometheus counter `edgegate_bulkhead_rejected_total` (`bulkhead_rejected_total` in JSON metrics).
     - Record an audit ledger entry with decision `RATE_LIMITED` / `BULKHEAD_EXCEEDED` and `upstream = "-"`.
   - Hold the bulkhead permit across the entire request lifecycle (in-flight request processing, upstream checkout, body streaming, and response delivery) via an RAII guard so permits are unconditionally reclaimed upon stream completion, client abort, or upstream timeout.

2. **Per-Route Request Timeout Overrides & Upstream Response Body Size Caps (`INV-21`, [src/config.rs](src/config.rs), [src/proxy.rs](src/proxy.rs), [src/pool.rs](src/pool.rs)):**
   - Extend `RouteConfig` (`[[routes]]`) and `CompiledRoute` with:
     - `timeout_ms: Option<u64>` (validated `> 0`). When set, `timeout_ms` overrides the default `server.response_timeout_ms` for upstream response generation on this route. If the upstream fails to return initial response headers within this deadline, EdgeGate aborts the attempt with `504 Gateway Timeout`.
     - `max_response_body_bytes: Option<usize>` (validated `> 0`). When set, establishes an upper bound on bytes delivered by the upstream response body.
   - Enforce `max_response_body_bytes` on the streaming response body:
     - Wrap incoming upstream response body frames in a bounded stream collector or frame-counting guard.
     - If the accumulated response payload exceeds `max_response_body_bytes`, immediately terminate the transfer, drop the upstream connection to prevent dirty socket reuse, increment `upstream_errors_total`, and fail closed with `502 Bad Gateway` (`{"error":"upstream response exceeded maximum allowed body size"}`).

3. **JSON-RPC 2.0 / MCP Tool-Call Method Allowlisting (`INV-22`, [src/config.rs](src/config.rs), [src/policy.rs](src/policy.rs), [src/proxy.rs](src/proxy.rs), [src/telemetry.rs](src/telemetry.rs)):**
   - Extend `PolicyRuleConfig` (`[[policies]]`) and `CompiledPolicyRule` with `#[serde(default)] pub allowed_jsonrpc_methods: Vec<String>`, compiled into a lookup set (`HashSet<String>`).
   - In `DefaultDenyPolicyEngine::evaluate_full`, if the matched rule defines `allowed_jsonrpc_methods`, flag the request for JSON-RPC verification.
   - In `EdgeGateProxy::handle_request_with_auth`, execute JSON-RPC inspection on the bounded request payload before any upstream socket checkout or secret injection:
     - Parse the collected payload bytes using `serde_json::from_slice::<serde_json::Value>`. If the payload is not valid RFC 8259 JSON, reject with `400 Bad Request` or `403 Forbidden` (`{"error":"malformed JSON-RPC payload"}`).
     - Support both single JSON-RPC 2.0 objects and batch arrays:
       - **Single Object:** Ensure `"jsonrpc": "2.0"` and extract `"method"`. Verify that `"method"` is a JSON string and exists within `allowed_jsonrpc_methods`.
       - **Batch Array:** If the top-level JSON is an array (`[...]`), iterate over every element, ensuring each item has `"jsonrpc": "2.0"` and an extracted `"method"` string present in `allowed_jsonrpc_methods`. If any element contains an unlisted method, a missing method, or invalid JSON-RPC structure, reject the entire batch fail-closed.
     - If any method fails authorization:
       - Fail closed with `403 Forbidden` (`{"error":"forbidden JSON-RPC method: <method>"}`).
       - Increment Prometheus counter `edgegate_jsonrpc_blocked_total` (`jsonrpc_blocked_total` in JSON metrics).
       - Record a flight-recorder entry (`reason = "jsonrpc_method_blocked"`) and append a `BLOCKED` entry to the SHA-256 hash-chained audit ledger (`INV-16`) with `upstream = "-"`.

4. **Protocol & Control-Plane Hardening ([src/pool.rs](src/pool.rs), [src/proxy.rs](src/proxy.rs), [src/main.rs](src/main.rs)):**
   - **Active HTTP/2 Health Probing:** Extend active background health checks (`spawn_active_health_probes`) to honor `backend.http2 = true`. For HTTP/2 backends, negotiate ALPN `h2` (or `h2c` prior knowledge) and issue HTTP/2 `GET` probes on multiplexed streams, ensuring that backend circuit breakers only remain `Closed` when HTTP/2 framing is verified end-to-end.
   - **HTTP/2 Response Trailer Scrubbing:** In `EdgeGateProxy::handle_request_with_auth`, apply `strip_response_headers` not only to initial response headers but also to HTTP/2 response trailers. When streaming chunked or framed responses, any trailer field matching `strip_response_headers` is filtered before delivery to the client.
   - **Hardened CLI Audit Subcommand (`edgegate audit`):**
     - Support `EDGEGATE_ADMIN_TOKEN` environment variable fallback if `--admin-token` is omitted.
     - Add `--ca-cert <PATH>` to load custom root certificates for verified HTTPS communication with the Admin Control Plane.
     - On receiving the audit ledger payload from `GET /_edgegate/admin/audit`, recompute the SHA-256 hash chain from the genesis entry through all records to the head hash client-side. If the computed hash chain diverges or `chain_valid` is false, exit with a non-zero error code and report tamper detection.

## Alternatives Considered
- **Global Rate Limiting vs. Dedicated Bulkhead Semaphores:** Token-bucket rate limiting (`rate_limit_rps`) bounds request initiation frequency but does not constrain request duration. If a workload issues 50 requests per second against an LLM inference endpoint with a 30-second latency, it can hold 1,500 active connections simultaneously, exhausting connection pools. Per-workload concurrency bulkheads enforce hard in-flight limits, guaranteeing that a single runaway sandbox cannot monopolize connection slots.
- **Client-Side Timeout vs. Route-Level Gateway Timeout Enforcement:** Relying on client timeouts leaves gateway and upstream connections open if the client hangs or disconnects improperly. Route-granular `timeout_ms` allows operators to assign tight, deterministic SLAs to fast microservices while permitting necessary leeway for long-running streaming routes.
- **Regex or Substring Method Matching vs. RFC 8259 `serde_json` Ast Parsing:** Using regex or substring matching to detect `"method": "tools/call"` is susceptible to parser differentials, whitespace variations, Unicode escapes, and JSON-RPC batch smuggling (hiding an unauthorized call inside a multi-item batch). Parsing with `serde_json` ensures exact syntactic alignment with the upstream JSON-RPC server.
- **Rejecting Whole Batch vs. Partial Execution for JSON-RPC:** Returning partial JSON-RPC error responses inside a 200 OK would require EdgeGate to simulate upstream JSON-RPC semantics and rewrite payloads on the fly. Failing closed at the HTTP gateway boundary with `403 Forbidden` preserves EdgeGate's role as a strict security choke point and signals policy violation clearly.

## Consequences & Failure Modes
- **Positive:**
  - Multi-tenant sandboxes cannot starve neighbor workloads of upstream connection resources, even during prolonged upstream degradations (`INV-20`).
  - Operators can tune request timeout SLAs per route and protect gateway memory from bloated upstream responses (`INV-21`).
  - MCP and JSON-RPC 2.0 endpoints are protected against tool-call smuggling and unauthorized method invocation (`INV-22`).
  - Active health checks accurately reflect HTTP/2 backend health, and response trailers cannot leak stripped headers.
  - Audit logs can be safely inspected and verified over verified HTTPS using the operator CLI.
- **Failure Modes & Mitigations:**
  - *Bulkhead Starvation under Burst Traffic:* If a workload legitimately needs high concurrency, setting `max_concurrent_requests` too low will cause premature `429 Too Many Requests`. Workload owners should configure concurrency quotas based on expected parallel task counts, and clients must respect the returned `Retry-After: 1` header.
  - *Large JSON-RPC Payloads:* Parsing very large JSON payloads with `serde_json` consumes CPU cycles. This is mitigated by existing request body size caps (`max_request_body_bytes` and per-rule `max_body_bytes`), bounding the maximum JSON parse tree in memory.
  - *Upstream Response Size Truncation:* When an upstream emits a response larger than `max_response_body_bytes`, EdgeGate terminates the stream with `502 Bad Gateway` and closes the connection. Upstream services returning large files or datasets should be mapped to dedicated routes with appropriately sized `max_response_body_bytes` or have pagination enabled.
