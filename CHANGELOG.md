# Changelog

All notable changes to EdgeGate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-26

EdgeGate `v1.0.0` marks General Availability (GA) as a production-grade, panic-free Layer 7 zero-secret reverse proxy and AI workload gateway. This release completes the GA hardening milestone with cryptographic outbound request signing, end-to-end stream-lifetime concurrency bulkheads, graceful draining guards, trailer-preserving response caps, and strict JSON-RPC 2.0 conformance.

### Added
- **Outbound Cryptographic Request Signing (`INV-23`, `[routes.request_signing]`):**
  - Pure-Rust RFC 2104 HMAC-SHA256 request signing over incoming request payloads.
  - Automatically generates and attaches `X-EdgeGate-Timestamp: <unix_seconds>` and `X-EdgeGate-Signature-256: sha256=<hex_digest>` computed over `<unix_seconds>.<raw_body>`.
  - Backed by organization-scoped `SecretProvider` with live TTL rotation and expiry validation.
  - Fail-closed stripping of any untrusted or forged caller-supplied `X-EdgeGate-*` timestamp/signature headers prior to signing.
  - Added telemetry counters `signed_requests_total` and Prometheus `edgegate_signed_requests_total`.
- **Stream-Lifetime Workload Bulkhead & Graceful Drain Guards (`INV-20` Hardening):**
  - Atomic CAS per-workload active concurrency counters (`Arc<AtomicUsize>`) preserved across live `ArcSwap` hot reloads.
  - RAII `GuardedResponseBody` holding both `WorkloadBulkheadGuard` and `InFlightGuard` until streaming response EOF or stream drop, guaranteeing Server-Sent Events (SSE), gRPC streams, and chunked HTTP/2 transfers cannot escape concurrency limits or shutdown drain cycles.
- **Strict JSON-RPC 2.0 Envelope & Empty-Allowlist Enforcement (`INV-22` Hardening):**
  - Deep validation verifying `"jsonrpc": "2.0"` envelope compliance.
  - Explicit fail-closed rejection (`403 Forbidden`) when `allowed_jsonrpc_methods` is declared as an empty list (`[]`).
  - RFC 8259-compliant validation across both single object calls and JSON-RPC batch arrays.
- **Circuit-Breaker Isolation for Response Cap Overflow (`INV-21` Hardening):**
  - Immediate upstream connection abort on `max_response_body_bytes` overflow while scrubbing trailing HTTP/2 headers.
  - Upstream backend connection ejection without triggering erroneous circuit breaker failure penalties against healthy upstream endpoints.
- **CLI Cleartext Remote HTTP Admin-Token Protection:**
  - `edgegate audit` proactively rejects transmitting admin tokens over non-loopback cleartext HTTP URLs unless explicit HTTPS or loopback (`127.0.0.1` / `::1`) is targeted.
- **Open-Source Repository Infrastructure & Community Governance:**
  - Added structured GitHub Issue Forms (`bug_report.yml`, `feature_request.yml`, `config.yml`).
  - Added standardized Pull Request template (`PULL_REQUEST_TEMPLATE.md`) enforcing zero `.unwrap()`/`.expect()`, poisoned lock recovery, and ADR compliance.
  - Added visual security verification console asset (`docs/assets/edgegate-console.svg`).

### Changed
- Promoted all remaining experimental API interfaces and configuration schemas to stable `v1.0.0` GA status.
- Standardized error mapping for bulkhead and rate limit rejections with standard `Retry-After: 1` headers.

---

## [0.9.0] - 2026-11-26

### Added
- **Per-Workload Concurrency Quotas & Bulkhead Isolation (`INV-20`, `max_concurrent_requests`):**
  - Concurrency partition semaphores per `(org_id, workload_id)` across TCP workloads and Unix Domain Socket listeners.
  - Immediate `429 Too Many Requests` with `{"error":"workload concurrency limit exceeded"}` and `Retry-After: 1` upon bulkhead exhaustion.
  - Prometheus counter `edgegate_bulkhead_rejected_total`.
- **Per-Route Timeout Overrides & Response Body Size Caps (`INV-21`):**
  - Configurable `timeout_ms` route overrides overriding global `server.response_timeout_ms`.
  - Configurable `max_response_body_bytes` on streaming responses; fails closed with `502 Bad Gateway` (`{"error":"upstream response exceeded maximum allowed body size"}`).
- **JSON-RPC 2.0 / MCP Tool-Call Method Allowlists (`INV-22`, `allowed_jsonrpc_methods`):**
  - Syntactic inspection of Model Context Protocol (MCP) and JSON-RPC 2.0 payloads on single requests and batch arrays before upstream checkout.
  - Enforces `403 Forbidden` (`{"error":"unauthorized JSON-RPC method: <name>"}`) on unapproved methods.
- **Active HTTP/2 mTLS Health Probes:** Proactive multiplexed `h2` ping and GET probes for HTTP/2 backends.
- **HTTP/2 Trailer Scrubbing:** Hardened response pipeline scrubbing forbidden or sensitive header names emitted in HTTP/2 trailing frames.
- **Hardened Operator CLI (`edgegate audit`):** Added verified HTTPS via `--ca-cert` and automated secret injection via `EDGEGATE_ADMIN_TOKEN`.

---

## [0.8.0] - 2026-11-26

### Added
- **Outbound Mutual TLS (`INV-18`, `[upstreams.mtls]`):**
  - Client certificate and private key presentation for zero-trust upstream backends.
  - Configurable CA bundles (`ca_cert_path`) and per-upstream client cert validation.
- **Egress Data Loss Prevention Payload Guard (`INV-19`, `[routes.dlp]`):**
  - Deep inspection of outgoing request bodies against configurable regex patterns (e.g., API keys, credit cards, bearer tokens).
  - Blocked attempts fail closed with `403 Forbidden` (`{"error":"egress DLP violation: payload pattern matched"}`).
- **Programmable Response Header Hardening (`strip_response_headers`, `set_response_headers`):**
  - Strips server fingerprinting headers (`Server`, `X-Powered-By`) and injects defensive headers (`X-Content-Type-Options`, `Content-Security-Policy`).
- **Admin Pool Topology Introspection (`GET /_edgegate/admin/pools`):**
  - Real-time visibility into active connection pools, idle connections, and circuit breaker states.
- **Operator Audit CLI (`edgegate audit`):**
  - Standalone verification command to retrieve and cryptographically validate the SHA-256 audit ledger.

---

## [0.7.0] - 2026-11-26

### Added
- **Authenticated Admin Control Plane API (`/_edgegate/admin/*`):**
  - Bearer token authentication via `X-EdgeGate-Admin-Token` or `Authorization: Bearer <token>`.
  - Dedicated endpoints for configuration state, health inspection, and audit ledger access.
- **Cryptographic SHA-256 Hash-Chained Audit Ledger (`INV-16`):**
  - Tamper-evident ledger linking every gateway decision to previous record's SHA-256 digest (`genesis` -> record N).
  - Telemetry validation endpoint and verification functions.
- **Weighted Canary Load Balancing (`canary_weight`, `canary_upstream`):**
  - Deterministic traffic splitting between baseline and canary upstream instances.
- **Query Parameter & Request Body Guards (`INV-17`):**
  - `forbidden_query_params` policy matching to block illicit query strings.
  - `max_body_bytes` payload enforcement rejecting oversized requests with `413 Payload Too Large`.
- **Prometheus Latency Histograms:** Added high-resolution duration histograms for routing, proxy forwarding, and policy evaluation.

---

## [0.6.0] - 2026-11-25

### Added
- **Scoped Credential Live Rotation & TTL Expiry (`INV-14`):**
  - Background reloading of upstream credentials without process restarts.
  - Automatic expiration and eviction of credentials past their configured TTL.
- **Request-Attribute Policy Rules (`INV-15`, `required_headers`):**
  - Granular policy enforcement matching exact or regex-based HTTP request headers.
- **Dual Workload Token Rollover:**
  - Zero-downtime client credential rotation supporting active and next token pairs.
- **CLI Commands (`edgegate status`, `edgegate replay`):**
  - Interactive status inspection and ring-buffer flight-recorder replay tool.
- **Security Console Verification Demo (`examples/security_console_demo.rs`):**
  - Automated scenario suite demonstrating zero-secret injection, tenant isolation, egress DLP, and reflection defense.

---

## [0.5.0] - 2026-11-25

### Added
- **Inbound TLS 1.2 and 1.3 Termination:**
  - Pure-Rust `rustls` engine terminating TLS connections with modern cipher suites.
  - ALPN negotiation supporting `h2` and `http/1.1`.
- **Credential Reflection Guard (`INV-12`):**
  - Scans upstream response bodies and headers to detect and intercept reflected secrets, returning `502 Bad Gateway`.
- **Controlled Idempotent Failover Retries (`INV-13`):**
  - Safe, bounded retries on idempotent HTTP methods (`GET`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`) across healthy pool members.
- **Graceful Shutdown & Draining:**
  - Signal-aware drain cycles allowing in-flight requests to complete before socket closure.
- **Continuous Integration Workflows:**
  - Comprehensive GitHub Actions CI matrix running formatting, clippy, unit, integration, and adversarial security suites.

---

## [0.4.0] - 2026-11-25

### Added
- **Token-Bucket Rate Limiting:**
  - Per-policy rate limiting with configurable requests-per-second (`rate_limit_rps`) and burst limits (`rate_limit_burst`).
- **W3C Distributed Tracing (`traceparent`):**
  - Seamless propagation and generation of W3C `traceparent` headers across ingress and egress boundaries.
- **Prometheus Metrics Exporter (`/_edgegate/metrics`):**
  - Real-time Prometheus metrics exposition for request counts, error rates, and latency.
- **Dual-Stack IPv4 / IPv6 SSRF Resolution:**
  - Complete DNS resolution scrubbing preventing DNS rebinding and loopback escape across IPv4 and IPv6 networks.

---

## [0.3.0] - 2026-11-24

### Added
- **HTTP/2 Support:** Inbound and outbound HTTP/2 multiplexing with pure-Rust connection management.
- **Three-State Circuit Breakers (`Closed`, `Open`, `Half-Open`):**
  - Consecutive error thresholds and cool-off intervals to isolate unhealthy upstream backends.
- **Advanced Load Balancing Strategies:**
  - `ConsistentHash` routing by tenant, header, or IP.
  - `LatencyAware` exponentially weighted moving average (EWMA) load distribution.
- **Asynchronous Traffic Shadowing:** Non-blocking fire-and-forget request mirroring to candidate backends.
- **Flight-Recorder Replay Ring Buffer:** In-memory circular buffer capturing recent failed and blocked requests for debugging.
- **Boxlet UDS Direct Attachment:** Zero-overhead Unix Domain Socket listener support for container sandboxes.

---

## [0.2.0] - 2026-11-24

### Added
- **Outbound TLS:** Secure HTTPS upstream proxying with SNI verification and custom root CA support.
- **Live Configuration Hot Reload (`ArcSwap`):**
  - Dynamic configuration reloading via SIGHUP and file-watch polling without dropping connections.
- **Static Zero-Token Unix Domain Socket Listeners:**
  - Dedicated UDS endpoints with kernel-level identity verification for local sandbox agents.
- **Role-Based Access Control (RBAC):** Policy rules enforcing specific workload roles (`required_roles`).
- **Active Health Probes:** Periodic background HTTP/1.1 health checking with automatic pool membership management.

---

## [0.1.0] - 2026-11-24

### Added
- **Initial Core L7 Reverse Proxy Architecture:**
  - High-performance asynchronous HTTP/1.1 reverse proxy built on Tokio and Hyper.
- **Cryptographic Workload Authentication:**
  - Constant-time SHA-256 token verification mapping incoming workloads to organization contexts.
- **Default-Deny Multi-Tenant Policy Engine:**
  - Strict default-deny evaluation matching method, path prefix, and tenant boundaries.
- **Zero-Secret Workload Boundary (`ZeroizeOnDrop`):**
  - Secure credential injection storing sensitive secrets in guarded memory zeroized on drop.
- **Persistent HTTP/1.1 Connection Pool:**
  - Bounded connection pooling with idle timeouts and connection limits per backend.
- **IPv4 / IPv6 Anti-SSRF Defense:**
  - Immediate blocking of loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and multicast address ranges.
