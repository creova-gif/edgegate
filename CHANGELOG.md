# Changelog

All notable changes to EdgeGate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-11-26

EdgeGate `v1.1.0` introduces enterprise scalability, inbound mutual TLS (mTLS), native AWS Signature Version 4 (SigV4) cloud request signing, wait-free hot-path concurrency, warm connection pool reuse across hot reloads, and multi-platform release distribution.

### Added
- **Embedded WCAG 2.1 AA+ Operator Control-Plane Web Console (`INV-26`, `GET /_edgegate/console`, `src/console.rs`):**
  - Serves an embedded, zero-dependency, self-contained operator control-plane console compiled directly into the binary.
  - Adaptive design system supporting `prefers-color-scheme` (dark/light) with >= 7:1 contrast ratios and `prefers-reduced-motion`.
  - Accessible keyboard navigation featuring top skip-links, WAI-ARIA landmark roles (`banner`, `main`, `region`, `status`), and `aria-live="polite"` real-time telemetry announcements.
  - Hardened with strict `Content-Security-Policy` (`default-src 'none'`, `frame-ancestors 'none'`) and ephemeral in-memory admin token handling with zero persistence in `localStorage`, cookies, or browser history.
- **Route-Level CORS Preflight & Browser/MCP Interoperability (`INV-27`, `[routes.cors]`):**
  - Declarative route-level CORS policies (`allow_origins`, `allow_methods`, `allow_headers`, `expose_headers`, `allow_credentials`, `max_age_s`).
  - Strict origin validation forbidding wildcard `*` origins when credentials are enabled.
  - Zero-secret `OPTIONS` preflight short-circuiting returning `204 No Content` with `Vary: Origin` before upstream connection checkout or secret injection.
- **W3C `tracestate` Distributed Tracing Interoperability (`src/router.rs`):**
  - Full W3C Trace Context Level 1 validation ensuring `tracestate` contains only printable ASCII, `<= 512` bytes, and `<= 32` `key=value` list members.
  - Upstream and shadow propagation alongside `traceparent` for OpenTelemetry, Datadog, Jaeger, and AWS X-Ray context tracing.
- **Inbound Mutual TLS (`mTLS`) Client Verification (`INV-24`, `[server.tls]`):**
  - Added `client_ca_cert_pem` and `client_ca_cert_path` to `[server.tls]` configuration.
  - Enforces hardware/sidecar X.509 client certificate validation at the inbound TLS listener via `rustls::server::WebPkiClientVerifier`.
  - Added `--client-cert` and `--client-key` CLI options to `edgegate status`, `edgegate replay`, and `edgegate audit` to authenticate against mTLS-protected gateways.
- **Outbound AWS Signature Version 4 (`SigV4`) Cloud Request Signing (`INV-25`, `[routes.aws_sigv4]`):**
  - Native zero-secret canonical AWS SigV4 request signing (`AWS4-HMAC-SHA256`, `x-amz-date`, `x-amz-content-sha256`) for Amazon S3, Amazon Bedrock, DynamoDB, Cloudflare R2, and MinIO backends.
  - Organization-scoped secret resolution for AWS access keys and secret keys with fail-closed TTL enforcement (`INV-14`).
  - Automatic stripping of caller-forged `Authorization` and `x-amz-*` headers prior to signing.
  - Compile-time validation preventing conflicting `credential`, `request_signing`, and `aws_sigv4` definitions on the same route.
  - Added telemetry counter `aws_sigv4_signed_requests_total` (`edgegate_aws_sigv4_signed_requests_total`).
- **Wait-Free Hot-Path Concurrency & Warm Pool Reuse across Live Hot Reloads:**
  - Migrated `SecretProvider::get_secret` and workload bulkhead lookups to lock-free `ArcSwap` pointers, eliminating `Mutex` lock contention under heavy multi-core load.
  - Added configurable `dns_cache_ttl_ms` on `[server]` for bounded caching of SSRF-validated upstream socket addresses.
  - Enabled warm `UpstreamSlot` connection pool reuse across atomic `ArcSwap` configuration reloads, preserving active HTTP/2 multiplexed connections and idle HTTP/1.1 pools.
- **Optional Observability Endpoint Authentication (`protect_observability`):**
  - Added `protect_observability = true` on `[server]` to restrict `GET /_edgegate/metrics` and `GET /_edgegate/replay` behind constant-time `X-EdgeGate-Admin-Token` authentication in multi-tenant environments.
  - `GET /_edgegate/healthz` remains unauthenticated for orchestrator (Kubernetes, Nomad) liveness/readiness probes.
- **HTTP/2 Response Trailer Credential-Reflection Scanning (`INV-12` Hardening):**
  - Hardened `block_secret_reflection = true` to scan HTTP/2 response trailers (`BufferedBodyWithTrailers`) for reflected credentials, dropping trailers and failing closed with `502 Bad Gateway` if matched.
- **Multi-Platform Release CI & Packaging Matrix:**
  - Upgraded `.github/workflows/release.yml` with a 2-target build matrix (`x86_64-unknown-linux-gnu` on `ubuntu-latest` and `aarch64-apple-darwin` on `macos-14`).
  - Added automated publication of unified `SHA256SUMS` covering Linux and macOS release archives.

### Performance
- **Measured 2.36x Throughput Gain & -50.9% p95 Latency Reduction:**
  - Upstream keep-alive benchmarking via `cargo run --release --example bench` (32 concurrent workers × 500 requests = 16,000 requests on Apple Silicon loopback) demonstrated:
    - Gateway throughput increased from `27,458.3 req/s` (`v1.0.0`) to **`64,854.4 req/s`** (**`2.36x` / `+136.2%` gain**).
    - Gateway `p95` latency dropped from `1,300 µs` to **`692 µs`** (**`-50.9%` reduction**).
    - Added EdgeGate `p95` overhead reduced from `+906 µs` down to **`+445 µs`** (`0.445 ms`).
  - Achieved by resolving `PooledBody` HTTP/1.1 keep-alive EOF return conditions, eliminating hot-path `Mutex` contention via wait-free `ArcSwap` pointers, and deploying SSRF-validated DNS caching.

### Changed
- Standardized minimum supported Rust toolchain prerequisite to Rust 1.85+ across documentation, Dockerfiles, and CI configurations.

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
