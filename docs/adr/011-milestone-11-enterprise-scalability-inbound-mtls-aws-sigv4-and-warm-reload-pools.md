# ADR-011: Milestone 11 — Enterprise Scalability: Inbound Mutual TLS (mTLS), AWS SigV4 Cloud Request Signing, Wait-Free ArcSwap Hot Paths & Warm Connection Pool Reuse
- **Status:** Accepted
- **Date:** 2026-11-26
- **Owner:** Justin Mafie

## Context

Following the General Availability release of EdgeGate (`v1.0.0`), deployment across enterprise multi-tenant agent execution clusters, high-concurrency cloud environments, and hybrid zero-trust service meshes revealed six major architectural requirements, interoperability needs, and scalability bottlenecks:

1. **Hot-Path Lock Contention, DNS Over-Resolution & Cold Reload Pools:**
   In `v1.0.0`, tenant secret lookups (`SecretProvider::get_secret`) and workload bulkhead permit lookups (`WorkloadAuthenticator`) relied on internal `std::sync::Mutex` locks around lookup tables. Under high concurrent workloads (thousands of requests/second across dozens of CPU cores), lock contention on these shared mutexes became a measurable bottleneck. Furthermore, `ConnectionPool` resolved and validated upstream IP addresses on every new socket dial without caching, incurring redundant DNS lookups and SSRF blocklist evaluations for high-churn short-lived backends. Crucially, when `ArcSwap<RuntimeSnapshot>` executed an atomic configuration hot reload, existing connection pools were dropped and rebuilt from scratch, forcing active keep-alive HTTP/1.1 connections and multiplexed HTTP/2 sessions to disconnect and suffer cold-start handshake latency.

2. **Inbound Mutual TLS (`mTLS`) Client Verification (`INV-24`, `[server.tls]`):**
   While Milestone 8 added outbound mTLS (`INV-18`) where EdgeGate presents client certificates to upstream backends, enterprise zero-trust architectures and hardware enclave sidecars mandate mutual TLS at the *inbound* listener. Unauthenticated network agents or spoofed internal workloads should not be permitted to establish a TLS handshake or transmit HTTP requests to EdgeGate unless they present an X.509 client certificate cryptographically signed by an approved enterprise root/intermediate Certificate Authority (`client_ca_cert_pem` or `client_ca_cert_path`). Operators also require CLI support (`--client-cert` and `--client-key`) to interact with mTLS-enforced gateway instances.

3. **Outbound AWS Signature Version 4 (`SigV4`) Cloud Request Signing (`INV-25`, `[routes.aws_sigv4]`):**
   Enterprise AI workloads routinely interact with cloud object stores (Amazon S3, Cloudflare R2, MinIO) and AI foundation model APIs (Amazon Bedrock) that require AWS Signature Version 4 (`AWS4-HMAC-SHA256`). Placing raw AWS IAM access keys or secret access keys inside sandbox environments violates the zero-secret invariant. Conversely, asking untrusted agent code to pre-sign requests allows callers to sign arbitrary verbs, headers, and paths. EdgeGate requires native outbound AWS SigV4 canonicalization and signing (`Authorization: AWS4-HMAC-SHA256 Credential=...`, `x-amz-date`, and `x-amz-content-sha256`) that validates secret TTLs fail-closed, strips caller-forged AWS headers, and strictly validates route configuration against header collisions at compile time.

4. **Multi-Tenant Observability Endpoint Protection & Trailer Credential-Reflection Scanning (`INV-12` Hardening):**
   In shared multi-tenant clusters, exposing detailed internal telemetry (`/_edgegate/metrics`) and ring-buffer flight-recorder data (`/_edgegate/replay`) to unauthenticated callers can facilitate reconnaissance by malicious tenants. Operators need an optional flag (`protect_observability = true`) that gates `/metrics` and `/replay` behind the constant-time `X-EdgeGate-Admin-Token` while keeping `/healthz` unauthenticated for container orchestrator (Kubernetes, Nomad) liveness/readiness probes. Additionally, the response credential reflection guard (`INV-12`) must be hardened to scan HTTP/2 response trailers for reflected secrets, closing a potential leak vector where backends echo secrets inside trailing frames.

5. **Embedded WCAG 2.1 AA+ Operator Control-Plane Web Console (`INV-26`, `GET /_edgegate/console`):**
   Enterprise operations and security response teams require real-time visibility into cluster generation, circuit-breaker states, active bulkheads, and the cryptographic SHA-256 audit ledger without relying on third-party SaaS dashboards, external node/npm dependencies, or unvetted frontends. To meet enterprise government and enterprise accessibility standards, EdgeGate requires an embedded, zero-dependency, self-contained web console at `GET /_edgegate/console` satisfying WCAG 2.1 AA+ guidelines, supporting keyboard-only navigation with skip-links, dynamic ARIA live regions, adaptive high-contrast dark/light design systems, and memory-only token handling that prevents credential leakage into browser persistence layers.

6. **Route-Level CORS Preflight & Browser/MCP Interoperability (`INV-27`, `[routes.cors]`) and W3C `tracestate`:**
   Browser-based AI workbenches, interactive inspector UIs, and Model Context Protocol (MCP) clients increasingly query EdgeGate from web origins. Without granular route-level CORS governance, browser clients are blocked by Same-Origin Policy or forced into insecure global wildcard configurations. EdgeGate requires declarative route-level CORS policy evaluation that short-circuits `OPTIONS` preflight requests with `204 No Content` without upstream checkout or secret leakage, and enforces W3C `tracestate` Level 1 validation alongside `traceparent` for end-to-end distributed tracing.

---

## Decision

### 1. Wait-Free Hot-Path Concurrency & Connection Pool Warm Reuse ([../../src/secrets.rs](../../src/secrets.rs), [../../src/auth.rs](../../src/auth.rs), [../../src/pool.rs](../../src/pool.rs), [../../src/proxy.rs](../../src/proxy.rs))
- **Wait-Free Secret & Bulkhead Lookups:**
  Migrate internal lookup tables in `SecretProvider` and `WorkloadAuthenticator` to `ArcSwap<Arc<HashMap<...>>>` (or lock-free map structures). Hot-path reads (`get_secret`, workload bulkhead lookups) load an immutable reference without acquiring a `std::sync::Mutex` or `RwLock`. Updates (secret rotation, config hot reload) construct a new map off the hot path and swap the pointer atomically via `ArcSwap::store`.
- **Bounded SSRF-Validated DNS Cache (`dns_cache_ttl_ms`):**
  Introduce `dns_cache_ttl_ms: u64` on `[[pools]]` (default `10000` ms). When configured, EdgeGate caches the resolved and SSRF-validated `Vec<SocketAddr>` for each upstream `(host, port)` up to the pool's configured TTL. Subsequent dials within the TTL use the pre-validated addresses without re-invoking DNS lookups, while still validating IP blocklists upon cache insertion to preserve anti-SSRF invariants (`INV-07`).
- **Warm Connection Pool Reuse Across Hot Reloads:**
  When `RuntimeSnapshot` compiles a new configuration during hot reload, `ConnectionPool` matches surviving `(pool_name, backend_id)` slots with unchanged network parameters (`address`, `tls`, `http2`, `mtls`). Surviving `UpstreamSlot` instances retain their active HTTP/2 multiplexed connections and idle HTTP/1.1 pools, eliminating cold-start reconnections and TLS handshakes during dynamic policy and route updates.

### 2. Inbound Mutual TLS (`mTLS`) Client Verification (`INV-24`, [../../src/config.rs](../../src/config.rs), [../../src/proxy.rs](../../src/proxy.rs), [../../src/main.rs](../../src/main.rs))
- **Configuration Schema:**
  Extend `[server.tls]` with optional client CA certificate settings:
  ```toml
  [server.tls]
  cert_path = "/etc/edgegate/tls/server.crt"
  key_path = "/etc/edgegate/tls/server.key"
  client_ca_cert_path = "/etc/edgegate/tls/client_ca.crt" # or inline client_ca_cert_pem
  ```
- **Handshake Verification Engine:**
  When `client_ca_cert_pem` or `client_ca_cert_path` is configured, EdgeGate compiles a `rustls::server::WebPkiClientVerifier` using the provided CA certificates and configures `rustls::ServerConfig::builder().with_client_cert_verifier(...)`.
  - The inbound TLS listener mandates a valid X.509 client certificate during the TLS 1.2/1.3 handshake.
  - Clients presenting missing, untrusted, or expired certificates are terminated at the TLS layer with an alert before any HTTP framing bytes are accepted.
- **Operator CLI Support:**
  Extend the `edgegate` CLI (`status`, `replay`, `audit`) with `--client-cert <PATH>` and `--client-key <PATH>` flags to enable operators to authenticate against mTLS-protected gateways.

### 3. Outbound AWS Signature Version 4 (`SigV4`) Cloud Request Signing (`INV-25`, [../../src/config.rs](../../src/config.rs), [../../src/router.rs](../../src/router.rs), [../../src/proxy.rs](../../src/proxy.rs))
- **Configuration Schema:**
  Add optional `[routes.aws_sigv4]` as its own clean route definition (or note it replaces `[routes.credential]` and `[routes.request_signing]` on `Authorization`):
  ```toml
  [[routes]]
  id = "s3-route"
  path_prefix = "/v1/s3"
  pool = "s3-pool"

  [routes.aws_sigv4]
  access_key_ref = "aws_access_key_id"      # Org-scoped secret in [[secrets]]
  secret_key_ref = "aws_secret_access_key"  # Org-scoped secret in [[secrets]]
  region = "us-east-1"
  service = "s3"                            # e.g., "s3", "bedrock", "dynamodb"
  ```
- **Compile-Time Header Collision Validation:**
  At configuration compile time, EdgeGate validates that a route cannot simultaneously declare `[routes.credential]`, `[routes.request_signing]`, and `[routes.aws_sigv4]`, as these mechanisms collide on outbound authorization and signature headers.
- **Forged Header Stripping:**
  In `sanitize_outbound_headers` ([../../src/router.rs](../../src/router.rs)), unconditionally strip any incoming caller-provided `Authorization`, `x-amz-date`, `x-amz-content-sha256`, and all `x-amz-*` headers to prevent caller-forged AWS signature manipulation.
- **Canonical AWS SigV4 Request Construction:**
  1. Retrieve `access_key_id` and `secret_access_key` from `SecretProvider` scoped to `identity.org_id`. Verify TTL deadlines (`INV-14`); fail closed with `403 Forbidden` if missing or expired.
  2. Compute SHA-256 payload digest `x-amz-content-sha256 = hex(SHA256(raw_body))`.
  3. Format current UTC timestamp as ISO 8601 basic format (`YYYYMMDD'T'HHMMSS'Z'`) for `x-amz-date` and date stamp (`YYYYMMDD`).
  4. Build Canonical Request according to AWS SigV4 specification: HTTP method, canonical URI, canonical query string, canonical headers (lowercased, sorted, trimmed), signed headers list, and payload hash.
  5. Compute String-to-Sign: `"AWS4-HMAC-SHA256\n" + timestamp + "\n" + date/region/service/aws4_request + "\n" + hex(SHA256(canonical_request))`.
  6. Derive signing key: `kDate = HMAC("AWS4" + secret, date)`, `kRegion = HMAC(kDate, region)`, `kService = HMAC(kRegion, service)`, `kSigning = HMAC(kService, "aws4_request")`.
  7. Compute final signature: `signature = hex(HMAC(kSigning, string_to_sign))`.
  8. Inject `Authorization: AWS4-HMAC-SHA256 Credential=<access_key>/<date>/<region>/<service>/aws4_request, SignedHeaders=..., Signature=<signature>`, `x-amz-date`, and `x-amz-content-sha256`.
- **Telemetry:**
  Increment atomic counter `aws_sigv4_signed_requests_total` (`edgegate_aws_sigv4_signed_requests_total`).

### 4. Optional Observability Endpoint Protection & Trailer Credential-Reflection Scanning (`INV-12` Hardening, [../../src/proxy.rs](../../src/proxy.rs), [../../src/config.rs](../../src/config.rs))
- **`protect_observability` Flag:**
  Add optional `protect_observability: bool` to `[server]` (default `false`).
  - When `true`, requests to `GET /_edgegate/metrics` and `GET /_edgegate/replay` require constant-time `X-EdgeGate-Admin-Token` authentication (matching `server.admin_token` or `server.admin_token_sha256`), failing closed with `401 Unauthorized` / `403 Forbidden` if absent or invalid.
  - `GET /_edgegate/healthz` remains unauthenticated to ensure platform orchestrators (Kubernetes kubelet, Nomad, Consul) can perform liveness and readiness checks without exposing administrative credentials in probe manifests.
- **HTTP/2 Trailer Secret-Reflection Scanning (`INV-12` Hardening):**
  When `block_secret_reflection = true` is configured, EdgeGate extends inspection beyond response headers and body frames to include HTTP/2 trailing headers (`BufferedBodyWithTrailers`). If the raw injected secret bytes appear inside any trailing header name or value, EdgeGate drops the trailer, aborts the response, increments `secret_reflections_blocked_total`, and fails closed with `502 Bad Gateway`.

### 5. Embedded WCAG 2.1 AA+ Operator Control-Plane Web Console (`INV-26`, [../../src/console.rs](../../src/console.rs), [../../src/proxy.rs](../../src/proxy.rs))
- **Single-Binary Zero-Dependency Console (`GET /_edgegate/console`):**
  EdgeGate compiles a standalone, zero-dependency HTML/CSS/JS control-plane console directly into `src/console.rs`. Operators navigate to `/_edgegate/console` in any modern browser to inspect cluster generation, live circuit-breaker topology, health status, and stream the cryptographic SHA-256 audit ledger.
- **Strict WCAG 2.1 AA+ Accessibility:**
  - High-contrast color palette adhering to >= 7:1 contrast ratios for light and dark themes.
  - Automatically respects user OS preferences via `@media (prefers-color-scheme: dark)` and `@media (prefers-reduced-motion: reduce)`.
  - Full keyboard accessibility with an accessible `Skip to main content` anchor, prominent `:focus-visible` styling, semantic landmark tags (`banner`, `main`, `region`, `status`), and dynamic `aria-live="polite"` telemetry announcements.
- **Defense-in-Depth Security:**
  - Strict `Content-Security-Policy`: `default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.
  - Operator credentials (`X-EdgeGate-Admin-Token`) are managed exclusively in volatile JavaScript runtime closure memory and are never written to `localStorage`, `sessionStorage`, or cookies.

### 6. Route-Level CORS Preflight & Browser/MCP Interoperability (`INV-27`, [../../src/config.rs](../../src/config.rs), [../../src/router.rs](../../src/router.rs), [../../src/proxy.rs](../../src/proxy.rs))
- **Declarative Route-Level Configuration (`[routes.cors]`):**
  Enables granular CORS policies per route with `allowed_origins`, `allowed_methods`, `allowed_headers`, `expose_headers`, and `max_age_secs`.
- **Compile-Time Origin Validation:**
  Validation strictly forbids empty origins or wildcard origin `allowed_origins = ["*"]`, preventing browser data and credential exposure vulnerabilities.
- **Zero-Secret Preflight Short-Circuiting:**
  `OPTIONS` requests matching a CORS-enabled route are intercepted at the routing layer before authentication, policy evaluation, or backend checkout. Requests from authorized origins immediately return `204 No Content` with appropriate `Access-Control-Allow-*` and `Vary: Origin` headers, preventing unauthorized credential injection or upstream socket allocation.

### 7. W3C `tracestate` Distributed Tracing Interoperability ([../../src/router.rs](../../src/router.rs))
- **W3C Trace Context Level 1 Validation:**
  In `sanitize_outbound_headers`, incoming `tracestate` headers are validated against W3C specification limits: printable ASCII characters only (0x20..0x7E), maximum length `<= 512` bytes, and maximum list member count `<= 32` key=value pairs.
- **Transparent Propagation:**
  Valid `tracestate` headers are forwarded alongside `traceparent` to primary and shadow upstreams, maintaining end-to-end tracing context across OpenTelemetry, Datadog, Jaeger, and AWS X-Ray collectors.

### 8. Measured Systems Benchmark Results (Loopback HTTP/1.1 Keep-Alive Verification)
Reproducible localhost HTTP/1.1 keep-alive benchmark ([../../examples/bench.rs](../../examples/bench.rs)) executed via `cargo run --release --example bench` (32 concurrent workers × 500 requests = 16,000 requests against in-process mock upstreams on Apple Silicon loopback):
- **Direct Upstream Baseline:** `174,084.6 req/s` | `p50 = 183 µs` | `p95 = 247 µs` | `p99 = 307 µs`
- **Via EdgeGate (`v1.1.0` Full Auth + RBAC + SSRF + Pool + Secret Injection):** **`64,854.4 req/s`** (**`2.36x` / `+136.2%` throughput gain** vs `v1.0.0`'s `27,458.3 req/s`) | `p50 = 474 µs` | `p95 = 692 µs` | `p99 = 836 µs`
- **Added EdgeGate Overhead:** `p50 = +291 µs (0.29 ms)` | **`p95 = +445 µs (0.445 ms, -50.9% reduction)`** | `p99 = +529 µs (0.53 ms)`

The `2.36x` throughput gain and `-50.9%` reduction in p95 latency overhead directly validate the architectural choices: resolving `PooledBody` HTTP/1.1 keep-alive EOF socket return, replacing mutex synchronizations with lock-free `ArcSwap` pointers, and caching SSRF-validated DNS lookups.

---

## Alternatives Considered

1. **`RwLock` vs. `ArcSwap` for Secret and Bulkhead Lookups:**
   `RwLock` provides read-write semantics but still requires cache-line invalidation and atomic counter increments for reader tracking across cores. Under saturated multi-core load, reader lock contention degrades throughput. `ArcSwap` provides wait-free, pointer-swapping reads with zero lock overhead on the hot path.
2. **Upstream SigV4 Pre-Signing by Agent Workloads:**
   Allowing workloads to pre-sign requests requires injecting IAM credentials into the sandbox or exposing a pre-signing oracle. In both cases, a compromised agent can pre-sign destructive actions (e.g., `s3:DeleteBucket`). Centralizing SigV4 signing inside EdgeGate enforces policy evaluation (`[[policies]]`) and secret isolation (`INV-05`) before any AWS signature is generated.
3. **Inbound mTLS Client Certificate Identity Mapping vs. Dedicated CA Validation:**
   Extracting Common Name (CN) or SAN from the client certificate to automatically map workload identity was considered. However, enterprise environments frequently terminate TLS via sidecars or gateways where client certificates authenticate host-level identities while application-level workload identity is managed via tokens or UDS. Maintaining orthogonal inbound mTLS transport verification (`INV-24`) and workload authentication (`INV-02`/`INV-03`) provides maximum flexibility without coupling certificate fields to tenant schemas.
4. **External React/Vue Dashboard vs. Embedded Zero-Dependency Console (`INV-26`):**
   Requiring an external frontend SPA or npm packaging pipeline adds deployment complexity, security attack surface (node dependency supply-chain risks), and container image bloat. Embedding the console directly in the Rust binary produces a single, self-contained binary with zero runtime dependencies.

---

## Consequences & Failure Modes

### Positive Consequences
- Data-plane request throughput increases by `2.36x` (`+136.2%` to `64,854.4 req/s`) with p95 latency overhead reduced by `-50.9%` to `+445 µs`.
- Upstream connection pools remain warm across hot reloads, avoiding latency spikes during routine configuration updates.
- Workloads can securely access Amazon S3, Bedrock, and DynamoDB endpoints without holding AWS credentials (`INV-25`).
- Hardware and sidecar mutual TLS client certificate verification secures the inbound boundary against unauthorized network participants (`INV-24`).
- Multi-tenant clusters can restrict metrics and replay inspection without breaking orchestrator health probes.
- Upstream HTTP/2 trailer reflection attempts are intercepted fail-closed (`INV-12`).
- Operators gain an accessible WCAG 2.1 AA+ control-plane console (`INV-26`) with zero external dependencies.
- Browser-based agent workbenches and MCP frontends safely interact with routes via granular CORS policies (`INV-27`).
- Distributed tracing context is preserved across systems via W3C `tracestate` Level 1 interoperability.

### Failure Modes & Mitigations
- **SigV4 Clock Skew:**
  AWS SigV4 enforces a strict ±15 minute timestamp window. Significant gateway host clock drift will result in `403 RequestTimeTooSkewed` from AWS. *Mitigation:* Ensure host systems run synchronized NTP/Chrony daemons.
- **Expired Client CA Certificates:**
  If the configured `client_ca_cert_path` expires or client certificates expire, inbound handshakes will fail at the TLS layer. *Mitigation:* Monitor certificate expiration and rotate CA bundles live via atomic hot reload.
- **DNS Cache Stale Addresses:**
  If `dns_cache_ttl_ms` on `[[pools]]` is configured with an excessively long TTL, dynamic upstream IP failover may take up to the TTL duration to discover new endpoints. *Mitigation:* Operators should choose moderate TTLs (e.g., default 10,000 ms / 10 seconds, or 30–60 seconds) matching upstream DNS records.
