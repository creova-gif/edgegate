# ADR-008: Milestone 8 — Outbound Mutual TLS (mTLS) Client Authentication, Egress Data Loss Prevention (DLP) Payload Guard, Programmable Response Header Hardening, and Admin Pool & Circuit-Breaker Topology Introspection
- **Status:** Accepted
- **Date:** 2026-11-26
- **Owner:** Justin Mafie

## Context
Following Milestone 7 (`v0.7.0`, authenticated Admin Control Plane API, SHA-256 hash-chained tamper-evident audit ledger, weighted canary load balancing, per-rule query-parameter/payload guards, and lock-free Prometheus microsecond histograms), zero-trust production deployments of EdgeGate (`v0.8.0`) requires four additional outbound identity, egress data-exfiltration defense, response surface hardening, and live topology introspection capabilities:

1. **Outbound Mutual TLS (mTLS) Client Authentication (`INV-18`, `client_cert_pem`, `client_key_pem` on `[[pools]]`):**
   Enterprise internal services, financial APIs, and service-mesh upstreams frequently require Mutual TLS (mTLS) client certificate authentication in addition to—or instead of—HTTP bearer tokens. Giving untrusted AI agents or ephemeral sandboxes access to private X.509 client keys would violate EdgeGate's zero-secret execution model. EdgeGate must terminate outbound mTLS on behalf of authorized workloads by presenting a pool-scoped X.509 client certificate chain and private key during upstream TLS 1.2/1.3 handshakes without ever exposing private key material to the sandbox.

2. **Egress Data Loss Prevention (DLP) Request Payload Guard (`INV-19`, `blocked_body_substrings` on `[[policies]]`):**
   Even when an AI agent or sandbox is authorized to call an external API (e.g., posting an issue comment, sending a webhook, or invoking an LLM prompt endpoint), prompt injection or compromised agent code may attempt to exfiltrate sensitive host or tenant markers (such as PEM private key headers `-----BEGIN PRIVATE KEY-----`, internal token prefixes `AKIA`, `ghp_`, or confidential dataset watermarks) inside the outbound HTTP request body. EdgeGate needs a synchronous, fail-closed L7 Egress DLP payload guard that inspects bounded outbound request bodies against per-rule `blocked_body_substrings` before any upstream socket is dialed or secret is transmitted.

3. **Programmable Response Header Stripping & Security Header Injection (`strip_response_headers`, `inject_response_headers` on `[[routes]]`):**
   Upstream backends frequently emit verbose server fingerprinting headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, internal debug headers) or omit defense-in-depth security and caching headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`). Operators need deterministic, route-level response header scrubbing and security header injection executed at the gateway boundary.

4. **Admin Pool & Circuit-Breaker Topology Introspection (`GET /_edgegate/admin/pools`) & CLI `edgegate audit`:**
   While `/_edgegate/metrics` exports aggregate gateway counters and histograms, operators and automated control planes need live, authenticated visibility into per-pool load-balancing strategy, mTLS status, per-backend canary weights, active health probe status, active connection counts, EWMA latency, and three-state circuit-breaker state (`closed`, `open`, `half_open`). Additionally, operators need a first-class `edgegate audit` CLI subcommand to fetch and verify the cryptographic SHA-256 hash-chained audit ledger from the terminal.

## Decision
1. **Outbound Mutual TLS (mTLS) Client Authentication (`INV-18`, `src/config.rs`, `src/pool.rs`):**
   - Extend `BackendPoolConfig` (`[[pools]]`) and `CompiledBackendPool` with optional `client_cert_pem: Option<String>` and `client_key_pem: Option<String>`.
   - Enforce strict fail-closed config compilation rules:
     - `client_cert_pem` and `client_key_pem` must be configured together; providing one without the other is rejected at startup and hot-reload validation time.
     - Parse X.509 certificates (`rustls_pemfile::certs`) and the private key (`rustls_pemfile::private_key`), and validate key/certificate compatibility via `rustls::ClientConfig::builder().with_client_auth_cert(certs, key)` during `CompiledConfig::compile` so invalid or mismatched key pairs never reach the data plane.
   - In `ConnectionPool::build_tls_connector`, configure the outbound `rustls::ClientConfig` with `.with_client_auth_cert(cert_chain, private_key)` when `client_cert_pem` and `client_key_pem` are present on the pool, seamlessly supporting both HTTP/1.1 and multiplexed HTTP/2 (`h2` ALPN) over mTLS.

2. **Egress Data Loss Prevention (DLP) Request Payload Guard (`INV-19`, `src/config.rs`, `src/policy.rs`, `src/proxy.rs`, `src/telemetry.rs`):**
   - Extend `PolicyRuleConfig` (`[[policies]]`) and `CompiledPolicyRule` with `#[serde(default)] pub blocked_body_substrings: Vec<String>`, rejecting empty pattern strings during config validation.
   - Return the matched rule's `blocked_body_substrings` from `DefaultDenyPolicyEngine::evaluate_full`.
   - In `EdgeGateProxy::handle_request_with_auth`, immediately after bounded request body collection (`http_body_util::Limited`) and before any upstream connection checkout or network dispatch, scan the outbound request payload bytes against every pattern in `blocked_body_substrings`.
   - If any forbidden substring is detected, fail closed with `403 Forbidden` (`{"error":"request blocked by egress DLP policy"}`), increment `dlp_blocked_total` (`edgegate_dlp_blocked_total` in Prometheus format), record a sanitized flight-recorder replay entry (`reason = "dlp_payload_blocked"`), and append a `BLOCKED` entry to the SHA-256 hash-chained audit ledger (`INV-16`).

3. **Programmable Response Header Stripping & Security Header Injection (`src/config.rs`, `src/proxy.rs`):**
   - Extend `RouteConfig` (`[[routes]]`) and `CompiledRoute` with:
     - `#[serde(default)] pub strip_response_headers: Vec<String>` (compiled and validated as lowercase `http::header::HeaderName` entries).
     - `#[serde(default)] pub inject_response_headers: BTreeMap<String, String>` (compiled and validated as `(HeaderName, HeaderValue)` pairs).
   - After upstream response headers arrive (and after the `block_secret_reflection` guard completes), remove all headers matching `strip_response_headers` and insert all `(HeaderName, HeaderValue)` pairs from `inject_response_headers` before delivering the response to the caller.

4. **Admin Pool & Circuit-Breaker Topology Introspection (`GET /_edgegate/admin/pools`) & CLI `edgegate audit` (`src/lb.rs`, `src/proxy.rs`, `src/main.rs`):**
   - Expose `LoadBalancer::snapshot_pools(&self) -> Vec<PoolStatusSnapshot>`, reporting each pool's `name`, `strategy`, `mtls_enabled`, and per-backend `id`, `address`, `weight`, `tls`, `http2`, `active_healthy`, `circuit_state` (`"closed"`, `"open"`, or `"half_open"`), `active_connections`, and `ewma_latency_us`.
   - Add `GET /_edgegate/admin/pools` to the authenticated Admin Control Plane API (protected by constant-time `X-EdgeGate-Admin-Token` verification and disabled fail-closed when unconfigured), returning `{"pools": [...]}` as JSON.
   - Extend the `edgegate` operator CLI (`src/main.rs`) with the `edgegate audit --url <URL> --admin-token <TOKEN>` subcommand to query `/_edgegate/admin/audit` with `X-EdgeGate-Admin-Token` and inspect the cryptographic SHA-256 hash-chained audit ledger.

## Alternatives Considered
- **Sidecar Envoy / Istio mTLS vs. Native Per-Pool `rustls` mTLS in EdgeGate:** Delegating outbound mTLS to an external service-mesh proxy adds an extra localhost network hop and splits policy/credential configuration across two systems. Compiling and validating `client_cert_pem` + `client_key_pem` directly inside EdgeGate's `CompiledBackendPool` keeps outbound TLS, ALPN `h2` multiplexing, SSRF validation, and atomic `ArcSwap` hot reload unified in a single memory-safe binary.
- **Asynchronous Out-of-Band DLP Inspection vs. Synchronous Inline Payload Guard:** Inspecting outbound request bodies asynchronously (e.g., via shadow mirroring) would allow exfiltrated secrets or PII to reach the external upstream before detection. Because EdgeGate already bounds request bodies in memory via `http_body_util::Limited` (`max_request_body_bytes` / per-rule `max_body_bytes`), synchronous inline scanning against `blocked_body_substrings` operates in microseconds and guarantees zero data exfiltration (`403 Forbidden` before upstream dispatch). Furthermore, `blocked_body_substrings` enforces fast synchronous literal byte-pattern detection prior to backend selection (`upstream = "-"`), ensuring no upstream socket is checked out or dialed when forbidden patterns are detected.
- **Exposing Pool Topology on Unauthenticated `/_edgegate/metrics` vs. Authenticated `/_edgegate/admin/pools`:** Detailed upstream backend addresses, weights, and mTLS states represent sensitive infrastructure topology. Gating `GET /_edgegate/admin/pools` behind `X-EdgeGate-Admin-Token` preserves least privilege while giving authorized control planes full real-time visibility.

## Consequences & Failure Modes
- **Positive:**
  - Workloads can invoke mTLS-protected enterprise and service-mesh upstreams with zero private keys inside the sandbox (`INV-18`), and client certificates can be rotated without downtime via `POST /_edgegate/admin/reload`.
  - Egress DLP (`INV-19`) stops sensitive markers, private keys, or watermarked secrets from being exfiltrated inside outbound request bodies (`403 Forbidden`, `edgegate_dlp_blocked_total`, and `dlp_payload_blocked` replay record).
  - Route-level `strip_response_headers` and `inject_response_headers` eliminate upstream server banner leakage and enforce consistent security headers across heterogeneous backends.
  - Operators gain authenticated real-time topology and circuit-breaker introspection via `GET /_edgegate/admin/pools` and terminal audit verification via `edgegate audit`.
- **Failure Modes & Mitigations:**
  - *Mismatched or corrupted mTLS PEM material during hot reload:* `CompiledConfig::compile` eagerly constructs the `rustls` client auth configuration before swapping `ArcSwap<RuntimeSnapshot>`. If the certificate or private key PEM is malformed or mismatched, the reload fails closed (`reload_failures_total` increments) and existing mTLS connections continue uninterrupted.
  - *Binary or non-UTF8 request payloads with `blocked_body_substrings`:* Byte-slice substring search (`windows(needle.len())`) scans raw request body bytes directly without requiring valid UTF-8, preventing attackers from bypassing DLP checks by embedding invalid UTF-8 sequences alongside sensitive substrings.
  - *Encoded, Unicode-escaped, or compressed payloads:* Because `blocked_body_substrings` executes literal raw byte-pattern matching for maximum microsecond throughput prior to backend selection, payloads that encode sensitive markers via Unicode escape sequences (e.g., `\u0041` for `A`), URL percent-encoding, or compression (e.g., gzip/brotli) will not match raw literal byte needles. Mitigating such evasions requires upstream schema normalization, canonical decoding, or dedicated protocol-aware inspection policies (such as Milestone 9's RFC 8259 `serde_json` JSON-RPC method inspection).
