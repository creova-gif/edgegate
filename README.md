# EdgeGate

[![CI](https://github.com/creova-gif/edgegate/actions/workflows/ci.yml/badge.svg)](https://github.com/creova-gif/edgegate/actions/workflows/ci.yml)
[![Version: v1.1.0](https://img.shields.io/badge/version-v1.1.0-blue.svg)](https://github.com/creova-gif/edgegate/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rust: 1.85+](https://img.shields.io/badge/rust-2021%20edition%20%7C%201.85%2B-orange.svg)](Cargo.toml)
[![Security Invariants: INV-01..INV-27](https://img.shields.io/badge/security%20invariants-INV--01..INV--27-brightgreen.svg)](SECURITY.md)

**EdgeGate** is a high-performance, programmable Layer-7 (L7) reverse proxy and load balancer written in Rust (`tokio` + `hyper` v1 + `rustls` + `arc-swap`) that establishes a **zero-secret network execution boundary** for AI agents, ephemeral code sandboxes, and untrusted multi-tenant workloads.

> **Defining Principle:** Untrusted workloads and AI agents should be able to invoke explicitly authorized external and internal APIs without ever possessing the underlying upstream credentials in their environment variables, filesystem, or memory, and without possessing unrestricted outbound network authority.

![EdgeGate Zero-Secret L7 Security Console](docs/assets/edgegate-console.svg)

---

## Table of Contents

- [Why EdgeGate?](#why-edgegate)
- [Industry Comparison Matrix](#industry-comparison-matrix)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Quickstart & Operator CLI](#quickstart--operator-cli)
- [Capabilities Matrix (v1.1.0)](#capabilities-matrix-v110)
- [Configuration Reference (edgegate.toml)](#configuration-reference-edgegatetoml)
- [Observability & Admin Control Plane](#observability--admin-control-plane)
- [Container Zero-Bypass Demo](#container-zero-bypass-demo)
- [Benchmarks](#benchmarks)
- [Project Structure](#project-structure)
- [Documentation & ADRs](#documentation--architecture-decision-records)
- [Contributing](#contributing)
- [License](#license)

---

## Why EdgeGate?

When AI agents or untrusted code execute inside containers or microVMs, giving them raw API keys (`OPENAI_API_KEY`, `GITHUB_TOKEN`, internal service credentials) means any prompt injection, dependency vulnerability, or arbitrary code execution immediately compromises those secrets. Conversely, routing sandbox traffic through a traditional `HTTP_PROXY` MITM forward proxy introduces custom CA distribution complexity and exposes the host network to DNS-rebinding SSRF and credential-redirect leaks.

EdgeGate solves this at the systems layer:
1. **Zero Secrets in the Sandbox:** Workloads hold zero upstream API keys, zero X.509 client private keys, and **zero bearer tokens of any kind** when connected over host-mounted or dynamically attached Unix domain sockets (`register_boxlet_sandbox`). EdgeGate authenticates the workload (supporting zero-downtime dual-token rollover via `secondary_token` / `secondary_token_sha256`), enforces stream-lifetime per-workload concurrency bulkhead quotas (`max_concurrent_requests`, `INV-20`), evaluates a default-deny multi-tenant RBAC, request-attribute, and JSON-RPC 2.0 / MCP tool policy (`required_headers`, `forbidden_query_params`, per-rule `max_body_bytes`, Egress DLP `blocked_body_substrings`, and `allowed_jsonrpc_methods`), strips forged/hop-by-hop headers, injects the scoped, TTL-checked upstream secret (`expires_at_epoch_s`, live-rotatable via `EdgeGateProxy::rotate_secret` or `/_edgegate/admin/secrets/rotate`) on the wire, generates outbound HMAC-SHA256 request signatures (`[routes.request_signing]`, `INV-23`), generates outbound AWS Signature Version 4 (SigV4) cloud request signatures (`[routes.aws_sigv4]`, `INV-25`), negotiates outbound Mutual TLS (mTLS) via pool-scoped `client_cert_pem` / `client_key_pem` (`INV-18`), verifies inbound Mutual TLS (mTLS) via `client_ca_cert_pem` / `client_ca_cert_path` (`INV-24`), enforces route-level timeout SLAs (`timeout_ms`) and upstream response payload caps with trailer preservation (`max_response_body_bytes`, `INV-21`), hardens responses via `strip_response_headers` (applied to both headers and trailers) / `inject_response_headers`, and optionally guards responses against accidental or malicious upstream secret reflection in headers, bodies, or trailers (`block_secret_reflection = true`, `INV-12`).
2. **Fail-Closed L7 Security Pipeline:** Every request passes through a linear, strongly-typed security pipeline that enforces pre-policy path normalization (`400`), inbound mTLS client verification (`INV-24`), constant-time SHA-256 primary/secondary token verification (`401`), per-workload concurrency bulkhead limits with stream-lifetime retention (`429`, `INV-20`), multi-tenant RBAC, L7 attribute/MCP tool policy, & forbidden query-parameter filtering (`403`, `INV-15`, `INV-17`), per-rule and server-wide request payload size ceilings (`413`, `INV-17`), synchronous Egress DLP request payload inspection (`blocked_body_substrings` -> `403`, `INV-19`), deep JSON-RPC 2.0 / MCP method allowlisting for single and batch calls (`403`, `INV-22`), per-workload token-bucket rate limiting (`429`), scoped credential TTL expiry enforcement (`403`, `INV-14`), resolve-validate-connect SSRF protection across IPv4/IPv6/mapped-IPv6 (`403`), outbound mTLS client authentication (`INV-18`), outbound RFC 2104 HMAC-SHA256 request signing (`INV-23`), outbound AWS SigV4 request signing (`INV-25`), route timeout SLAs & response body caps (`504`/`502`, `INV-21`), zero `3xx` redirect following, response credential reflection blocking across headers and trailers (`502`, `INV-12`), programmable response header & trailer stripping & injection, and a cryptographic SHA-256 hash-chained tamper-evident audit ledger (`INV-16`).
3. **Production-Grade Resilience, Control Plane & Observability:** Features inbound TLS 1.2/1.3 termination (`[server.tls]`, ALPN `h2` & `http/1.1`) with optional client CA verification (`INV-24`), outbound TLS 1.2/1.3 & mTLS (`client_cert_pem` / `client_key_pem`), single-flight HTTP/1.1 connection pooling with RAII EOF-drain guards (`PooledBody`), multiplexed HTTP/2 (`h2` TLS ALPN & `h2c`), bounded TTL DNS caching (`dns_cache_ttl_ms`), warm connection pool reuse across hot reloads, four load-balancing algorithms (`RoundRobin`, `LeastConnections`, `ConsistentHash`, `LatencyAware` EWMA) with weighted canary traffic splitting (`weight` on `[[pools.backends]]`), three-state circuit breakers (`Closed` -> `Open` -> `HalfOpen` single-flight probe) with payload limit fault isolation, controlled idempotent-only failover retries (`max_idempotent_retries`), stream-lifetime graceful in-flight connection draining (`drain_timeout_ms`, `GuardedResponseBody`), atomic zero-downtime hot reload (`ArcSwap`), an authenticated Admin Control Plane API (`/_edgegate/admin/reload`, `/_edgegate/admin/secrets/rotate`, `/_edgegate/admin/audit`, `/_edgegate/admin/pools` guarded by constant-time `X-EdgeGate-Admin-Token`), optional observability endpoint protection (`protect_observability = true`), lock-free Prometheus microsecond latency histograms (`edgegate_request_duration_microseconds_bucket`), W3C `traceparent` & `tracestate` propagation, live traffic shadowing, a sanitized flight-recorder replay buffer (`/_edgegate/replay`), an embedded zero-dependency WCAG 2.1 AA+ operator web console (`GET /_edgegate/console`, `INV-26`), and operator inspection CLI subcommands (`edgegate status`, `edgegate replay`, `edgegate audit` with transport security and mTLS client cert protections).

---

## Industry Comparison Matrix

| Capability / Architecture Property | EdgeGate (`v1.1.0`) | General-Purpose L7 Proxies<br>(Envoy / Kong / Traefik) | MITM Forward Proxies<br>(`HTTP_PROXY` / Squid / mitmproxy) |
|---|---|---|---|
| **Zero-Secret UDS Sandbox Identity**<br>(`[[server.unix_listeners]]`, `register_boxlet_sandbox`) | **Native & First-Class:** Dedicated per-sandbox Unix domain sockets bind tenant identity at the OS boundary; workloads hold zero bearer tokens or certificates. | **Partial / Complex:** Requires external control plane (Envoy SDS, SPIFFE/SPIRE agent) or custom Lua/Wasm plugins; TCP listeners predominate. | **Unsupported:** Relies on cleartext/basic proxy auth headers (`Proxy-Authorization`) holding credentials inside guest environment. |
| **Scoped Credential Injection & Signing**<br>(`INV-05`, `INV-23` HMAC-SHA256, `INV-25` AWS SigV4) | **Native & Org-Scoped:** Injects scoped API keys, RFC 2104 HMAC-SHA256 signatures, and AWS SigV4 signatures with fail-closed TTL validation (`INV-14`). | **Limited / Add-On:** Requires external vault sidecars, enterprise plugins (Kong Enterprise), or custom Wasm/Lua scripts; lacks integrated TTL governance. | **Unsupported:** Blindly tunnels traffic (`CONNECT`) or forwards client-supplied credentials; cannot dynamically synthesize AWS SigV4 or HMAC signatures. |
| **Defense-in-Depth Secret Reflection Guard**<br>(`INV-12`, Headers, Body & HTTP/2 Trailers) | **Native & Enforced:** Scans response headers, buffered body bytes, and HTTP/2 trailers; fails closed with `502 Bad Gateway` on echoed secrets. | **Unsupported:** No native awareness of injected secrets; echoed credentials in responses pass through unfiltered to downstream callers. | **Unsupported:** Transparent proxying forwards all response payloads verbatim, exposing reflected credentials to sandbox code. |
| **Pre-Dispatch Egress DLP & Tool Governance**<br>(`INV-19` Egress DLP, `INV-22` JSON-RPC / MCP AST) | **Native & Fail-Closed:** Pre-checkout request body DLP substring scanning + RFC 8259 JSON-RPC 2.0 / MCP AST allowlisting across single and batch objects. | **Partial:** Requires heavy external WAF modules (ModSecurity, Coraza) or custom Lua filters; no native MCP tool-call schema inspection. | **Partial / Heuristic:** Inspects plaintext streams via dynamic TLS MITM; no native JSON-RPC 2.0 / MCP tool allowlisting before dispatch. |
| **Cryptographic SHA-256 Audit Ledger**<br>(`INV-16`, Tamper-Evident Hash Chain) | **Native:** Mathematical `prev_hash` -> `entry_hash` SHA-256 chain over every routing decision, verifiable via API (`/_edgegate/admin/audit`) and CLI. | **Externalized:** Relies on streaming access logs to external SIEMs (Fluentd, OpenTelemetry); no built-in tamper-evident hash chaining. | **Externalized:** Standard access logs written to disk or syslog; easily modified or truncated without cryptographic tampering detection. |
| **Embedded WCAG 2.1 AA Operator Console**<br>(`INV-26`, `GET /_edgegate/console`) | **Native & Zero-Dependency:** Embedded high-contrast dark/light UI (>= 7:1), keyboard skip-links, ARIA live regions, memory-only token state, strict CSP. | **Externalized:** Separate dashboard deployments (Kong Manager, Traefik Dashboard); Traefik web UI has no strict WCAG 2.1 AA audit or memory-only auth. | **Limited / Developer-Only:** `mitmproxy` web interface is intended for local debugging, lacks production RBAC/CSP hardening and accessibility compliance. |
| **Memory-Safe Single Binary**<br>(`Rust 1.85+`, zero C/C++ TLS dependencies) | **Yes:** Pure Rust (`tokio` + `hyper` v1 + `rustls`), zero C/C++ dependencies in TLS path, statically compiled, minimal attack surface. | **Mixed:** Envoy (C++ with BoringSSL/OpenSSL), Kong (C/Lua on OpenResty/Nginx), Traefik (Go with standard crypto/tls). | **Mixed:** Squid (C++), mitmproxy (Python with OpenSSL C-bindings), Tinyproxy (C). |

---

## Architecture Overview

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Untrusted AI Agent / Ephemeral Sandbox (Docker internal:true or Boxlet MicroVM)  │
│  • Zero upstream API keys or mTLS private keys in env, disk, or memory           │
│  • Zero default route to the public internet                                     │
└───────────────────┬──────────────────────────────────────────┬───────────────────┘
                    │ Zero-Token UDS Socket                    │ TCP / Inbound TLS / mTLS (INV-24)
                    │ (TransportBoundAuthenticator)            │ + X-EdgeGate-Token (SHA-256)
                    ▼                                          ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                              EdgeGate L7 Data Plane                              ║
║                                                                                  ║
║  0. Admin Control Plane & Obs. ──► /_edgegate/admin/{reload,secrets/rotate,      ║
║                                    audit,pools} & optional protect_observability ║
║                                    (Constant-time Admin Token, fail-closed)      ║
║  1. Pre-Policy Path Validator  ──► Rejects .., %2e, %2f, %5c, \, %00, // (400)   ║
║  2. Workload Authenticator     ──► UDS Identity or Dual-Token SHA-256 (401)      ║
║  3. Deterministic L7 Router    ──► Longest-prefix + Host matching (403 on miss)  ║
║  4. Default-Deny Policy Engine ──► (org, workload, roles, route, method, pfx,    ║
║                                    required_headers, forbidden_query_params,     ║
║                                    per-rule max_body_bytes ceiling) (403 / 413)  ║
║  5. Stream Bulkhead & Rate Lim ──► Wait-free ArcSwap bulkhead counters (429) &   ║
║                                    token-bucket rate limits (429, INV-20)        ║
║  6. Egress DLP & JSON-RPC AST  ──► blocked_body_substrings (403, INV-19) &       ║
║                                    strict allowed_jsonrpc_methods (403, INV-22)  ║
║  7. Load Balancer & Breaker    ──► Weighted RR | LeastConn | ConsistentHash |    ║
║                                    EWMA + 3-State Breaker + Idempotent Failover  ║
║  8. Sanitizer, Secrets & HMAC  ──► Strips hop-by-hop & forged auth/signatures;   ║
║                                    TTL checks, W3C traceparent, secret injection ║
║                                    & outbound HMAC (INV-23) / AWS SigV4 (INV-25) ║
║  9. Connection Pool, mTLS/SSRF ──► Resolve-validate-connect IPv4/IPv6/mapped-v6  ║
║                                    with dns_cache_ttl_ms, warm reload pools,     ║
║                                    Outbound TLS/mTLS (INV-18), HTTP/1.1 & HTTP/2 ║
║ 10. Guarded Streaming Response ──► BufferedBodyWithTrailers (INV-21), reflection ║
║                                    guard scanning headers & trailers (502, INV-12║
║                                    GuardedResponseBody holds guards to stream EOF║
║ 11. Tamper-Evident Audit Chain ──► SHA-256 prev_hash -> entry_hash ledger        ║
║                                    (INV-16) + Lock-Free Latency Histograms       ║
╚═══════════════════╤══════════════════════════════════════════╤═══════════════════╝
                    │ Primary Dispatch                         │ Async Non-Blocking Mirror
                    ▼                                          ▼
     ┌─────────────────────────────┐            ┌─────────────────────────────┐
     │   Primary Upstream Pool     │            │   Optional Shadow Pool      │
     │ (HTTP/1.1, HTTP/2, mTLS)    │            │ (Canary Status Diffing &    │
     └─────────────────────────────┘            │  Flight-Recorder Capture)   │
                                                └─────────────────────────────┘
```

For a deep dive into the internal state machines, connection pool invariants, and design trade-offs, see [**ARCHITECTURE.md**](ARCHITECTURE.md) and [**SECURITY.md**](SECURITY.md).

---

## Installation

### 1. Prebuilt Release Binaries

Download locked, statically compiled binaries and integrity checksums from the [EdgeGate Releases](https://github.com/creova-gif/edgegate/releases) page:

```bash
# Example: Download and extract v1.1.0 for Linux x86_64 or macOS Apple Silicon (aarch64)
TARGET="x86_64-unknown-linux-gnu" # or "aarch64-apple-darwin" for macOS Apple Silicon
curl -fsSLO "https://github.com/creova-gif/edgegate/releases/download/v1.1.0/edgegate-v1.1.0-${TARGET}.tar.gz"
curl -fsSLO "https://github.com/creova-gif/edgegate/releases/download/v1.1.0/SHA256SUMS"

# Verify binary integrity against published SHA256SUMS BEFORE extraction
sha256sum --ignore-missing -c SHA256SUMS # or on macOS: shasum -a 256 --ignore-missing -c SHA256SUMS

# Extract and install binary
tar -xzf "edgegate-v1.1.0-${TARGET}.tar.gz"
sudo mv edgegate /usr/local/bin/
edgegate --version
```

### 2. Build From Source (Cargo)

EdgeGate requires Rust `1.85+` (2021 edition):

```bash
git clone https://github.com/creova-gif/edgegate.git
cd edgegate
cargo build --release
sudo cp target/release/edgegate /usr/local/bin/
```

Or install directly via Cargo:
```bash
cargo install --path .
```

### 3. Docker Container

Build a lightweight, minimal container image:

```bash
docker build -t edgegate:latest .
docker run --rm -p 127.0.0.1:8080:8080 -v $(pwd)/edgegate.demo.toml:/etc/edgegate/edgegate.toml edgegate:latest start --config /etc/edgegate/edgegate.toml
```

---

## Quickstart & Operator CLI

```bash
# 0. Clone and enter the repository (when building/running from source)
git clone https://github.com/creova-gif/edgegate.git && cd edgegate

# 1. Validate a configuration file without starting the server
cargo run -- validate --config edgegate.demo.toml
# Or with installed binary: edgegate validate --config edgegate.demo.toml

# 2. Start EdgeGate with 1-second zero-downtime hot-reload file watching
cargo run -- start --config edgegate.demo.toml --watch-interval-ms 1000

# 3. Inspect live health and telemetry counters via the Operator CLI (supports --client-cert/--client-key for mTLS)
edgegate status --url http://127.0.0.1:8080

# 4. Inspect the sanitized flight-recorder replay buffer via the Operator CLI
edgegate replay --url http://127.0.0.1:8080

# 5. Inspect and verify the cryptographic SHA-256 hash-chained audit ledger via the Operator CLI
# (Reads EDGEGATE_ADMIN_TOKEN from environment when --admin-token is omitted; supports --ca-cert for verified HTTPS, --client-cert/--client-key for mTLS)
edgegate audit --url https://127.0.0.1:8080 --admin-token "$EDGEGATE_ADMIN_TOKEN" --ca-cert /etc/edgegate/tls/ca.crt

# Note: edgegate audit refuses unencrypted http:// to non-loopback hosts unless --allow-insecure-http is passed:
edgegate audit --url http://gateway.internal:8080 --admin-token "$EDGEGATE_ADMIN_TOKEN" --allow-insecure-http

# 6. Run the interactive 5-scenario zero-secret security console demo
cargo run --example security_console_demo

# 7. Run the full unit, integration, and adversarial security test suite
cargo test --all-targets
```

---

## Capabilities Matrix (v1.1.0)

| Milestone | Subsystem | Key Capabilities |
|---|---|---|
| **Milestone 1** | **Core L7 Proxy & Zero-Secret Boundary** | • Linear typed L7 pipeline (`tokio` + `hyper` v1) with fail-closed pre-policy path normalization<br>• Constant-time SHA-256 `X-EdgeGate-Token` authentication (`subtle::ConstantTimeEq`)<br>• Default-deny multi-tenant `(org_id, workload_id, route_id, method, path_prefix)` policy engine<br>• Scoped credential injection (`SecretValue` with `ZeroizeOnDrop` and redacted `Debug`/`Display`)<br>• Single-flight HTTP/1.1 connection pool (`PooledBody` EOF-drain guard) & resolve-validate-connect SSRF guard<br>• `RoundRobin` & `LeastConnections` load balancing with passive failure ejection isolated from local `503` |
| **Milestone 2** | **TLS, Hot Reload, Zero-Token UDS & RBAC** | • Outbound `rustls` TLS 1.2/1.3 (`webpki-roots` + custom per-pool `ca_cert_pem` & `tls_sni` override)<br>• Atomic zero-downtime configuration hot reload via wait-free `ArcSwap<RuntimeSnapshot>`<br>• Static zero-token Unix domain socket listeners (`[[server.unix_listeners]]`)<br>• Role-Based Access Control (`roles` / `required_roles`) & environment-backed secrets (`env = "VAR"`)<br>• Background active HTTP health probes (`health_check_path`) + `/_edgegate/healthz` & `/_edgegate/metrics` |
| **Milestone 3** | **HTTP/2, 3-State Breakers, Shadowing & Boxlet** | • Inbound HTTP/1.1 + HTTP/2 (`h2c`) auto-detection & outbound multiplexed HTTP/2 (`http2 = true`, ALPN `h2` / `h2c`)<br>• Explicit 3-state circuit breaker (`Closed` -> `Open` -> `HalfOpen` with single-flight trial probe)<br>• `ConsistentHash` (`X-EdgeGate-Routing-Key` / `workload_id`) & `LatencyAware` (lock-free atomic EWMA) load balancing<br>• Non-blocking asynchronous traffic shadowing (`shadow_pool`) with status-mismatch telemetry<br>• Bounded flight-recorder ring buffer (`/_edgegate/replay`) & dynamic Boxlet UDS registration (`register_boxlet_sandbox`) |
| **Milestone 4** | **Rate Limiting, Trace Context & Production Hardening** | • Per-workload lock-free token-bucket rate limiting (`rate_limit_rps`, `rate_limit_burst` -> `429 Too Many Requests`)<br>• W3C Trace Context (`traceparent`) validation, synthesis, and upstream/shadow propagation<br>• Prometheus text exposition (`GET /_edgegate/metrics?format=prometheus`) alongside JSON metrics<br>• Comprehensive systems architecture, security invariant verification, and benchmark harness |
| **Milestone 5 (`v0.5.0`)** | **Inbound TLS, Secret Reflection Guard, Idempotent Failover & Graceful Drain** | • Inbound `rustls` TLS 1.2/1.3 termination (`[server.tls]`, inline `cert_pem`/`key_pem` or `cert_path`/`key_path`) with automatic ALPN `h2` & `http/1.1` negotiation<br>• Defense-in-depth Response Credential Reflection Guard (`block_secret_reflection = true` on `[routes.credential]`) blocking upstream responses that reflect injected secrets (`502 Bad Gateway`, `secret_reflections_blocked_total` + `/_edgegate/replay` audit entry)<br>• Controlled idempotent failover retries (`max_idempotent_retries` on `[[pools]]`, `retries_total`) retrying only safe methods (`GET`, `HEAD`, `OPTIONS`) on connect/transport errors against the next healthy backend while never retrying state-mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`)<br>• Graceful in-flight connection draining (`drain_timeout_ms` on `[server]`, `in_flight_requests` gauge) waiting for active streams to complete on shutdown |
| **Milestone 6 (`v0.6.0`)** | **Scoped Credential Rotation & TTL Expiry, Request-Attribute Policies, Dual-Token Rollover & Operator CLI** | • Scoped Credential Rotation & TTL Expiry (`INV-14`): `expires_at_epoch_s` on `[[secrets]]` fails closed (`403 Forbidden`) when a credential expires, and `EdgeGateProxy::rotate_secret` rotates credentials live in-memory without a full config reload (`secret_rotations_total` metric)<br>• Programmable Request-Attribute Policy Matching (`INV-15`): `required_headers` on `[[policies]]` (e.g., `required_headers = { "x-mcp-tool" = "github.read_repo" }`) enables fine-grained L7 attribute and MCP tool-call enforcement alongside Keelway MCP Gateway and IoRa<br>• Zero-Downtime Dual Workload Token Rollover: `secondary_token` / `secondary_token_sha256` on `[[workloads]]` allows seamless workload token rotation without dropping active requests<br>• Live Security Console Demo (`cargo run --example security_console_demo`) & Operator Inspection CLI (`edgegate status`, `edgegate replay`) |
| **Milestone 7 (`v0.7.0`)** | **Authenticated Admin Control Plane API, SHA-256 Tamper-Evident Audit Ledger, Weighted Canary LB, Query/Payload Resource Limits & Latency Histograms** | • Authenticated Admin Control Plane API (`/_edgegate/admin/reload`, `/_edgegate/admin/secrets/rotate`, `/_edgegate/admin/audit`): constant-time `X-EdgeGate-Admin-Token` authentication (`server.admin_token` / `server.admin_token_sha256`), disabled fail-closed when unconfigured<br>• Cryptographic SHA-256 Hash-Chained Tamper-Evident Audit Ledger (`INV-16`): `prev_hash` -> `entry_hash` SHA-256 chain over every gateway decision, verified at `/_edgegate/admin/audit` and exported via `audit_chain_valid` in `/_edgegate/metrics`<br>• Weighted Canary Load Balancing (`weight` on `[[pools.backends]]`): configurable backend weights for proportional canary traffic splitting<br>• Per-Rule Query-Parameter & Payload Resource Limits (`INV-17`, `forbidden_query_params`, `max_body_bytes`): blocks forbidden query parameters (`403 Forbidden`) and enforces per-rule request body size ceilings (`413 Payload Too Large`)<br>• Prometheus Latency Histograms (`edgegate_request_duration_microseconds_bucket`): lock-free microsecond histogram buckets (`100us`, `500us`, `1000us`, `5000us`, `10000us`, `50000us`, `+Inf`) exported on `/_edgegate/metrics?format=prometheus` |
| **Milestone 8 (`v0.8.0`)** | **Outbound mTLS Client Auth, Egress DLP Payload Guard, Programmable Response Header Hardening & Admin Pool Introspection** | • Outbound Mutual TLS (mTLS) Client Authentication (`INV-18`): per-pool `client_cert_pem` + `client_key_pem` validated via `rustls` / `rustls-pemfile` so EdgeGate presents client certificates during upstream TLS 1.2/1.3 handshakes with zero private keys in the sandbox<br>• Egress Data Loss Prevention (DLP) Payload Guard (`INV-19`): per-rule `blocked_body_substrings` inspecting bounded outbound request bodies before upstream dispatch, rejecting exfiltration attempts fail-closed with `403 Forbidden`, incrementing `dlp_blocked_total` (`edgegate_dlp_blocked_total`), and recording sanitized `dlp_payload_blocked` replay entries<br>• Programmable Response Header Stripping & Security Header Injection: route-level `strip_response_headers` and `inject_response_headers` to scrub upstream server fingerprinting headers and enforce security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control`)<br>• Admin Pool & Circuit-Breaker Topology Introspection (`GET /_edgegate/admin/pools`) & CLI `edgegate audit`: live authenticated inspection of per-pool strategy, mTLS status, backend weights, active health, EWMA latency, and 3-state circuit breakers (`closed`, `open`, `half_open`), plus the `edgegate audit` CLI subcommand |
| **Milestone 9 (`v0.9.0`)** | **Workload Bulkheads, JSON-RPC/MCP Allowlisting, Route SLAs & Protocol Hardening** | • Per-Workload Concurrency Quotas & Bulkheads (`INV-20`, `max_concurrent_requests` on `[[workloads]]` and `[[server.unix_listeners]]`): Semaphore-backed per-`(org_id, workload_id)` in-flight concurrency caps on TCP and zero-token Unix socket workloads, returning `429 Too Many Requests` (`Retry-After: 1`, `edgegate_bulkhead_rejected_total`)<br>• Per-Route Request Timeout Overrides & Upstream Response Body Caps (`INV-21`, `timeout_ms`, `max_response_body_bytes` on `[[routes]]`): Granular route response timeout SLAs (`504 Gateway Timeout` on timeout) and bounded upstream response payload enforcement (`502 Bad Gateway` on overflow)<br>• JSON-RPC 2.0 / MCP Tool-Call Method Allowlisting (`INV-22`, `allowed_jsonrpc_methods` on `[[policies]]`): RFC 8259 `serde_json` inspection of single and batch JSON-RPC 2.0 requests prior to backend checkout, blocking unauthorized MCP tool execution (`403 Forbidden`, `edgegate_jsonrpc_blocked_total`)<br>• Protocol & Control-Plane Hardening: Active HTTP/2 (`h2`/`h2c`/mTLS) health probing, HTTP/2 response trailer scrubbing (`strip_response_headers` applied to headers and trailers), and verified HTTPS (`--ca-cert`) + environment-variable token (`EDGEGATE_ADMIN_TOKEN`) + client-side SHA-256 hash-chain verification in `edgegate audit` |
| **Milestone 10 (`v1.0.0` GA)** | **HMAC Request Signing, Stream-Lifetime Bulkheads, Trailer Preservation & Production Packaging** | • Outbound Cryptographic Request Signing — HMAC-SHA256 (`INV-23`, `[routes.request_signing]`): Pure-Rust RFC 2104 HMAC-SHA256 signing (`X-EdgeGate-Timestamp` + `X-EdgeGate-Signature-256: sha256=<hex>` over `<timestamp>.<raw_body>`) backed by org-scoped `SecretProvider` with fail-closed TTL enforcement (`INV-14`), forged header stripping, and `signed_requests_total` metric<br>• Stream-Lifetime Workload Bulkhead & Graceful-Drain Guards (`INV-20` Hardening): Live-reload persistent `Arc<AtomicUsize>` counters paired with `GuardedResponseBody` holding both `WorkloadBulkheadGuard` and `InFlightGuard` until streaming response EOF or drop, protecting SSE, gRPC, and chunked streams<br>• Trailer-Preserving Response Caps & Breaker Fault Isolation (`INV-21` Hardening): Preserves HTTP/2 trailers (`grpc-status`) through `BufferedBodyWithTrailers` and scrubs trailers via `strip_response_headers`; isolates `http_body_util::LengthLimitError` (`502 Bad Gateway`) from tripping shared backend circuit breakers<br>• Strict JSON-RPC 2.0 Envelope Validation & Explicit Empty Allowlist (`INV-22` Hardening): `Option<Vec<String>>` semantics where `allowed_jsonrpc_methods = []` enforces fail-closed deny-all (`403 Forbidden`) and mandatory `"jsonrpc": "2.0"` envelope validation is required on all single and batch objects<br>• CLI Cleartext Admin Credential Protection & Production Packaging: `edgegate audit` refuses cleartext `http://` transport to non-loopback hosts without `--allow-insecure-http`, rejects `--ca-cert` on `http://` URLs, and packages deterministic GitHub Release binaries |
| **Milestone 11 (`v1.1.0`)** | **Enterprise Scalability, Inbound mTLS, AWS SigV4, Web Console & Browser Interoperability** | • Inbound Mutual TLS (mTLS) Client Verification (`INV-24`, `[server.tls]` `client_ca_cert_pem` / `client_ca_cert_path`): Hardware/sidecar X.509 client certificate validation at the inbound TLS listener via `rustls::server::WebPkiClientVerifier`, with `--client-cert` / `--client-key` CLI support<br>• Outbound AWS Signature Version 4 (SigV4) Cloud Request Signing (`INV-25`, `[routes.aws_sigv4]`): Zero-secret canonical AWS SigV4 signing (`AWS4-HMAC-SHA256`, `x-amz-date`, `x-amz-content-sha256`) for S3, Bedrock, DynamoDB, R2, and MinIO backends with automatic stripping of caller-forged `Authorization` and `x-amz-*` headers<br>• Wait-Free Hot-Path Concurrency & Warm Pool Reuse: Lock-free `ArcSwap` secret and bulkhead lookups eliminating `Mutex` contention, bounded SSRF-validated DNS cache (`dns_cache_ttl_ms`), and warm `UpstreamSlot` connection pool reuse across atomic `ArcSwap` hot reloads delivering **2.36x throughput gain** (`64,854.4 req/s`) and **-50.9% added p95 latency reduction** (`+445 µs`)<br>• Embedded WCAG 2.1 AA+ Operator Web Console (`INV-26`, `GET /_edgegate/console`, `src/console.rs`): Zero-dependency control-plane console with adaptive dark/light high-contrast themes (>= 7:1), keyboard skip-links, WAI-ARIA live regions, strict CSP, and memory-only token handling<br>• Route-Level CORS Preflight & Browser/MCP Interoperability (`INV-27`, `[routes.cors]`): Granular origin allowlists forbidding wildcard `*` with credentials, zero-secret `OPTIONS` preflight short-circuiting (`204 No Content`), `Vary: Origin`, and `Access-Control-Expose-Headers`<br>• W3C `tracestate` Interoperability (`src/router.rs`): Level 1 validation (printable ASCII, `<= 512` bytes, `<= 32` members) and upstream/shadow propagation alongside `traceparent`<br>• Optional Observability Authentication (`protect_observability = true`) & Trailer Secret-Reflection Scanning (`INV-12` Hardening): Restricts `/_edgegate/metrics` and `/_edgegate/replay` behind `X-EdgeGate-Admin-Token` while keeping `/_edgegate/healthz` open for orchestrators, and intercepts reflected credentials in HTTP/2 trailers |

---

## Configuration Reference (`edgegate.toml`)

```toml
[server]
listen_addr = "0.0.0.0:8080"
max_request_body_bytes = 1048576   # Global 1 MiB cap enforced via http_body_util::Limited (413 on overflow)
connect_timeout_ms = 2000          # Upstream TCP + TLS + HTTP handshake timeout (504 on timeout)
response_timeout_ms = 10000        # Upstream response header timeout (504 on timeout)
drain_timeout_ms = 5000            # Graceful shutdown drain window for in_flight_requests (Milestone 5)
replay_buffer_size = 64            # Bounded flight-recorder ring buffer capacity for /_edgegate/replay
dns_cache_ttl_ms = 60000          # Optional bounded TTL DNS cache for SSRF-validated sockets (Milestone 11)
protect_observability = true       # Optional gate /metrics and /replay behind admin_token in multi-tenant setups (Milestone 11)
# Optional Admin Control Plane token (`admin_token` or 64-hex-char `admin_token_sha256`, Milestone 7).
# When omitted, all `/_edgegate/admin/*` endpoints fail closed.
admin_token_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Optional inbound TLS 1.2/1.3 termination with automatic ALPN `h2` and `http/1.1` negotiation (Milestone 5).
# Provide either `cert_pem` + `key_pem` inline OR `cert_path` + `key_path` on disk.
# Optional client_ca_cert_path or client_ca_cert_pem enforces inbound Mutual TLS (INV-24, Milestone 11).
# [server.tls]
# cert_path = "/etc/edgegate/tls/server.crt"
# key_path = "/etc/edgegate/tls/server.key"
# client_ca_cert_path = "/etc/edgegate/tls/client_ca.crt"

# Optional zero-token Unix domain socket listeners bound to specific workload identities.
# Workloads connecting via this socket need ZERO tokens in environment variables or headers.
[[server.unix_listeners]]
path = "/tmp/edgegate-agent-alpha.sock"
workload_id = "sandbox-alpha-uds"
org_id = "org-alpha"
roles = ["repo:read", "inference:call"]
max_concurrent_requests = 16       # Optional per-workload concurrency bulkhead limit (INV-20, Milestone 9)

# Token-authenticated workloads (specify either plaintext `token` for local dev or 64-hex-char `token_sha256`).
# Optional `secondary_token` or `secondary_token_sha256` enables zero-downtime workload token rollover (Milestone 6).
[[workloads]]
workload_id = "sandbox-alpha"
org_id = "org-alpha"
token_sha256 = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"
secondary_token_sha256 = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
roles = ["repo:read", "inference:call"]
max_concurrent_requests = 32       # Optional per-workload concurrency bulkhead limit (INV-20, Milestone 9)

[[pools]]
name = "github-primary"
strategy = "round_robin"           # "round_robin" | "least_connections" | "consistent_hash" | "latency_aware"
max_connections_per_upstream = 64  # Bounded per-backend Semaphore (returns local 503 when saturated)
idle_ttl_ms = 30000                # Idle HTTP/1.1 keep-alive eviction TTL
passive_failure_threshold = 3      # Consecutive 502/504/5xx failures before tripping Closed -> Open
passive_cooldown_ms = 5000         # Cooldown in Open state before admitting single-flight HalfOpen probe
max_idempotent_retries = 1         # Retries safe methods (GET/HEAD/OPTIONS) on connect/transport errors across healthy backends
allow_private_ip = false           # Keep false in production to enforce full IPv4/IPv6/mapped-v6 SSRF blocklist
health_check_path = "/healthz"     # Optional background active HTTP health probe path
health_check_interval_ms = 5000
# Optional outbound Mutual TLS (mTLS) client certificate & private key (INV-18, Milestone 8).
# Must be specified together; validated at config compile time via rustls.
# client_cert_pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
# client_key_pem = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
backends = [
  { id = "gh-stable", address = "api.github.com:443", tls = true, tls_sni = "api.github.com", http2 = true, weight = 9 },
  { id = "gh-canary", address = "api.github.com:443", tls = true, tls_sni = "api.github.com", http2 = true, weight = 1 },
]

[[pools]]
name = "github-canary"
strategy = "consistent_hash"
allow_private_ip = false
backends = [
  { id = "gh-canary-1", address = "canary.api.github.com:443", tls = true, http2 = true },
]

[[routes]]
id = "github-api"
path_prefix = "/v1/github"
host = "gateway.internal"          # Optional Host header constraint
strip_prefix = true                # Rewrites /v1/github/repos/foo -> /repos/foo
pool = "github-primary"
shadow_pool = "github-canary"      # Optional non-blocking async traffic mirroring & status diffing
timeout_ms = 30000                 # Optional per-route response timeout SLA in ms, overriding server default (INV-21, Milestone 9)
max_response_body_bytes = 10485760 # Optional per-route upstream response body size cap; 502 on overflow (INV-21, Milestone 9)
strip_response_headers = ["server", "x-powered-by"] # Optional upstream response header scrubbing (Milestone 8)
inject_response_headers = { "x-content-type-options" = "nosniff", "x-frame-options" = "DENY", "cache-control" = "no-store" } # Optional security header injection (Milestone 8)
[routes.credential]
credential_ref = "github_pat"
header_name = "Authorization"      # Unconditionally stripped from incoming request before injection
value_prefix = "Bearer "
block_secret_reflection = true     # Blocks 502 Bad Gateway if upstream reflects injected secret in headers/body/trailers

# Optional Outbound Cryptographic Request Signing (INV-23, Milestone 10 / v1.0.0 GA).
# Signs outbound payload using pure-Rust RFC 2104 HMAC-SHA256, stripping incoming caller-forged headers.
[routes.request_signing]
credential_ref = "webhook_hmac_key"          # Resolves org-scoped secret in [[secrets]]
signature_header = "X-EdgeGate-Signature-256" # Header populated with sha256=<hex_digest>
timestamp_header = "X-EdgeGate-Timestamp"     # Header populated with Unix epoch seconds

# Optional Outbound AWS Signature Version 4 (SigV4) Signing (INV-25, Milestone 11 / v1.1.0).
# Signs outbound requests to S3, Bedrock, DynamoDB, R2, or MinIO using canonical AWS SigV4.
# [routes.aws_sigv4]
# access_key_ref = "aws_access_key"            # Resolves org-scoped AWS access key in [[secrets]]
# secret_key_ref = "aws_secret_key"            # Resolves org-scoped AWS secret key in [[secrets]]
# region = "us-east-1"
# service = "s3"

# Optional Route-Level CORS Preflight & Browser/MCP Interoperability (INV-27, Milestone 11 / v1.1.0).
# Short-circuits OPTIONS requests with 204 No Content before upstream connection checkout or secret injection.
# [routes.cors]
# allow_origins = ["https://console.internal", "https://agent.example.com"]
# allow_methods = ["GET", "POST", "OPTIONS"]
# allow_headers = ["Authorization", "Content-Type", "X-EdgeGate-Token", "X-MCP-Tool"]
# expose_headers = ["X-EdgeGate-Timestamp", "X-EdgeGate-Signature-256"]
# allow_credentials = true
# max_age_s = 86400

[[policies]]
org_id = "org-alpha"
workload_id = "sandbox-alpha"      # Optional; omit to match any workload within `org_id`
required_roles = ["repo:read"]     # All listed RBAC roles must be present on the authenticated workload
route_id = "github-api"
methods = ["GET", "POST"]
path_prefix = "/v1/github/repos"   # Segment-boundary-safe prefix check
required_headers = { "x-mcp-tool" = "github.read_repo" } # Optional L7 attribute / MCP tool-call enforcement (Milestone 6)
forbidden_query_params = ["debug", "raw_token"]          # Blocks requests containing forbidden query parameters with 403 (Milestone 7)
max_body_bytes = 65536             # Optional per-rule payload ceiling in bytes; returns 413 on overflow (Milestone 7)
blocked_body_substrings = ["-----BEGIN PRIVATE KEY-----", "AKIA"] # Optional Egress DLP payload guard; blocks with 403 (INV-19, Milestone 8)
allowed_jsonrpc_methods = ["tools/list", "tools/call", "resources/read"] # Optional JSON-RPC 2.0 / MCP tool allowlist (INV-22, Milestone 9; [] denies all fail-closed)
rate_limit_rps = 100               # Optional token-bucket refill rate (requests/sec)
rate_limit_burst = 200             # Optional token-bucket burst capacity

[[secrets]]
org_id = "org-alpha"
credential_ref = "github_pat"
env = "EDGEGATE_GITHUB_PAT"        # Reads secret from host process environment (or use `value = "..."` for local dev)
expires_at_epoch_s = 4102444800    # Optional Unix epoch expiry timestamp; fails closed (403) when expired (Milestone 6)

[[secrets]]
org_id = "org-alpha"
credential_ref = "webhook_hmac_key"
env = "EDGEGATE_WEBHOOK_HMAC_KEY"  # Secret used for RFC 2104 HMAC-SHA256 request signing (INV-23, Milestone 10)

[[secrets]]
org_id = "org-alpha"
credential_ref = "aws_access_key"
env = "AWS_ACCESS_KEY_ID"          # Secret used for outbound AWS SigV4 request signing (INV-25, Milestone 11)

[[secrets]]
org_id = "org-alpha"
credential_ref = "aws_secret_key"
env = "AWS_SECRET_ACCESS_KEY"      # Secret used for outbound AWS SigV4 request signing (INV-25, Milestone 11)
```

---

## Observability & Admin Control Plane

EdgeGate exposes built-in, zero-secret diagnostic endpoints and an authenticated Admin Control Plane API (`X-EdgeGate-Admin-Token`, disabled fail-closed when `server.admin_token` / `server.admin_token_sha256` is unconfigured; `/metrics` and `/replay` optionally gated by `protect_observability = true` in Milestone 11):

| Endpoint | Format | Description |
|---|---|---|
| `GET /_edgegate/healthz` | `application/json` | Returns liveness and active atomic `ArcSwap` configuration generation (`{"status":"ok","config_generation":1}`). Unauthenticated for container orchestrator liveness probes. |
| `GET /_edgegate/metrics` | `application/json` | Exposes lock-free atomic counters, gauges, and tamper-evident audit chain health: `allowed_total`, `blocked_total`, `signed_requests_total`, `aws_sigv4_signed_requests_total`, `dlp_blocked_total`, `bulkhead_rejected_total`, `jsonrpc_blocked_total`, `rate_limited_total`, `upstream_errors_total`, `retries_total`, `secret_reflections_blocked_total`, `secret_rotations_total`, `in_flight_requests`, `reloads_total`, `reload_failures_total`, `config_generation`, `shadow_requests_total`, `shadow_mismatches_total`, and `audit_chain_valid`. (Protected by admin token when `protect_observability = true`). |
| `GET /_edgegate/metrics?format=prometheus` | `text/plain; version=0.0.4` | Exposes all EdgeGate telemetry counters (`edgegate_signed_requests_total`, `edgegate_aws_sigv4_signed_requests_total`, `edgegate_dlp_blocked_total`, `edgegate_bulkhead_rejected_total`, `edgegate_jsonrpc_blocked_total`, etc.), gauges (`edgegate_audit_chain_valid`, `edgegate_in_flight_requests`), and lock-free microsecond request latency histogram buckets (`edgegate_request_duration_microseconds_bucket` across `100us`, `500us`, `1000us`, `5000us`, `10000us`, `50000us`, `+Inf`) in standard Prometheus text exposition format. |
| `GET /_edgegate/replay` | `application/json` | Returns the bounded flight-recorder ring buffer of recent `5xx`/`502`/`503`/`504` upstream failures, `secret_reflection_blocked` events, `dlp_payload_blocked` events, `jsonrpc_method_blocked` events, and `shadow_status_mismatch` events (strictly sanitized: zero headers, bodies, or credentials). (Protected by admin token when `protect_observability = true`). |
| `POST /_edgegate/admin/reload` | `application/json` | Requires constant-time `X-EdgeGate-Admin-Token`. Atomically compiles and swaps a new TOML configuration payload without dropping in-flight connections (`403`/`401` when unconfigured or invalid token). Preserves warm connection pools for surviving backends. |
| `POST /_edgegate/admin/secrets/rotate` | `application/json` | Requires constant-time `X-EdgeGate-Admin-Token`. Rotates a scoped `(org_id, credential_ref)` secret and optional `expires_at_epoch_s` TTL live in-memory (`secret_rotations_total`). |
| `GET /_edgegate/admin/audit` | `application/json` | Requires constant-time `X-EdgeGate-Admin-Token`. Returns the cryptographic SHA-256 hash-chained tamper-evident audit ledger (`prev_hash` -> `entry_hash` over every gateway decision, `INV-16`) along with full chain verification status. |
| `GET /_edgegate/admin/pools` | `application/json` | Requires constant-time `X-EdgeGate-Admin-Token`. Returns live pool and backend topology snapshots (`strategy`, `mtls_enabled`, per-backend `weight`, `active_healthy`, `circuit_state` (`closed`/`open`/`half_open`), `active_connections`, and `ewma_latency_us`). |
| `GET /_edgegate/console` | `text/html; charset=utf-8` | Embedded WCAG 2.1 AA+ Operator Control-Plane Web Console featuring adaptive high-contrast dark/light theming (>= 7:1), keyboard skip-links, WAI-ARIA landmarks & `aria-live` announcements, strict `Content-Security-Policy` (`default-src 'none'`, `frame-ancestors 'none'`), and memory-only admin token handling (`INV-26`). |

---

## Container Zero-Bypass Demo

EdgeGate ships with a reproducible multi-container Docker Compose topology ([`docker-compose.demo.yml`](docker-compose.demo.yml) and [`scripts/demo-verify.sh`](scripts/demo-verify.sh)) that places a sandbox container onto an isolated `internal: true` network with zero upstream API keys and verifies:
1. Direct outbound bypass from the sandbox to upstream backends fails at the network layer.
2. Unauthenticated, cross-tenant, and path-traversal requests to EdgeGate fail closed (`400`/`401`/`403`).
3. Requests targeting cloud metadata (`169.254.169.254`) are blocked by EdgeGate's SSRF guard (`403`).
4. Authorized requests succeed (`200 OK`), round-robin across healthy upstreams, and receive the injected `Authorization: Bearer ...` credential on the wire.

```bash
docker compose -f docker-compose.demo.yml up -d --build
./scripts/demo-verify.sh
docker compose -f docker-compose.demo.yml down
```

---

## Benchmarks

Reproducible localhost HTTP/1.1 keep-alive benchmark ([`examples/bench.rs`](examples/bench.rs)) executed via `cargo run --release --example bench` (32 concurrent workers × 500 requests = 16,000 requests against in-process mock upstreams on Apple Silicon loopback) with EdgeGate `v1.1.0` (`PooledBody` HTTP/1.1 keep-alive EOF return fix + wait-free `ArcSwap` secret/bulkhead lookups + validated TTL DNS cache):

| Path | Throughput (`req/s`) | `p50` Latency | `p95` Latency | `p99` Latency |
|---|---:|---:|---:|---:|
| **Direct Upstream Baseline** | `174,084.6 req/s` | `183 µs` | `247 µs` | `307 µs` |
| **Via EdgeGate (v1.1.0 Full Auth + RBAC + SSRF + Pool + Secret Injection)** | **`64,854.4 req/s`**<br>*(**2.36x** / **+136.2%** vs v1.0.0's `27,458.3 req/s`)* | `474 µs` | **`692 µs`**<br>*(-46.8% vs v1.0.0)* | `836 µs` |
| **Added EdgeGate Overhead** | — | **`+291 µs` (`0.29 ms`)** | **`+445 µs` (`0.445 ms`, -50.9% reduction)** | **`+529 µs` (`0.53 ms`)** |

*(Measured on local loopback against in-process mock upstreams to isolate proxy data-plane overhead; not a claim of WAN internet latency. The measured 2.36x throughput gain and -50.9% reduction in added p95 overhead reflect the elimination of mutex contention via wait-free ArcSwap pointers, warm connection pool reuse across hot reloads, and the PooledBody keep-alive EOF fix.)*

---

## Project Structure

```text
edgegate/
├── Cargo.toml                  # Rust workspace configuration, dependencies, and v1.0.0 metadata
├── README.md                   # Flagship documentation, quickstart, capabilities matrix & architecture
├── ARCHITECTURE.md             # In-depth systems architecture, state machines, and RFC implementations
├── SECURITY.md                 # Security policy, vulnerability reporting, and 27 enforced invariants (INV-01..INV-27)
├── CONTRIBUTING.md             # Developer guidelines, coding standards, and PR workflows
├── CHANGELOG.md                # Detailed version history and release notes from v0.1.0 to v1.1.0
├── LICENSE                     # MIT Open Source License
├── edgegate.demo.toml          # Annotated production reference configuration
├── docker-compose.demo.yml     # Multi-container zero-bypass security proof topology
├── Dockerfile                  # Production container build specification
│
├── src/                        # Core Rust source modules
│   ├── lib.rs                  # Library entry point, typed EdgeGateError enum & status code mappings
│   ├── main.rs                 # CLI entry point (start, validate, status, replay, audit)
│   ├── auth.rs                 # Workload identity, constant-time SHA-256 tokens & UDS authenticators
│   ├── config.rs               # TOML deserialization, validation, compilation & HMAC/mTLS config models
│   ├── console.rs              # Embedded zero-dependency WCAG 2.1 AA+ operator web console (INV-26)
│   ├── lb.rs                   # RoundRobin, LeastConn, ConsistentHash, EWMA & 3-state circuit breakers
│   ├── policy.rs               # Default-deny RBAC, attribute policies, egress DLP & JSON-RPC 2.0 AST engine
│   ├── pool.rs                 # Connection pool, HTTP/1.1 single-flight & HTTP/2 multiplexing, SSRF & mTLS
│   ├── proxy.rs                # Linear L7 data plane, GuardedResponseBody, HMAC signing & response hardening
│   ├── router.rs               # Path normalization, longest-prefix routing & header sanitization
│   ├── secrets.rs              # ZeroizeOnDrop SecretValue, MockSecretProvider & in-memory rotation
│   └── telemetry.rs            # Prometheus metrics, microsecond latency histograms & SHA-256 audit ledger
│
├── tests/                      # Deterministic integration and adversarial security test suites
│   ├── adversarial_security.rs # Path traversal, SSRF, header smuggling, reflection & cross-tenant tests
│   ├── milestone2_features.rs  # Outbound TLS, hot reload, UDS identity & RBAC tests
│   ├── milestone3_features.rs  # HTTP/2, 3-state circuit breakers, traffic shadowing & Boxlet tests
│   ├── milestone4_features.rs  # Token-bucket rate limiting, W3C trace context & Prometheus metrics
│   ├── milestone5_features.rs  # Inbound TLS, credential reflection guard & idempotent failover tests
│   ├── milestone6_features.rs  # Scoped credential rotation, TTL expiry & attribute policies
│   ├── milestone7_features.rs  # Authenticated Admin Control Plane & SHA-256 audit ledger tests
│   ├── milestone8_features.rs  # Outbound mTLS, egress DLP payload guard & header hardening tests
│   ├── milestone9_features.rs  # Bulkheads, JSON-RPC allowlists, route SLAs & protocol tests
│   ├── milestone10_v1_ga.rs    # HMAC signing, stream bulkheads & JSON-RPC envelope tests
│   ├── milestone11_enterprise.rs # Inbound mTLS, AWS SigV4, warm reload pools & DNS cache tests
│   └── milestone12_console_and_interop.rs # Operator console WCAG 2.1 AA, CORS preflight & tracestate tests
│
├── examples/                   # Executable demonstrations and benchmark harnesses
│   ├── bench.rs                # Reproducible 32-worker latency/throughput benchmark
│   └── security_console_demo.rs# Interactive 5-scenario zero-secret security console demo
│
├── scripts/                    # Automation and validation scripts
│   └── demo-verify.sh          # Automated Docker zero-bypass container verification script
│
├── docs/                       # Architecture decision records and threat model documentation
│   ├── THREAT_MODEL.md         # STRIDE threat model and attack boundary analysis
│   ├── assets/                 # Visual architecture and security console diagrams
│   │   └── edgegate-console.svg# Vector SVG preview of EdgeGate L7 security console
│   └── adr/                    # Complete Architecture Decision Records (ADR-001 through ADR-011)
│       ├── 000-template.md     # Architecture Decision Record template
│       ├── 001-explicit-l7-gateway-architecture.md
│       ├── 002-milestone-2-tls-hot-reload-uds-and-rbac.md
│       ├── 003-milestone-3-http2-circuit-breakers-shadowing-and-boxlet.md
│       ├── 004-milestone-4-rate-limiting-w3c-tracing-and-prometheus.md
│       ├── 005-milestone-5-inbound-tls-reflection-guard-and-idempotent-retries.md
│       ├── 006-milestone-6-credential-rotation-attribute-policies-and-cli-replay.md
│       ├── 007-milestone-7-admin-control-plane-hash-chained-audit-and-weighted-canary.md
│       ├── 008-milestone-8-outbound-mtls-egress-dlp-response-hardening-and-pool-introspection.md
│       ├── 009-milestone-9-workload-bulkheads-jsonrpc-mcp-allowlists-and-route-slas.md
│       ├── 010-milestone-10-v1-ga-hmac-request-signing-streaming-bulkheads-and-oss-packaging.md
│       └── 011-milestone-11-enterprise-scalability-inbound-mtls-aws-sigv4-and-warm-reload-pools.md
│
└── .github/                    # CI/CD automation workflows
    └── workflows/
        ├── ci.yml              # Automated rustfmt, clippy (-D warnings), tests, audit, and demo validation
        └── release.yml         # Tagged release automation across Linux and macOS matrix with SHA256SUMS
```

---

## Documentation & Architecture Decision Records

- [**Systems Architecture Guide (`ARCHITECTURE.md`)**](ARCHITECTURE.md)
- [**Security Policy & Enforced Invariants (`SECURITY.md`)**](SECURITY.md)
- [**Threat Model (`docs/THREAT_MODEL.md`)**](docs/THREAT_MODEL.md)
- [**Changelog & Version History (`CHANGELOG.md`)**](CHANGELOG.md)
- [**Contributing & Engineering Standards (`CONTRIBUTING.md`)**](CONTRIBUTING.md)
- **Architecture Decision Records (`docs/adr/`):**
  - [**ADR-001:** Explicit L7 Reverse-Proxy Gateway Architecture](docs/adr/001-explicit-l7-gateway-architecture.md)
  - [**ADR-002:** Milestone 2 — Outbound TLS, Atomic Hot Reload, Zero-Token UDS Identity, RBAC & Active Health Probes](docs/adr/002-milestone-2-tls-hot-reload-uds-and-rbac.md)
  - [**ADR-003:** Milestone 3 — HTTP/2, Three-State Circuit Breakers, Consistent/Latency-Aware LB, Traffic Shadowing & Boxlet UDS](docs/adr/003-milestone-3-http2-circuit-breakers-shadowing-and-boxlet.md)
  - [**ADR-004:** Milestone 4 — Token-Bucket Rate Limiting, W3C Trace Context Propagation, and Prometheus Exposition](docs/adr/004-milestone-4-rate-limiting-w3c-tracing-and-prometheus.md)
  - [**ADR-005:** Milestone 5 — Inbound TLS, Response Credential Reflection Guard, Controlled Idempotent Retries, and Graceful Draining](docs/adr/005-milestone-5-inbound-tls-reflection-guard-and-idempotent-retries.md)
  - [**ADR-006:** Milestone 6 — Scoped Credential Rotation & TTL Expiry, Programmable Request-Attribute Policy Matching, Zero-Downtime Dual Workload Token Rollover, and CLI Replay](docs/adr/006-milestone-6-credential-rotation-attribute-policies-and-cli-replay.md)
  - [**ADR-007:** Milestone 7 — Authenticated Admin Control Plane API, SHA-256 Tamper-Evident Audit Ledger, Weighted Canary LB, Query/Payload Resource Guards & Latency Histograms](docs/adr/007-milestone-7-admin-control-plane-hash-chained-audit-and-weighted-canary.md)
  - [**ADR-008:** Milestone 8 — Outbound Mutual TLS (mTLS) Client Authentication, Egress DLP Payload Guard, Programmable Response Header Hardening & Admin Pool Introspection](docs/adr/008-milestone-8-outbound-mtls-egress-dlp-response-hardening-and-pool-introspection.md)
  - [**ADR-009:** Milestone 9 — Workload Bulkheads, JSON-RPC 2.0 / MCP Tool Method Allowlists, Route Timeout SLAs & Protocol Hardening](docs/adr/009-milestone-9-workload-bulkheads-jsonrpc-mcp-allowlists-and-route-slas.md)
  - [**ADR-010:** Milestone 10 — v1.0.0 GA: Outbound Cryptographic Request Signing (HMAC-SHA256), Stream-Lifetime Bulkheads & Drain Guards, Trailer-Preserving Response Caps, Strict JSON-RPC Envelope Enforcement, and Production Hardening](docs/adr/010-milestone-10-v1-ga-hmac-request-signing-streaming-bulkheads-and-oss-packaging.md)
  - [**ADR-011:** Milestone 11 — Enterprise Scalability: Inbound Mutual TLS (mTLS), AWS SigV4 Cloud Request Signing, Wait-Free ArcSwap Hot Paths & Warm Connection Pool Reuse](docs/adr/011-milestone-11-enterprise-scalability-inbound-mtls-aws-sigv4-and-warm-reload-pools.md)

---

## Contributing

We welcome community contributions to EdgeGate! Please review our [**Contributing Guide (`CONTRIBUTING.md`)**](CONTRIBUTING.md) for details on:
- Setting up the local development environment and toolchain
- Running formatters (`cargo fmt`) and strict lints (`cargo clippy --all-targets -- -D warnings`)
- Writing deterministic integration and adversarial security tests
- Recording non-trivial design decisions using the ADR template (`docs/adr/000-template.md`)

---

## License

Licensed under the [MIT License](LICENSE).
