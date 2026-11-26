# EdgeGate

[![CI](https://github.com/creova-gif/edgegate/actions/workflows/ci.yml/badge.svg)](https://github.com/creova-gif/edgegate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021%20edition%20%7C%20stable-orange.svg)](Cargo.toml)

**EdgeGate** is a high-performance, programmable Layer-7 (L7) reverse proxy and load balancer written in Rust (`tokio` + `hyper` v1 + `rustls` + `arc-swap`) that establishes a **zero-secret network execution boundary** for AI agents, ephemeral code sandboxes, and untrusted multi-tenant workloads.

> **Defining Principle:** Untrusted workloads and AI agents should be able to invoke explicitly authorized external and internal APIs without ever possessing the underlying upstream credentials in their environment variables, filesystem, or memory, and without possessing unrestricted outbound network authority.

---

## Why EdgeGate?

When AI agents or untrusted code execute inside containers or microVMs, giving them raw API keys (`OPENAI_API_KEY`, `GITHUB_TOKEN`, internal service credentials) means any prompt injection, dependency vulnerability, or arbitrary code execution immediately compromises those secrets. Conversely, routing sandbox traffic through a traditional `HTTP_PROXY` MITM forward proxy introduces custom CA distribution complexity and exposes the host network to DNS-rebinding SSRF and credential-redirect leaks.

EdgeGate solves this at the systems layer:
1. **Zero Secrets in the Sandbox:** Workloads hold zero upstream API keys, zero X.509 client private keys, and **zero bearer tokens of any kind** when connected over host-mounted or dynamically attached Unix domain sockets (`register_boxlet_sandbox`). EdgeGate authenticates the workload (supporting zero-downtime dual-token rollover via `secondary_token` / `secondary_token_sha256`), enforces per-workload concurrency bulkhead quotas (`max_concurrent_requests`, `INV-20`), evaluates a default-deny multi-tenant RBAC, request-attribute, and JSON-RPC 2.0 / MCP tool policy (`required_headers`, `forbidden_query_params`, per-rule `max_body_bytes`, Egress DLP `blocked_body_substrings`, and `allowed_jsonrpc_methods`), strips forged/hop-by-hop headers, injects the scoped, TTL-checked upstream secret (`expires_at_epoch_s`, live-rotatable via `EdgeGateProxy::rotate_secret` or `/_edgegate/admin/secrets/rotate`) on the wire, negotiates outbound Mutual TLS (mTLS) via pool-scoped `client_cert_pem` / `client_key_pem` (`INV-18`), enforces route-level timeout SLAs (`timeout_ms`) and upstream response payload caps (`max_response_body_bytes`, `INV-21`), hardens responses via `strip_response_headers` (applied to both headers and trailers) / `inject_response_headers`, and optionally guards responses against accidental or malicious upstream secret reflection (`block_secret_reflection = true`).
2. **Fail-Closed L7 Security Pipeline:** Every request passes through a linear, strongly-typed security pipeline that enforces pre-policy path normalization (`400`), constant-time SHA-256 primary/secondary token verification (`401`), per-workload concurrency bulkhead limits (`429`, `INV-20`), multi-tenant RBAC, L7 attribute/MCP tool policy, & forbidden query-parameter filtering (`403`, `INV-15`, `INV-17`), per-rule and server-wide request payload size ceilings (`413`, `INV-17`), synchronous Egress DLP request payload inspection (`blocked_body_substrings` -> `403`, `INV-19`), deep JSON-RPC 2.0 / MCP method allowlisting for single and batch calls (`403`, `INV-22`), per-workload token-bucket rate limiting (`429`), scoped credential TTL expiry enforcement (`403`, `INV-14`), resolve-validate-connect SSRF protection across IPv4/IPv6/mapped-IPv6 (`403`), outbound mTLS client authentication (`INV-18`), route timeout SLAs & response body caps (`504`/`502`, `INV-21`), zero `3xx` redirect following, response credential reflection blocking (`502`), programmable response header & trailer stripping & injection, and a cryptographic SHA-256 hash-chained tamper-evident audit ledger (`INV-16`).
3. **Production-Grade Resilience, Control Plane & Observability:** Features inbound TLS 1.2/1.3 termination (`[server.tls]`, ALPN `h2` & `http/1.1`), outbound TLS 1.2/1.3 & mTLS (`client_cert_pem` / `client_key_pem`), single-flight HTTP/1.1 connection pooling with RAII EOF-drain guards (`PooledBody`), multiplexed HTTP/2 (`h2` TLS ALPN & `h2c`), four load-balancing algorithms (`RoundRobin`, `LeastConnections`, `ConsistentHash`, `LatencyAware` EWMA) with weighted canary traffic splitting (`weight` on `[[pools.backends]]`), three-state circuit breakers (`Closed` -> `Open` -> `HalfOpen` single-flight probe), controlled idempotent-only failover retries (`max_idempotent_retries`), graceful in-flight connection draining (`drain_timeout_ms`), atomic zero-downtime hot reload (`ArcSwap`), an authenticated Admin Control Plane API (`/_edgegate/admin/reload`, `/_edgegate/admin/secrets/rotate`, `/_edgegate/admin/audit`, `/_edgegate/admin/pools` guarded by constant-time `X-EdgeGate-Admin-Token`), lock-free Prometheus microsecond latency histograms (`edgegate_request_duration_microseconds_bucket`), W3C `traceparent` propagation, live traffic shadowing, a sanitized flight-recorder replay buffer (`/_edgegate/replay`), and operator inspection CLI subcommands (`edgegate status`, `edgegate replay`, `edgegate audit`).

---

## Architecture Overview

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Untrusted AI Agent / Ephemeral Sandbox (Docker internal:true or Boxlet MicroVM)  │
│  • Zero upstream API keys or mTLS private keys in env, disk, or memory           │
│  • Zero default route to the public internet                                     │
└───────────────────┬──────────────────────────────────────────┬───────────────────┘
                    │ Zero-Token UDS Socket                    │ TCP / Inbound TLS (h2/http1.1)
                    │ (TransportBoundAuthenticator)            │ + X-EdgeGate-Token (Primary/Secondary SHA-256)
                    ▼                                          ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                              EdgeGate L7 Data Plane                              ║
║                                                                                  ║
║  0. Admin Control Plane & Obs. ──► /_edgegate/admin/{reload,secrets/rotate,      ║
║                                    audit,pools} (Constant-time Admin Token,      ║
║                                    fail-closed when unconfigured)                ║
║  1. Pre-Policy Path Validator  ──► Rejects .., %2e, %2f, %5c, \, %00, // (400)   ║
║  2. Workload Authenticator     ──► UDS Identity or Dual-Token SHA-256 (401)      ║
║  3. Deterministic L7 Router    ──► Longest-prefix + Host matching (403 on miss)  ║
║  4. Default-Deny Policy Engine ──► (org, workload, roles, route, method, pfx,    ║
║                                    required_headers, forbidden_query_params,     ║
║                                    per-rule max_body_bytes ceiling) (403 / 413)  ║
║  5. Token-Bucket Rate Limiter  ──► Per-workload RPS & burst enforcement (429)    ║
║  6. Egress DLP Payload Guard   ──► Scans bounded body for blocked_body_substrings║
║                                    before upstream dispatch (403, INV-19)        ║
║  7. Load Balancer & Breaker    ──► Weighted RR | LeastConn | ConsistentHash |    ║
║                                    EWMA + 3-State Breaker + Idempotent Failover  ║
║  8. Header Sanitizer & Secrets ──► Strips hop-by-hop & forged auth; enforces     ║
║                                    TTL (expires_at_epoch_s) & injects scoped     ║
║                                    (org_id, cred_ref) + W3C traceparent          ║
║  9. Connection Pool, mTLS/SSRF ──► Resolve-validate-connect IPv4/IPv6/mapped-v6  ║
║                                    Outbound TLS/mTLS (INV-18), HTTP/1.1 & HTTP/2 ║
║ 10. Response Guard & Hardening ──► Blocks secret reflection (502); applies       ║
║                                    strip_response_headers & inject_response_hdrs ║
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

## Capabilities Matrix (Milestones 1–9 / `v0.9.0`)

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

---

## Annotated Configuration Reference (`edgegate.toml`)

```toml
[server]
listen_addr = "0.0.0.0:8080"
max_request_body_bytes = 1048576   # Global 1 MiB cap enforced via http_body_util::Limited (413 on overflow)
connect_timeout_ms = 2000          # Upstream TCP + TLS + HTTP handshake timeout (504 on timeout)
response_timeout_ms = 10000        # Upstream response header timeout (504 on timeout)
drain_timeout_ms = 5000            # Graceful shutdown drain window for in_flight_requests (Milestone 5)
replay_buffer_size = 64            # Bounded flight-recorder ring buffer capacity for /_edgegate/replay
# Optional Admin Control Plane token (`admin_token` or 64-hex-char `admin_token_sha256`, Milestone 7).
# When omitted, all `/_edgegate/admin/*` endpoints fail closed.
admin_token_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Optional inbound TLS 1.2/1.3 termination with automatic ALPN `h2` and `http/1.1` negotiation (Milestone 5).
# Provide either `cert_pem` + `key_pem` inline OR `cert_path` + `key_path` on disk.
# [server.tls]
# cert_path = "/etc/edgegate/tls/server.crt"
# key_path = "/etc/edgegate/tls/server.key"

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
block_secret_reflection = true     # Blocks 502 Bad Gateway if upstream reflects injected secret in headers/body

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
allowed_jsonrpc_methods = ["tools/list", "tools/call", "resources/read"] # Optional JSON-RPC 2.0 / MCP tool allowlist (INV-22, Milestone 9)
rate_limit_rps = 100               # Optional token-bucket refill rate (requests/sec)
rate_limit_burst = 200             # Optional token-bucket burst capacity

[[secrets]]
org_id = "org-alpha"
credential_ref = "github_pat"
env = "EDGEGATE_GITHUB_PAT"        # Reads secret from host process environment (or use `value = "..."` for local dev)
expires_at_epoch_s = 4102444800    # Optional Unix epoch expiry timestamp; fails closed (403) when expired (Milestone 6)
```

---

## Quickstart & Operator CLI

```bash
# 1. Validate a configuration file without starting the server
cargo run -- validate --config edgegate.demo.toml

# 2. Start EdgeGate with 1-second zero-downtime hot-reload file watching
cargo run -- start --config edgegate.demo.toml --watch-interval-ms 1000

# 3. Inspect live health and telemetry counters via the Operator CLI
cargo run -- status --url http://127.0.0.1:8080

# 4. Inspect the sanitized flight-recorder replay buffer via the Operator CLI
cargo run -- replay --url http://127.0.0.1:8080

# 5. Inspect and verify the cryptographic SHA-256 hash-chained audit ledger via the Operator CLI
# (Reads EDGEGATE_ADMIN_TOKEN from environment when --admin-token is omitted; supports --ca-cert for verified HTTPS)
cargo run -- audit --url https://127.0.0.1:8080 --admin-token "$EDGEGATE_ADMIN_TOKEN" --ca-cert /etc/edgegate/tls/ca.crt

# 6. Run the interactive 5-scenario zero-secret security console demo
cargo run --example security_console_demo

# 7. Run the full unit, integration, and adversarial security test suite
cargo test --all-targets
```

---

## Live Security Console Demo (`security_console_demo`)

EdgeGate includes a self-contained, in-process 5-scenario interactive security console demo (`cargo run --example security_console_demo`) that spins up mock upstreams and an EdgeGate data plane on ephemeral loopback ports and walks through:
1. **Zero-Secret Scoped Credential Injection & MCP Tool Attribute Enforcement (`INV-05`, `INV-15`):** Authorized `sandbox-alpha` request with `x-mcp-tool: github.read_repo` succeeds (`200 OK`) with the upstream `Authorization: Bearer ...` secret injected on the wire, while an unapproved `x-mcp-tool: github.delete_repo` call is blocked (`403 Forbidden`).
2. **Zero-Downtime Dual Workload Token Rollover:** `sandbox-alpha` seamlessly authenticates with both its primary `token` and its rollover `secondary_token` during key rotation without dropping in-flight traffic.
3. **Live In-Memory Scoped Credential Rotation & TTL Expiry (`INV-14`):** Calls `EdgeGateProxy::rotate_secret` to rotate `github_pat` live in-memory (`secret_rotations_total` increments with zero config reload), then demonstrates fail-closed `403 Forbidden` rejection when a credential's `expires_at_epoch_s` TTL has elapsed.
4. **Adversarial Path Traversal & SSRF Defense (`INV-01`, `INV-07`):** Blocks encoded dot-segment traversal (`400 Bad Request`) and cloud metadata `169.254.169.254` SSRF probes (`403 Forbidden`).
5. **Defense-in-Depth Response Credential Reflection Guard (`INV-12`) & Flight-Recorder Replay (`INV-11`):** Triggers a simulated compromised upstream that reflects the injected secret in its response body, verifying that EdgeGate intercepts and blocks the leak with `502 Bad Gateway` (`secret_reflections_blocked_total`) and records a sanitized entry in `/_edgegate/replay`.

---

## Built-in Observability, Flight-Recorder & Authenticated Admin Control Plane Endpoints

EdgeGate exposes built-in, zero-secret diagnostic endpoints and an authenticated Admin Control Plane API (`X-EdgeGate-Admin-Token`, disabled fail-closed when `server.admin_token` / `server.admin_token_sha256` is unconfigured):

| Endpoint | Format | Description |
|---|---|---|
| `GET /_edgegate/healthz` | `application/json` | Returns liveness and active atomic `ArcSwap` configuration generation (`{"status":"ok","config_generation":1}`). |
| `GET /_edgegate/metrics` | `application/json` | Exposes lock-free atomic counters, gauges, and tamper-evident audit chain health: `allowed_total`, `blocked_total`, `dlp_blocked_total`, `bulkhead_rejected_total`, `jsonrpc_blocked_total`, `rate_limited_total`, `upstream_errors_total`, `retries_total`, `secret_reflections_blocked_total`, `secret_rotations_total`, `in_flight_requests`, `reloads_total`, `reload_failures_total`, `config_generation`, `shadow_requests_total`, `shadow_mismatches_total`, and `audit_chain_valid`. |
| `GET /_edgegate/metrics?format=prometheus` | `text/plain; version=0.0.4` | Exposes all EdgeGate telemetry counters (`edgegate_dlp_blocked_total`, `edgegate_bulkhead_rejected_total`, `edgegate_jsonrpc_blocked_total`, etc.), gauges (`edgegate_audit_chain_valid`), and lock-free microsecond request latency histogram buckets (`edgegate_request_duration_microseconds_bucket` across `100us`, `500us`, `1000us`, `5000us`, `10000us`, `50000us`, `+Inf`) in standard Prometheus text exposition format. |
| `GET /_edgegate/replay` | `application/json` | Returns the bounded flight-recorder ring buffer of recent `5xx`/`502`/`503`/`504` upstream failures, `secret_reflection_blocked` events, `dlp_payload_blocked` events, `jsonrpc_method_blocked` events, and `shadow_status_mismatch` events (strictly sanitized: zero headers, bodies, or credentials). |
| `POST /_edgegate/admin/reload` | `application/json` | Requires constant-time `X-EdgeGate-Admin-Token`. Atomically compiles and swaps a new TOML configuration payload without dropping in-flight connections (`403`/`401` when unconfigured or invalid token). |
| `POST /_edgegate/admin/secrets/rotate` | `application/json` | Requires constant-time `X-EdgeGate-Admin-Token`. Rotates a scoped `(org_id, credential_ref)` secret and optional `expires_at_epoch_s` TTL live in-memory (`secret_rotations_total`). |
| `GET /_edgegate/admin/audit` | `application/json` | Requires constant-time `X-EdgeGate-Admin-Token`. Returns the cryptographic SHA-256 hash-chained tamper-evident audit ledger (`prev_hash` -> `entry_hash` over every gateway decision, `INV-16`) along with full chain verification status. |
| `GET /_edgegate/admin/pools` | `application/json` | Requires constant-time `X-EdgeGate-Admin-Token`. Returns live pool and backend topology snapshots (`strategy`, `mtls_enabled`, per-backend `weight`, `active_healthy`, `circuit_state` (`closed`/`open`/`half_open`), `active_connections`, and `ewma_latency_us`). |

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

## Measured Local Benchmark

Reproducible localhost HTTP/1.1 keep-alive benchmark ([`examples/bench.rs`](examples/bench.rs)) executed via `cargo run --release --example bench` (32 concurrent workers × 500 requests = 16,000 requests against in-process mock upstreams on Apple Silicon loopback):

| Path | Throughput (`req/s`) | `p50` Latency | `p95` Latency | `p99` Latency |
|---|---:|---:|---:|---:|
| **Direct Upstream Baseline** | `125,826.6 req/s` | `231 µs` | `394 µs` | `586 µs` |
| **Via EdgeGate (Full Auth + RBAC + SSRF + Pool + Secret Injection)** | `27,458.3 req/s` | `1,142 µs` | `1,300 µs` | `1,376 µs` |
| **Added EdgeGate Overhead** | — | **`+911 µs` (`0.91 ms`)** | **`+906 µs` (`0.91 ms`)** | **`+790 µs` (`0.79 ms`)** |

*(Measured on local loopback against in-process mock upstreams to isolate proxy data-plane overhead; not a claim of WAN internet latency.)*

---

## Documentation & Architecture Decision Records

- [**Systems Architecture Guide (`ARCHITECTURE.md`)**](ARCHITECTURE.md)
- [**Security Policy & Enforced Invariants (`SECURITY.md`)**](SECURITY.md)
- [**Threat Model (`docs/THREAT_MODEL.md`)**](docs/THREAT_MODEL.md)
- [**Contributing & Engineering Standards (`CONTRIBUTING.md`)**](CONTRIBUTING.md)
- **Architecture Decision Records (`docs/adr/`):**
  - [**ADR-001:** Explicit L7 Reverse-Proxy Gateway Architecture](docs/adr/001-explicit-l7-gateway-architecture.md)
  - [**ADR-002:** Outbound TLS, Atomic Hot Reload, Zero-Token UDS Identity, RBAC & Active Health Probes](docs/adr/002-milestone-2-tls-hot-reload-uds-and-rbac.md)
  - [**ADR-003:** HTTP/2, Three-State Circuit Breakers, Consistent/Latency-Aware LB, Traffic Shadowing & Boxlet UDS](docs/adr/003-milestone-3-http2-circuit-breakers-shadowing-and-boxlet.md)
  - [**ADR-007:** Authenticated Admin Control Plane API, SHA-256 Tamper-Evident Audit Ledger, Weighted Canary LB, Query/Payload Resource Guards & Latency Histograms](docs/adr/007-milestone-7-admin-control-plane-hash-chained-audit-and-weighted-canary.md)
  - [**ADR-008:** Outbound Mutual TLS (mTLS) Client Authentication, Egress DLP Payload Guard, Programmable Response Header Hardening & Admin Pool Introspection](docs/adr/008-milestone-8-outbound-mtls-egress-dlp-response-hardening-and-pool-introspection.md)
  - [**ADR-009:** Workload Bulkheads, JSON-RPC 2.0 / MCP Tool Method Allowlists, Route Timeout SLAs & Protocol Hardening](docs/adr/009-milestone-9-workload-bulkheads-jsonrpc-mcp-allowlists-and-route-slas.md)

## License

Licensed under the [MIT License](LICENSE).
