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
1. **Zero Secrets in the Sandbox:** Workloads hold zero upstream API keys—and **zero bearer tokens of any kind** when connected over host-mounted or dynamically attached Unix domain sockets (`register_boxlet_sandbox`). EdgeGate authenticates the workload, evaluates a default-deny multi-tenant RBAC policy, strips forged/hop-by-hop headers, and injects the scoped upstream secret on the wire.
2. **Fail-Closed L7 Security Pipeline:** Every request passes through a linear, strongly-typed security pipeline that enforces pre-policy path normalization (`400`), constant-time SHA-256 token verification (`401`), multi-tenant RBAC policy evaluation (`403`), per-workload token-bucket rate limiting (`429`), resolve-validate-connect SSRF protection across IPv4/IPv6/mapped-IPv6 (`403`), and zero `3xx` redirect following.
3. **Production-Grade Resilience & Observability:** Features single-flight HTTP/1.1 connection pooling with RAII EOF-drain guards (`PooledBody`), multiplexed HTTP/2 (`h2` TLS ALPN & `h2c`), four load-balancing algorithms (`RoundRobin`, `LeastConnections`, `ConsistentHash`, `LatencyAware` EWMA), three-state circuit breakers (`Closed` -> `Open` -> `HalfOpen` single-flight probe), atomic zero-downtime hot reload (`ArcSwap`), W3C `traceparent` propagation, live traffic shadowing, and a sanitized flight-recorder replay buffer (`/_edgegate/replay`).

---

## Architecture Overview

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Untrusted AI Agent / Ephemeral Sandbox (Docker internal:true or Boxlet MicroVM)  │
│  • Zero upstream API keys in env, disk, or memory                                │
│  • Zero default route to the public internet                                     │
└───────────────────┬──────────────────────────────────────────┬───────────────────┘
                    │ Zero-Token UDS Socket                    │ TCP + X-EdgeGate-Token
                    │ (TransportBoundAuthenticator)            │ (SHA-256 ConstantTimeEq)
                    ▼                                          ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                              EdgeGate L7 Data Plane                              ║
║                                                                                  ║
║  1. Pre-Policy Path Validator  ──► Rejects .., %2e, %2f, %5c, \, %00, // (400)   ║
║  2. Workload Authenticator     ──► UDS Transport Identity or SHA-256 Token (401) ║
║  3. Deterministic L7 Router    ──► Longest-prefix + Host matching (403 on miss)  ║
║  4. Default-Deny RBAC Policy   ──► (org_id, workload, roles, route, method, pfx) ║
║  5. Token-Bucket Rate Limiter  ──► Per-workload RPS & burst enforcement (429)    ║
║  6. Load Balancer & Breaker    ──► RR | LeastConn | ConsistentHash | EWMA        ║
║                                    3-State Circuit Breaker (Closed/Open/HalfOpen)║
║  7. Header Sanitizer & Secrets ──► Strips hop-by-hop & forged auth; injects      ║
║                                    W3C traceparent + scoped (org_id, cred_ref)   ║
║  8. Connection Pool & SSRF     ──► Resolve-validate-connect IPv4/IPv6/mapped-v6  ║
║                                    HTTP/1.1 PooledBody guard & HTTP/2 (h2/h2c)   ║
╚═══════════════════╤══════════════════════════════════════════╤═══════════════════╝
                    │ Primary Dispatch                         │ Async Non-Blocking Mirror
                    ▼                                          ▼
     ┌─────────────────────────────┐            ┌─────────────────────────────┐
     │   Primary Upstream Pool     │            │   Optional Shadow Pool      │
     │ (HTTP/1.1, HTTP/2, rustls)  │            │ (Canary Status Diffing &    │
     └─────────────────────────────┘            │  Flight-Recorder Capture)   │
                                                └─────────────────────────────┘
```

For a deep dive into the internal state machines, connection pool invariants, and design trade-offs, see [**ARCHITECTURE.md**](ARCHITECTURE.md) and [**SECURITY.md**](SECURITY.md).

---

## Capabilities Matrix (Milestones 1–4)

| Milestone | Subsystem | Key Capabilities |
|---|---|---|
| **Milestone 1** | **Core L7 Proxy & Zero-Secret Boundary** | • Linear typed L7 pipeline (`tokio` + `hyper` v1) with fail-closed pre-policy path normalization<br>• Constant-time SHA-256 `X-EdgeGate-Token` authentication (`subtle::ConstantTimeEq`)<br>• Default-deny multi-tenant `(org_id, workload_id, route_id, method, path_prefix)` policy engine<br>• Scoped credential injection (`SecretValue` with `ZeroizeOnDrop` and redacted `Debug`/`Display`)<br>• Single-flight HTTP/1.1 connection pool (`PooledBody` EOF-drain guard) & resolve-validate-connect SSRF guard<br>• `RoundRobin` & `LeastConnections` load balancing with passive failure ejection isolated from local `503` |
| **Milestone 2** | **TLS, Hot Reload, Zero-Token UDS & RBAC** | • Outbound `rustls` TLS 1.2/1.3 (`webpki-roots` + custom per-pool `ca_cert_pem` & `tls_sni` override)<br>• Atomic zero-downtime configuration hot reload via wait-free `ArcSwap<RuntimeSnapshot>`<br>• Static zero-token Unix domain socket listeners (`[[server.unix_listeners]]`)<br>• Role-Based Access Control (`roles` / `required_roles`) & environment-backed secrets (`env = "VAR"`)<br>• Background active HTTP health probes (`health_check_path`) + `/_edgegate/healthz` & `/_edgegate/metrics` |
| **Milestone 3** | **HTTP/2, 3-State Breakers, Shadowing & Boxlet** | • Inbound HTTP/1.1 + HTTP/2 (`h2c`) auto-detection & outbound multiplexed HTTP/2 (`http2 = true`, ALPN `h2` / `h2c`)<br>• Explicit 3-state circuit breaker (`Closed` -> `Open` -> `HalfOpen` with single-flight trial probe)<br>• `ConsistentHash` (`X-EdgeGate-Routing-Key` / `workload_id`) & `LatencyAware` (lock-free atomic EWMA) load balancing<br>• Non-blocking asynchronous traffic shadowing (`shadow_pool`) with status-mismatch telemetry<br>• Bounded flight-recorder ring buffer (`/_edgegate/replay`) & dynamic Boxlet UDS registration (`register_boxlet_sandbox`) |
| **Milestone 4** | **Rate Limiting, Trace Context & Production Hardening** | • Per-workload lock-free token-bucket rate limiting (`rate_limit_rps`, `rate_limit_burst` -> `429 Too Many Requests`)<br>• W3C Trace Context (`traceparent`) validation, synthesis, and upstream/shadow propagation<br>• Prometheus text exposition (`GET /_edgegate/metrics/prometheus`) alongside JSON metrics<br>• Comprehensive systems architecture, security invariant verification, and benchmark harness |

---

## Annotated Configuration Reference (`edgegate.toml`)

```toml
[server]
listen_addr = "0.0.0.0:8080"
max_request_body_bytes = 1048576   # 1 MiB cap enforced via http_body_util::Limited (413 on overflow)
connect_timeout_ms = 2000          # Upstream TCP + TLS + HTTP handshake timeout (504 on timeout)
response_timeout_ms = 10000        # Upstream response header timeout (504 on timeout)
replay_buffer_size = 64            # Bounded flight-recorder ring buffer capacity for /_edgegate/replay

# Optional zero-token Unix domain socket listeners bound to specific workload identities.
# Workloads connecting via this socket need ZERO tokens in environment variables or headers.
[[server.unix_listeners]]
path = "/tmp/edgegate-agent-alpha.sock"
workload_id = "sandbox-alpha-uds"
org_id = "org-alpha"
roles = ["repo:read", "inference:call"]

# Token-authenticated workloads (specify either plaintext `token` for local dev or 64-hex-char `token_sha256`).
[[workloads]]
workload_id = "sandbox-alpha"
org_id = "org-alpha"
token_sha256 = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"
roles = ["repo:read", "inference:call"]
rate_limit_rps = 100               # Optional per-workload token-bucket refill rate (requests/sec)
rate_limit_burst = 200             # Optional per-workload token-bucket burst capacity

[[pools]]
name = "github-primary"
strategy = "latency_aware"         # "round_robin" | "least_connections" | "consistent_hash" | "latency_aware"
max_connections_per_upstream = 64  # Bounded per-backend Semaphore (returns local 503 when saturated)
idle_ttl_ms = 30000                # Idle HTTP/1.1 keep-alive eviction TTL
passive_failure_threshold = 3      # Consecutive 502/504/5xx failures before tripping Closed -> Open
passive_cooldown_ms = 5000         # Cooldown in Open state before admitting single-flight HalfOpen probe
allow_private_ip = false           # Keep false in production to enforce full IPv4/IPv6/mapped-v6 SSRF blocklist
health_check_path = "/healthz"     # Optional background active HTTP health probe path
health_check_interval_ms = 5000
backends = [
  { id = "gh-1", address = "api.github.com:443", tls = true, tls_sni = "api.github.com", http2 = true },
  { id = "gh-2", address = "api.github.com:443", tls = true, tls_sni = "api.github.com", http2 = true },
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
[routes.credential]
credential_ref = "github_pat"
header_name = "Authorization"      # Unconditionally stripped from incoming request before injection
value_prefix = "Bearer "

[[policies]]
org_id = "org-alpha"
workload_id = "sandbox-alpha"      # Optional; omit to match any workload within `org_id`
required_roles = ["repo:read"]     # All listed RBAC roles must be present on the authenticated workload
route_id = "github-api"
methods = ["GET", "POST"]
path_prefix = "/v1/github/repos"   # Segment-boundary-safe prefix check

[[secrets]]
org_id = "org-alpha"
credential_ref = "github_pat"
env = "EDGEGATE_GITHUB_PAT"        # Reads secret from host process environment (or use `value = "..."` for local dev)
```

---

## Quickstart

```bash
# 1. Validate a configuration file without starting the server
cargo run -- validate --config edgegate.demo.toml

# 2. Start EdgeGate with 1-second zero-downtime hot-reload file watching
cargo run -- start --config edgegate.demo.toml --watch-interval-ms 1000

# 3. Run the full unit, integration, and adversarial security test suite
cargo test --all-targets
```

---

## Built-in Observability & Flight-Recorder Endpoints

EdgeGate exposes built-in, zero-secret diagnostic endpoints directly on the proxy listener:

| Endpoint | Format | Description |
|---|---|---|
| `GET /_edgegate/healthz` | `application/json` | Returns liveness and active atomic `ArcSwap` configuration generation (`{"status":"ok","config_generation":1}`). |
| `GET /_edgegate/metrics` | `application/json` | Exposes lock-free atomic counters: `allowed_total`, `blocked_total`, `rate_limited_total`, `upstream_errors_total`, `reloads_total`, `reload_failures_total`, `config_generation`, `shadow_requests_total`, and `shadow_mismatches_total`. |
| `GET /_edgegate/metrics/prometheus` | `text/plain; version=0.0.4` | Exposes all EdgeGate telemetry counters in standard Prometheus text exposition format. |
| `GET /_edgegate/replay` | `application/json` | Returns the bounded flight-recorder ring buffer of recent `5xx`/`502`/`503`/`504` upstream failures and `shadow_status_mismatch` events (strictly sanitized: zero headers, bodies, or credentials). |

---

## Container Zero-Bypass Demo

EdgeGate ships with a reproducible multi-container Docker Compose topology ([`docker-compose.demo.yml`](file:///Users/justinmafie/Documents/antigravity/edgegate/docker-compose.demo.yml) and [`scripts/demo-verify.sh`](file:///Users/justinmafie/Documents/antigravity/edgegate/scripts/demo-verify.sh)) that places a sandbox container onto an isolated `internal: true` network with zero upstream API keys and verifies:
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

Reproducible localhost HTTP/1.1 keep-alive benchmark ([`examples/bench.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/examples/bench.rs)) executed via `cargo run --release --example bench` (32 concurrent workers × 500 requests = 16,000 requests against in-process mock upstreams on Apple Silicon loopback):

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

## License

Licensed under the [MIT License](LICENSE).
