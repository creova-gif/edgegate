# EdgeGate

High-performance, programmable L7 reverse proxy and load balancer written in Rust that establishes a zero-secret network execution boundary for AI agents, sandboxes, and untrusted workloads.

> **Defining principle:** Untrusted workloads should be able to access explicitly authorized services without possessing the underlying upstream credentials or unrestricted outbound network authority.

## Capabilities (Milestones 1–3)

- **HTTP/1.1, HTTP/2 & Outbound HTTPS Reverse Proxy (`tokio` + `hyper` v1 + `rustls`):**
  - Inbound TCP and Unix domain socket listeners automatically serve both HTTP/1.1 and HTTP/2 (`h2c`).
  - Outbound pools support HTTP/1.1 single-flight pooling and multiplexed HTTP/2 (`http2 = true`, `h2` ALPN / `h2c`) over plaintext or encrypted `rustls` TLS 1.2/1.3 (`webpki-roots` + custom CA PEM verification).
- **Zero-Secret Credential Injection & Environment Secret Resolution:**
  - Workloads hold zero upstream API keys. EdgeGate resolves scoped secrets from config or host environment variables (`env = "VAR_NAME"`) and injects them on the wire after policy authorization.
- **Zero-Token Transport-Identity Unix Domain Sockets & Dynamic Boxlet Integration:**
  - Static `[[server.unix_listeners]]` and dynamic `EdgeGateProxy::register_boxlet_sandbox` bind per-sandbox Unix domain sockets directly to `(workload_id, org_id, roles)` so sandboxed workloads authenticate with **zero tokens in environment variables or memory**, with automatic RAII socket cleanup on drop.
- **Default-Deny Multi-Tenant & RBAC Policy Engine:**
  - Enforces `(org_id, workload_id, required_roles, route_id, method, path_prefix)` with constant-time SHA-256 token verification (`subtle`).
- **Four Load-Balancing Strategies & Three-State Circuit Breakers:**
  - `RoundRobin`, `LeastConnections` (RAII `AtomicUsize` in-flight guard), `ConsistentHash` (`X-EdgeGate-Routing-Key` or `workload_id`), and `LatencyAware` (lock-free atomic EWMA latency).
  - Three-state per-backend circuit breaker (`Closed` -> `Open` -> `HalfOpen` with single-flight trial probe) isolated from local `503` pool exhaustion, paired with background active HTTP health probes (`health_check_path`).
- **Atomic Zero-Downtime Configuration Hot Reload (`ArcSwap`):**
  - Validates and swaps `RuntimeSnapshot` atomically (`--watch-interval-ms` or programmatic reload) without dropping in-flight requests; invalid reload configs fail safe.
- **Traffic Shadowing & Sanitized Flight-Recorder Replay (`/_edgegate/replay`):**
  - Routes with `shadow_pool` asynchronously mirror sanitized traffic to canary pools and record status mismatches.
  - Bounded in-memory flight recorder (`/_edgegate/replay`) captures sanitized failure/mismatch metadata (zero secrets or payloads) alongside `/_edgegate/healthz` and `/_edgegate/metrics`.

## Quickstart

```bash
# Validate configuration
cargo run -- validate --config edgegate.demo.toml

# Start EdgeGate with 1s zero-downtime hot-reload file watching
cargo run -- start --config edgegate.demo.toml --watch-interval-ms 1000

# Run all unit, adversarial security, and Milestone 1-3 integration tests
cargo test --all-targets
```

## Container Zero-Bypass Demo

```bash
docker compose -f docker-compose.demo.yml up -d --build
./scripts/demo-verify.sh
docker compose -f docker-compose.demo.yml down
```

## Local Benchmark

Reproducible localhost HTTP/1.1 keep-alive benchmark (`cargo run --release --example bench`, 32 concurrent workers x 500 requests = 16,000 requests):

```text
Direct backend :   125826.6 req/s | p50=231us p95=394us p99=586us
Via EdgeGate   :    27458.3 req/s | p50=1142us p95=1300us p99=1376us
Added p95 overhead: 906us (0.906ms)
```

*(Measured on local loopback against in-process mock upstreams; not a claim of production internet WAN performance.)*

## Architecture & Documentation

- **ADR-001 (Milestone 1 Core Architecture):** [docs/adr/001-explicit-l7-gateway-architecture.md](docs/adr/001-explicit-l7-gateway-architecture.md)
- **ADR-002 (Milestone 2 TLS, Hot Reload, UDS & RBAC):** [docs/adr/002-milestone-2-tls-hot-reload-uds-and-rbac.md](docs/adr/002-milestone-2-tls-hot-reload-uds-and-rbac.md)
- **ADR-003 (Milestone 3 HTTP/2, Circuit Breakers, Shadowing & Boxlet):** [docs/adr/003-milestone-3-http2-circuit-breakers-shadowing-and-boxlet.md](docs/adr/003-milestone-3-http2-circuit-breakers-shadowing-and-boxlet.md)
- **Threat Model & Non-Goals:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- **Engineering Standards:** [AGENTS.md](AGENTS.md)
