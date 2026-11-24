# EdgeGate

High-performance, programmable L7 reverse proxy and load balancer written in Rust that establishes a zero-secret network execution boundary for AI agents, sandboxes, and untrusted workloads.

> **Defining principle:** Untrusted workloads should be able to access explicitly authorized services without possessing the underlying upstream credentials or unrestricted outbound network authority.

## Capabilities (Milestone 1 & Milestone 2)

- **Explicit L7 HTTP/1.1 & Outbound HTTPS Reverse Proxy (`tokio` + `hyper` v1 + `rustls`):** Hand-built routing, load balancing, bounded single-flight connection pooling, authentication, policy enforcement, and credential injection over plaintext HTTP/1.1 and encrypted `rustls` HTTPS (`webpki-roots` + custom CA PEM verification).
- **Zero-Secret Credential Injection & Environment Secret Resolution:** Workloads hold zero upstream API keys. EdgeGate resolves scoped secrets from inline config or host environment variables (`env = "VAR_NAME"`) and injects them on the wire after policy authorization.
- **Zero-Token Transport-Identity Unix Domain Sockets (`server.unix_listeners`):** Sandboxes or Boxlet containers mounted to a dedicated per-workload UDS socket authenticate via the transport boundary itself with **zero tokens in environment variables or memory**.
- **Default-Deny Multi-Tenant & RBAC Policy Engine:** Enforces `(org_id, workload_id, required_roles, route_id, method, path_prefix)` with constant-time SHA-256 token verification (`subtle`).
- **Atomic Zero-Downtime Configuration Hot Reload (`ArcSwap`):** Validates and swaps `RuntimeSnapshot` atomically (`--watch-interval-ms` or programmatic reload) without dropping in-flight requests; invalid reload configs fail safe.
- **Load Balancing, Passive Ejection & Active HTTP Health Probes:** `RoundRobin` and `LeastConnections` (RAII `AtomicUsize` in-flight guard) with passive failure ejection cooldown (excluding local `503` pool exhaustion) and background active HTTP health probes (`health_check_path`).
- **Built-in Observability Endpoints:** `/_edgegate/healthz` and `/_edgegate/metrics` exposing config generation and atomic allow/block/error/reload counters alongside structured JSON audit logs.

## Quickstart

```bash
# Validate configuration
cargo run -- validate --config edgegate.demo.toml

# Start EdgeGate with 1s zero-downtime hot-reload file watching
cargo run -- start --config edgegate.demo.toml --watch-interval-ms 1000

# Run all unit, adversarial security, and Milestone 2 integration tests
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
- **Threat Model & Non-Goals:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- **Engineering Standards:** [AGENTS.md](AGENTS.md)
