# EdgeGate

High-performance, programmable L7 reverse proxy and load balancer written in Rust that establishes a zero-secret network execution boundary for AI agents, sandboxes, and untrusted workloads.

> **Defining principle:** Untrusted workloads should be able to access explicitly authorized services without possessing the underlying upstream credentials or unrestricted outbound network authority.

## What Milestone 1 Proves

- **Explicit L7 HTTP/1.1 Reverse Proxy (`tokio` + `hyper` v1):** Hand-built routing, load balancing, bounded single-flight connection pooling, authentication, policy enforcement, and credential injection on top of `hyper` v1 HTTP/1.1 framing.
- **Zero-Secret Credential Injection:** Workloads hold zero upstream API keys. EdgeGate verifies the workload's scoped `X-EdgeGate-Token` (constant-time SHA-256 via `subtle`), enforces default-deny `(org_id, workload_id, route_id, method, path_prefix)` policies, strips client auth and RFC 9110 hop-by-hop headers, and injects scoped upstream credentials (`SecretProvider`) on the wire.
- **Load Balancing & Passive Health:** Both `RoundRobin` and `LeastConnections` (RAII `AtomicUsize` in-flight guard) behind `LoadBalancer`, with passive failure ejection cooldown on `502`/`504`/upstream `5xx` (never on local `503` pool exhaustion).
- **Structural Security Boundaries:**
  - Fail-closed pre-policy path validation (`400` on raw/encoded dot-segments, backslashes, null bytes, double slashes).
  - Never auto-follows `3xx` redirects (prevents cross-domain credential leakage and redirect SSRF).
  - Resolve-validate-connect SSRF guard blocking IPv4 loopback/RFC1918/metadata (`169.254.169.254`), IPv6 ULA/link-local, and IPv4-mapped IPv6 (`::ffff:169.254.169.254`) unless explicitly opted in for local test pools.
  - Single-flight HTTP/1.1 `SendRequest` checkout with `PooledBody` EOF-drain/`Drop` guard to prevent cross-tenant stream desynchronization.
- **Container Zero-Bypass Demo:** Docker Compose proof where an isolated sandbox runs on an `internal: true` network with zero upstream API keys and zero direct egress.

## Quickstart

```bash
# Validate configuration
cargo run -- validate --config edgegate.demo.toml

# Start EdgeGate
cargo run -- start --config edgegate.demo.toml

# Run unit + adversarial security tests
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

- **Architecture Decision Record:** [docs/adr/001-explicit-l7-gateway-architecture.md](docs/adr/001-explicit-l7-gateway-architecture.md)
- **Threat Model & Non-Goals:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- **Engineering Standards:** [AGENTS.md](AGENTS.md)

## Roadmap (Milestone 2+)

- Inbound and outbound TLS (`rustls`), HTTP/2, and HTTP/3.
- Atomic zero-downtime configuration hot reload (`ArcSwap<CompiledConfig>`).
- External secret manager integrations (GCP Secret Manager, Vault) behind `SecretProvider`.
- Transport-level workload identity (Unix domain sockets / sandbox runtime integration) behind `WorkloadAuthenticator`.
- Active health checks, circuit breakers, traffic shadowing/replay, and OpenTelemetry tracing.
