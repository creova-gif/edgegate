# Contributing to EdgeGate

Thank you for contributing to EdgeGate. Because EdgeGate operates as a security-critical Layer 7 network execution boundary and credential isolation layer, all contributions must adhere to the engineering standards defined in [AGENTS.md](AGENTS.md).

---

## 1. Development Setup

### Prerequisites
- **Rust Toolchain:** Stable Rust 1.80+ with `rustfmt` and `clippy`:
  ```bash
  rustup update stable
  rustup component add rustfmt clippy
  ```
- **Operating System:** Linux or macOS (macOS Darwin and Linux x86_64/aarch64 are supported natively).
- **Optional Tools:** `curl`, `jq`, and OpenSSL (for generating test certificates).

### Building and Testing
Clone the repository and build in debug mode:
```bash
git clone https://github.com/creova-gif/edgegate.git
cd edgegate
cargo build
```

Run the complete test suite:
```bash
cargo test --all-targets
```

Validate a configuration file:
```bash
cargo run -- validate --config edgegate.demo.toml
```

---

## 2. Engineering Standards

### Rust Code Quality & Panic-Free Production Paths
- **Zero `.unwrap()` or `.expect()` in production paths (`src/`):**
  All runtime errors in `src/` must be propagated explicitly using `Result<T, EdgeGateError>` and mapped cleanly to HTTP status codes via `EdgeGateError::status_code()`. Never call `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, or `unreachable!()` in non-test production code. Any use of `.unwrap()` or `.expect()` is strictly restricted to unit tests inside `#[cfg(test)]` modules or integration test fixtures under `tests/`.
- **Poisoned Lock Recovery:**
  If a `std::sync::Mutex` is used for bounded runtime metadata (such as the idle connection pool, circuit breaker states, token bucket, or flight-recorder ring buffer), recover gracefully from poisoned locks via `match lock.lock() { Ok(g) => g, Err(poisoned) => poisoned.into_inner() }` rather than `.unwrap()`.
- **No Inline Imports:**
  Place all `use` statements at the top of the module. Never use inline imports inside function bodies or struct definitions.
- **Exhaustive Matching:**
  Match exhaustively over enums (`EdgeGateError`, `LbStrategyConfig`, `CircuitState`, `PolicyDecision`) without wildcard `_ =>` fallbacks so that newly added variants trigger compile-time errors until explicitly handled.

### Architecture Decision Records (ADRs)
Every non-trivial architectural or security design change must be recorded in [docs/adr/](docs/adr/) using [docs/adr/000-template.md](docs/adr/000-template.md). Existing ADRs include:
- [001-explicit-l7-gateway-architecture.md](docs/adr/001-explicit-l7-gateway-architecture.md): Explicit L7 Gateway Architecture & Zero-Secret Boundary
- [002-milestone-2-tls-hot-reload-uds-and-rbac.md](docs/adr/002-milestone-2-tls-hot-reload-uds-and-rbac.md): Inbound/Outbound TLS, ArcSwap Hot Reload, UDS Listeners, and RBAC
- [003-milestone-3-http2-circuit-breakers-shadowing-and-boxlet.md](docs/adr/003-milestone-3-http2-circuit-breakers-shadowing-and-boxlet.md): HTTP/2 Multiplexing, Circuit Breakers, Shadowing, and Boxlet UDS
- [004-milestone-4-rate-limiting-w3c-tracing-and-prometheus.md](docs/adr/004-milestone-4-rate-limiting-w3c-tracing-and-prometheus.md): Token-Bucket Rate Limiting, W3C Traceparent, and Prometheus Metrics
- [005-milestone-5-inbound-tls-reflection-guard-and-idempotent-retries.md](docs/adr/005-milestone-5-inbound-tls-reflection-guard-and-idempotent-retries.md): Inbound TLS Termination, Credential Reflection Guard, and Idempotent Retries
- [006-milestone-6-credential-rotation-attribute-policies-and-cli-replay.md](docs/adr/006-milestone-6-credential-rotation-attribute-policies-and-cli-replay.md): Credential Rotation, Header Attribute Policies, and CLI Replay
- [007-milestone-7-admin-control-plane-hash-chained-audit-and-weighted-canary.md](docs/adr/007-milestone-7-admin-control-plane-hash-chained-audit-and-weighted-canary.md): Authenticated Control Plane, Tamper-Evident SHA-256 Ledger, and Weighted Canary
- [008-milestone-8-outbound-mtls-egress-dlp-response-hardening-and-pool-introspection.md](docs/adr/008-milestone-8-outbound-mtls-egress-dlp-response-hardening-and-pool-introspection.md): Outbound mTLS, Egress DLP Payload Filtering, Response Header Hardening, and Pool Introspection
- [009-milestone-9-workload-bulkheads-jsonrpc-mcp-allowlists-and-route-slas.md](docs/adr/009-milestone-9-workload-bulkheads-jsonrpc-mcp-allowlists-and-route-slas.md): Workload Bulkheads, JSON-RPC 2.0 / MCP Tool Allowlists, Route SLAs, and CLI Hardening
- [010-milestone-10-v1-ga-hmac-request-signing-streaming-bulkheads-and-oss-packaging.md](docs/adr/010-milestone-10-v1-ga-hmac-request-signing-streaming-bulkheads-and-oss-packaging.md): Outbound HMAC-SHA256 Request Signing, Stream-Lifetime Bulkheads, and v1.0.0 GA Hardening

### Security & Secret Hygiene
- Never commit `.env` files, production API tokens, private keys, or PII/PHI test fixtures.
- All test certificates and tokens in `tests/` must be ephemeral, self-signed, or synthetic test fixtures generated in memory.

---

## 3. Pre-PR Verification Gates

Every pull request must pass the following verification gates cleanly before merge:

```bash
# 1. Check code formatting
cargo fmt --all -- --check

# 2. Run Clippy with all warnings promoted to errors
cargo clippy --all-targets -- -D warnings

# 3. Verify zero .unwrap() or .expect() in production library/binary paths
#    (Must return 0 hits across src/)
git grep -n -E '\.(unwrap|expect)\(' -- src/

# 4. Run the complete test suite
cargo test --all-targets

# 5. Validate the reference demo configuration
cargo run -- validate --config edgegate.demo.toml
```

---

## 4. Running Benchmarks & Demos

### Local Reproducible Benchmark
Never claim throughput or latency metrics without running the reproducible benchmark harness:
```bash
cargo run --release --example bench
```
This runs an in-process mock upstream server and an EdgeGate proxy on loopback across 32 concurrent keep-alive workers (16,000 total requests) and compares direct upstream latency vs. proxied latency (`p50`, `p95`, `p99`, and `req/s`).

### Security Console Demo
Run the end-to-end security verification console demo showcasing zero-secret injection, tenant boundary isolation, egress DLP, and reflection defense:
```bash
cargo run --example security_console_demo
```

### Cryptographic Audit Ledger Verification
To verify the SHA-256 hash-chained audit ledger of a running EdgeGate gateway:
```bash
# Set your admin token
export EDGEGATE_ADMIN_TOKEN="adm_live_secret_token_123"

# Verify against HTTPS gateway
cargo run -- audit --url https://127.0.0.1:8443 --ca-cert certs/ca.pem
```

---

## 5. Issue & Pull Request Guidelines

### Reporting Bugs
- Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml) template.
- Provide a minimal redacted configuration snippet, reproduction steps, and relevant log/audit outputs.
- Redact all real secrets, bearer tokens, and private keys.

### Proposing Features
- Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml) template.
- Explain the motivating problem, proposed TOML configuration schema, and impact on EdgeGate's security and threat model.

### Pull Requests
- Follow the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
- Ensure all CI gates pass, code quality requirements are met, and an ADR is included for architectural changes.
- Write clear conventional commit messages (e.g., `feat(signing): implement outbound HMAC-SHA256 request signing INV-23`).
