# Contributing to EdgeGate

Thank you for contributing to EdgeGate. Because EdgeGate operates as a security-critical L7 network execution boundary, all contributions must adhere to the engineering standards defined in [`AGENTS.md`](file:///Users/justinmafie/Documents/antigravity/edgegate/AGENTS.md).

---

## 1. Engineering Standards

### Rust Code Quality & Panic-Free Production Paths
- **Zero `.unwrap()` or `.expect()` in production paths (`src/`):**
  All runtime errors in `src/` must be propagated explicitly using `Result<T, EdgeGateError>` and mapped cleanly to HTTP status codes via `EdgeGateError::status_code()`. Never call `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, or `unreachable!()` in non-test production code.
- **Poisoned Lock Recovery:**
  If a `std::sync::Mutex` is used for bounded metadata (such as the idle HTTP/1.1 connection queue, circuit breaker state, token bucket, or flight-recorder ring buffer), recover gracefully from poisoned locks via `match lock.lock() { Ok(g) => g, Err(poisoned) => poisoned.into_inner() }` rather than `.unwrap()`.
- **No Inline Imports:**
  Place all `use` statements at the top of the module.
- **Exhaustive Matching:**
  Match exhaustively over enums (`EdgeGateError`, `LbStrategyConfig`, `CircuitState`, `PolicyDecision`) so newly added variants trigger compile-time errors until handled.

### Architecture Decision Records (ADRs)
- Every non-trivial architectural or security design change must be recorded in [`docs/adr/`](file:///Users/justinmafie/Documents/antigravity/edgegate/docs/adr) using [`docs/adr/000-template.md`](file:///Users/justinmafie/Documents/antigravity/edgegate/docs/adr/000-template.md):
  - [`001-explicit-l7-gateway-architecture.md`](file:///Users/justinmafie/Documents/antigravity/edgegate/docs/adr/001-explicit-l7-gateway-architecture.md)
  - [`002-milestone-2-tls-hot-reload-uds-and-rbac.md`](file:///Users/justinmafie/Documents/antigravity/edgegate/docs/adr/002-milestone-2-tls-hot-reload-uds-and-rbac.md)
  - [`003-milestone-3-http2-circuit-breakers-shadowing-and-boxlet.md`](file:///Users/justinmafie/Documents/antigravity/edgegate/docs/adr/003-milestone-3-http2-circuit-breakers-shadowing-and-boxlet.md)

### Security & Secret Hygiene
- Never commit `.env` files, real API keys, private keys, or PII/PHI test fixtures.
- Any test certificates or tokens used in `tests/` must be ephemeral, self-signed, or synthetic test fixtures generated in-memory or clearly marked as mock demo values.

---

## 2. Pre-PR Verification Checklist

Every pull request must pass the following verification gates cleanly before merge:

```bash
# 1. Check formatting
cargo fmt --all -- --check

# 2. Run Clippy with all warnings promoted to errors
cargo clippy --all-targets -- -D warnings

# 3. Verify zero .unwrap() or .expect() in production library/binary paths
#    (Any occurrences must exist strictly inside #[cfg(test)] modules)
git grep -n -E '\.(unwrap|expect)\(' -- src/

# 4. Run the complete unit, integration, and adversarial test suite
cargo test --all-targets

# 5. Validate demo configuration
cargo run -- validate --config edgegate.demo.toml
```

---

## 3. Running Benchmarks

Never claim throughput or latency numbers without running the reproducible benchmark harness and reporting the exact workload parameters:

```bash
cargo run --release --example bench
```

This starts an in-process mock upstream server and an EdgeGate instance on local loopback and compares direct upstream latency vs. proxied EdgeGate latency (`p50`, `p95`, `p99`, and `req/s`) across 32 concurrent keep-alive workers (16,000 requests total).
