## Summary
<!-- Provide a concise description of the changes introduced by this pull request -->

## Security Invariants & Architectural Impact
- [ ] Invariant impacted (e.g., `INV-01` through `INV-23`)
- [ ] Architecture Decision Record (ADR) added or updated in `docs/adr/` (following `docs/adr/000-template.md`)
- [ ] Zero secret or credential reflection introduced
- [ ] Default-deny policy and SSRF protections preserved

## Code Quality & Engineering Standards
- [ ] **Zero `.unwrap()` or `.expect()` in `src/`:** All production code propagates `Result<T, EdgeGateError>` explicitly.
- [ ] **Poisoned lock recovery:** All `Mutex` acquisitions recover gracefully via `.into_inner()` rather than `.unwrap()`.
- [ ] **No inline imports:** All `use` statements are placed at the top of the module.
- [ ] **Exhaustive pattern matching:** Enums are matched exhaustively without wildcard `_ =>` catch-alls.

## Pre-PR Verification Gates
Verified locally:
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `git grep -n -E '\.(unwrap|expect)\(' -- src/` (returns zero occurrences)
- [ ] `cargo test --all-targets`
- [ ] `cargo run -- validate --config edgegate.demo.toml`

## Benchmarks & Performance
<!-- Required if modifying routing hot paths, connection pooling, or proxy forwarding -->
- [ ] `cargo run --release --example bench` executed and results recorded below:
<!-- Example:
Direct backend:  28,912.4 req/s | p50=812us p95=1240us p99=1820us
Via EdgeGate:    27,458.1 req/s | p50=845us p95=1310us p99=1950us
Added p95 overhead: 70us (0.070ms)
-->
