# ADR-001: Explicit L7 Reverse-Proxy Gateway Architecture for Milestone 1
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Untrusted workloads, sandboxes, and AI agents need access to external HTTP APIs without possessing raw upstream API keys or unrestricted internet egress. Conventional agent egress proxies intercept arbitrary internet traffic via `HTTP_PROXY` MITM TLS (`mitmproxy`), introducing CA certificate distribution complexity, arbitrary-destination DNS-rebinding SSRF risks, and high per-request latency. Meanwhile, general-purpose Rust proxy frameworks like Pingora abstract away core routing, load balancing, and connection-pool mechanics that EdgeGate aims to engineer from first principles.

## Decision
1. **Explicit L7 Gateway over MITM Forward Proxy:** In Milestone 1, EdgeGate operates as a declared HTTP/1.1 L7 reverse proxy over statically configured upstream pools (`edgegate.toml`), enforcing default-deny `(org_id, workload_id, route_id, method, path_prefix)` policies and injecting scoped upstream credentials on the wire.
2. **Single-Crate Linear Pipeline Core:** Implement a single Rust crate (`edgegate` lib + CLI binary) with 10 focused modules (`config`, `auth`, `policy`, `secrets`, `router`, `lb`, `pool`, `proxy`, `telemetry`, `main`) on `tokio` + `hyper` v1. Security ordering is enforced directly in a linear request pipeline rather than implicit middleware extension maps.
3. **Locked M1 Contracts:**
   - Workload identity authenticates via `X-EdgeGate-Token` (constant-time SHA-256 verification via `subtle`), resolving `WorkloadIdentity { workload_id, org_id }` (`roles` deferred to M2 RBAC). Both `X-EdgeGate-Token` and `Proxy-Authorization` are unconditionally stripped before upstream forwarding.
   - Load balancing implements both `RoundRobin` and `LeastConnections` (RAII `AtomicUsize` in-flight guard) behind `LoadBalancer`. Passive backend ejection triggers strictly on connect/transport (`502`), upstream timeout (`504`), and upstream `5xx` responses, never on local pool exhaustion (`503`).
   - Bounded HTTP/1.1 connection pool enforces resolve-validate-connect SSRF checks (IPv4, IPv6, and unwrapped IPv4-mapped IPv6), `is_closed()` stale-handle eviction, and single-flight `SendRequest` return only after full EOF body drain.
   - Outbound/inbound TLS (`rustls`), HTTP/2, HTTP/3, active health probes, automatic retries, hot-reload file watching, and Boxlet UDS transport are explicitly deferred to Milestone 2+.

## Alternatives Considered
- **Multi-Crate Workspace (`edgegate-core`, `edgegate-policy`, `edgegate-proxy`, `edgegate-cli`):** Rejected for Milestone 1 to avoid premature crate-plumbing overhead while interfaces stabilize; modules remain cleanly separated for future extraction.
- **Zero-Token Transport-Identity Gateway (Unix Domain Sockets):** Rejected as the sole Milestone 1 transport because UDS complicates standard TCP HTTP benchmarking and portable container demos; preserved via the `WorkloadAuthenticator` trait seam for Milestone 2 Boxlet integration.
- **Tower Middleware Stack:** Rejected because implicit `http::Extensions` ordering makes fail-closed security sequencing fragile compared to an explicit typed pipeline.

## Consequences & Failure Modes
- **Positive:** Eliminates MITM CA cert management and arbitrary-URL SSRF by construction; achieves clean single-flight HTTP/1.1 pool isolation and verifiable container zero-bypass proofs in Milestone 1.
- **Tradeoffs:** Workloads in Milestone 1 must target EdgeGate's explicit route prefixes and carry a scoped `X-EdgeGate-Token` (though zero upstream API keys).
- **Failure Modes Mitigated:** Path-traversal policy bypass (`400` fail-closed pre-policy rejection), `3xx` redirect credential leak (never auto-follow `3xx`), DNS rebinding TOCTOU (resolve-validate-connect directly to validated `SocketAddr`), cascading false ejection under burst load (local `503` excluded from passive health), and cross-tenant HTTP/1.1 stream desynchronization (`PooledBody` `Drop` guard).
