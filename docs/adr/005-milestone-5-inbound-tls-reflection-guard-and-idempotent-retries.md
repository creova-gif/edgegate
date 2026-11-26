# ADR-005: Milestone 5 — Inbound TLS, Response Credential Reflection Guard, Controlled Idempotent Retries, and Graceful Draining
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
As EdgeGate transitions toward multi-node production deployments (`v0.5.0`), four operational and security hardening requirements emerged:
1. **Inbound TLS with HTTP/2 ALPN:** Remote workloads connecting over TCP across hosts or VPC boundaries require encrypted inbound transport (`rustls`) with negotiated HTTP/2 (`h2`) and HTTP/1.1 ALPN.
2. **Response Credential Reflection Guard:** Compromised, buggy, or debug-echoing upstream services could reflect the injected upstream credential back to the caller in response headers or response bodies, violating the zero-secret sandbox invariant.
3. **Controlled Idempotent Failover Retries:** Transient upstream connection failures (`502 Bad Gateway`) on read-only idempotent requests (`GET`, `HEAD`, `OPTIONS`) should optionally fail over to another healthy backend in the pool without ever retrying non-idempotent state-changing requests (`POST`, `PUT`, `DELETE`, `PATCH`).
4. **Graceful In-Flight Draining:** During rolling restarts or shutdown signals, EdgeGate must track active in-flight requests and wait up to a bounded `drain_timeout_ms` for in-flight requests to complete before exiting.

## Decision
1. **Inbound TLS (`server.tls`):**
   - Added optional `ServerTlsConfig` (`cert_pem`/`cert_path` and `key_pem`/`key_path`) to `ServerConfig`, compiled into an `Option<Arc<rustls::ServerConfig>>` with `alpn_protocols = ["h2", "http/1.1"]`.
   - When configured, `EdgeGateProxy::serve` wraps accepted TCP connections with `tokio_rustls::TlsAcceptor` prior to serving via `AutoConnBuilder`.
2. **Response Credential Reflection Guard (`block_secret_reflection`):**
   - Added `block_secret_reflection: bool` (default `false`) to `CredentialBindingConfig`.
   - When enabled on a route's credential binding, EdgeGate scans all upstream response header values and the buffered upstream response body for the raw secret bytes (`secret.expose().as_bytes()`).
   - If detected in headers or body, EdgeGate increments `secret_reflections_blocked_total`, appends a sanitized `ReplayRecord` (`reason = "credential_reflection_blocked"`), and returns `502 Bad Gateway` without leaking the upstream payload.
3. **Controlled Idempotent Failover Retries (`max_idempotent_retries`):**
   - Added `max_idempotent_retries: u32` (default `0`) to `PoolConfig`.
   - When `max_idempotent_retries > 0` and the request method is `GET`, `HEAD`, or `OPTIONS`, a `502 Bad Gateway` transport failure from `ConnectionPool::send` records a passive failure on the failed backend, increments `retries_total`, selects the next healthy backend via the pool's `LoadBalancer`, rewrites the `Host` header, and retries up to `max_idempotent_retries` times. Non-idempotent methods (`POST`, `PUT`, `DELETE`, `PATCH`) are never retried.
4. **Graceful In-Flight Request Draining (`drain_timeout_ms`):**
   - Added an RAII `InFlightGuard` in `handle_request_with_auth` backed by `Telemetry::in_flight_requests` (`AtomicU64`) and a bounded drain loop in `EdgeGateProxy::serve` after receiving the shutdown signal.

## Alternatives Considered
- **Streaming regex/aho-corasick body scrubbing for credential reflection:** Scrubbing or redacting secrets in-stream can corrupt structured JSON responses or leak partial prefixes across chunk boundaries. Failing closed with `502 Bad Gateway` on full-response inspection provides a deterministic security boundary.
- **Retrying all HTTP methods on connection reset:** Even a TCP reset during `POST` cannot guarantee the upstream did not process the request before closing the socket; restricting retries strictly to `GET`, `HEAD`, and `OPTIONS` preserves idempotency guarantees.

## Consequences & Failure Modes
- Enabling `block_secret_reflection = true` buffers the upstream response body in memory prior to downstream transmission so that reflection checks complete before headers/status are committed to the caller.
- If all backends in a pool fail during idempotent retry attempts, each failed attempt increments passive failure counters and `retries_total`, eventually tripping the circuit breaker and returning `502 Bad Gateway`.
