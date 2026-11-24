# ADR-002: Milestone 2 — Outbound TLS, Atomic Hot Reload, Zero-Token UDS Identity, RBAC, and Active Health Probes
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Milestone 1 proved EdgeGate's core HTTP/1.1 L7 reverse-proxy pipeline, default-deny `org_id` policy engine, bounded single-flight connection pool, SSRF guard, and container zero-bypass boundary. To graduate toward production and sandbox-runtime workloads, Milestone 2 needs encrypted upstream transport (HTTPS/TLS), zero-downtime configuration reloads, transport-bound workload identity that removes even the gateway bearer token from inside sandboxes, role-based access control (`roles`), environment-backed secret resolution, and active upstream health probing.

## Decision
1. **Outbound TLS (`rustls` + `tokio-rustls` + `webpki-roots`):**
   - Backends may enable `tls = true` (with optional `tls_sni` override and pool-level `ca_cert_pem` for private/internal PKI).
   - `ConnectionPool` dials the SSRF-validated `SocketAddr`, completes a `rustls` TLS handshake verifying the server certificate against Mozilla root CAs (`webpki-roots`) plus any configured custom CA PEM, and runs `hyper` v1 HTTP/1.1 over the encrypted stream.
2. **Atomic Zero-Downtime Hot Reload (`ArcSwap<RuntimeSnapshot>`):**
   - `EdgeGateProxy::reload_from_file` and `reload_from_toml_str` compile and validate a candidate `CompiledConfig`, build a fresh `RuntimeSnapshot`, and atomically swap it via `ArcSwap::store`.
   - In-flight requests hold an `Arc<RuntimeSnapshot>` guard and complete undisturbed; invalid reload configs fail safe without mutating the active snapshot.
3. **Zero-Token Transport-Identity Unix Domain Socket Listeners:**
   - `server.unix_listeners` binds dedicated per-workload Unix domain sockets (`path`, `workload_id`, `org_id`, `roles`).
   - Connections accepted on a UDS listener carry pre-verified transport identity (`TransportIdentity`) so workloads inside a sandbox or Boxlet container require **zero tokens in environment variables or memory**.
4. **RBAC (`roles` / `required_roles`) & Environment-Backed Secrets:**
   - `WorkloadIdentity` carries `roles: HashSet<String>` and `PolicyRuleConfig` supports `required_roles` (all listed roles must be present).
   - `SecretEntryConfig` supports `env = "ENV_VAR"` in addition to inline `value` so EdgeGate can read secrets injected by host secret managers at startup/reload without storing raw secrets in `edgegate.toml`.
5. **Active HTTP Health Probes & Built-in Observability Endpoints:**
   - Pools with `health_check_path` run a background probe task that marks backends healthy/unhealthy alongside passive failure ejection.
   - Built-in `/_edgegate/healthz` and `/_edgegate/metrics` endpoints expose liveness, active config generation, and atomic allow/deny/error/reload counters.

## Alternatives Considered
- **OpenSSL / native-tls for Outbound TLS:** Rejected in favor of pure-Rust `rustls` (`ring` crypto provider) for memory safety and static container builds.
- **Read-Write Lock (`RwLock<RuntimeSnapshot>`) for Hot Reload:** Rejected in favor of `ArcSwap` so hot-path request reads remain wait-free under concurrent reloads.

## Consequences & Failure Modes
- **Positive:** Eliminates gateway bearer tokens inside UDS-connected sandboxes, supports encrypted upstream APIs, and enables zero-dropped-request policy/route updates.
- **Failure Modes Mitigated:** Bad reload config (rejected before swap; `reload_failures_total` incremented), invalid upstream TLS certificate or SNI mismatch (fails closed with `502 Bad Gateway` and increments passive failure counter), stale UDS socket file on restart (cleaned up safely before bind).
