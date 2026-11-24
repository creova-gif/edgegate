# EdgeGate Threat Model (Milestone 1 & Milestone 2)

## 1. Security Objective
Allow untrusted workloads (AI agents, sandboxed code, isolated containers) to call explicitly authorized HTTP/HTTPS upstream services without possessing the underlying upstream API credentials or unrestricted outbound network authority.

## 2. Assets
- **Upstream API credentials:** Scoped secrets held inside EdgeGate (`SecretProvider`, backed by process environment or config) and injected only into authorized outbound requests.
- **Tenant, role, & organizational boundaries (`org_id`, `roles`):** Strict isolation ensuring a workload in `org_a` cannot access routes, roles, credentials, or pooled HTTP/1.1 response bytes belonging to `org_b`.
- **Workload identity (`X-EdgeGate-Token` or transport-bound Unix Domain Socket):** Scoped gateway identity tokens (never forwarded upstream) or zero-token host-mounted UDS listeners where identity comes from the socket boundary itself.
- **Audit & authorization logs:** Structured JSON records of allow/deny decisions that must never contain raw credentials or sensitive headers.

## 3. Trust Boundaries
```text
[Untrusted Sandbox Container / Boxlet Workload]
   (sandbox-net: internal=true OR mounted Unix domain socket, zero upstream API keys)
              │
              │  HTTP/1.1 over UDS (zero tokens) OR TCP + X-EdgeGate-Token
              ▼
   ╔═════════════════════════╗
   ║     EdgeGate Gateway    ║  <-- Enforces parse, path validation, auth/UDS identity,
   ║   (trusted choke point) ║      RBAC policy, SSRF guard, header strip, credential
   ╚═════════════════════════╝      injection, no-redirect, bounded single-flight pooling
              │
              │  HTTP/1.1 or HTTPS (rustls TLS 1.2/1.3 + SNI/CA verification)
              ▼  + injected scoped credential
   [Declared Upstream Pool]
```

## 4. Threats & Mitigations

| Threat Class | Attack Vector | Mitigation |
|---|---|---|
| **Direct egress bypass** | Compromised sandbox calls upstream or public internet directly, bypassing EdgeGate. | Container runs on Docker `internal: true` network (or UDS-only mount) with no default route; only EdgeGate bridges `sandbox-net` and `upstream-net`. |
| **Credential leakage via env/fs** | Prompt injection or RCE reads environment variables or disk inside sandbox. | Sandbox holds zero upstream API keys (and zero tokens of any kind when connected via `server.unix_listeners`); EdgeGate injects scoped credentials on the wire after policy authorization. |
| **Path-traversal policy bypass** | Client sends `/v1/allowed/../secret`, `/%2e%2e/`, backslashes `\`, `%00`, or `//` to evade `path_prefix` rules. | Fail-closed pre-policy path validator (`src/router.rs`) rejects raw/encoded dot-segments, backslashes, null bytes, and double slashes with `400 Bad Request`. |
| **Cross-tenant (`org_id`) & RBAC escalation** | Workload from `org_a` calls a route belonging to `org_b`, or lacks `required_roles`. | Default-deny `PolicyEngine` (`src/policy.rs`) binds every rule and `SecretProvider` lookup to the authenticated `org_id`, `workload_id`, and `required_roles`. |
| **Timing side-channel on auth** | Attacker probes `X-EdgeGate-Token` character-by-character. | Pre-hashed SHA-256 token digests verified with `subtle::ConstantTimeEq` (`src/auth.rs`). |
| **Auth/hop-by-hop header smuggling** | Client supplies forged `Authorization`/`X-Api-Key`, `Proxy-Authorization`, or `Connection`-listed headers. | Unconditionally strips `X-EdgeGate-Token`, `Proxy-Authorization`, RFC 9110 hop-by-hop headers (plus `Connection`-listed names), and the route's target credential header before injection; rewrites `Host` to backend authority. |
| **Redirect credential leak & SSRF** | Authorized upstream returns `302 Location: http://attacker/` or `http://169.254.169.254/`. | EdgeGate never automatically follows `3xx` redirects; the `3xx` is returned directly to the caller with zero credential re-injection. |
| **DNS rebinding & metadata SSRF** | Backend hostname resolves to loopback, RFC1918, cloud metadata (`169.254.169.254`), IPv6 ULA/link-local, or IPv4-mapped IPv6 (`::ffff:169.254.169.254`). | Resolve-validate-connect (`src/pool.rs`): resolves via `tokio::net::lookup_host`, checks every IPv4/IPv6/unwrapped IPv4-mapped IPv6 address against the blocklist (unless `allow_private_ip = true` is explicitly configured for local fixtures), and dials the validated `SocketAddr` directly. |
| **Upstream MITM / rogue TLS certificate** | Attacker intercepts outbound traffic or spoofs upstream certificate. | Outbound `rustls` TLS (`src/pool.rs`) verifies server certificates and SNI against Mozilla root CAs (`webpki-roots`) and optional pool-pinned `ca_cert_pem`, failing closed (`502`) on mismatch. |
| **HTTP/1.1 stream desync / cross-tenant leak** | Client disconnects mid-response or upstream sends `Connection: close`; dirty socket is reused by another tenant. | Single-flight `SendRequest` checkout with `PooledBody` `Drop` guard (`src/pool.rs`): returns handle only after full EOF drain, `!Connection: close`, and `is_ready()`; otherwise drops socket immediately. |
| **Bad configuration reload outage** | Operator writes invalid TOML during live config reload. | `reload_from_file` validates the full `CompiledConfig` before swapping `ArcSwap<RuntimeSnapshot>`; invalid reloads increment `reload_failures_total` and leave the active snapshot untouched. |
| **Log secret leakage** | Raw credentials printed via `Debug`, `Display`, or structured request logs. | `SecretValue` wraps bytes in `ZeroizeOnDrop` with redacted `Debug` (`"[REDACTED]"`). Structured JSON logs emit only metadata. |

## 5. Explicit Non-Goals & Residual Risks
- **Malicious upstream credential reflection:** Response scrubbing alone cannot guarantee credential confidentiality if a compromised upstream deliberately reflects or encodes an injected secret inside a response body.
- **HTTP/2 & HTTP/3 multiplexing:** Deferred to Milestone 3.
- **Host/container escape:** Container kernel isolation is enforced by Docker/Linux or Boxlet, outside EdgeGate's process boundary.
