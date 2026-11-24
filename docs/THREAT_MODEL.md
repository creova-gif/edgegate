# EdgeGate Threat Model (Milestone 1)

## 1. Security Objective
Allow untrusted workloads (AI agents, sandboxed code, isolated containers) to call explicitly authorized HTTP upstream services without possessing the underlying upstream API credentials or unrestricted outbound network authority.

## 2. Assets
- **Upstream API credentials:** Scoped secrets held inside EdgeGate (`SecretProvider`) and injected only into authorized outbound requests.
- **Tenant & organizational boundaries (`org_id`):** Strict isolation ensuring a workload in `org_a` cannot access routes, credentials, or pooled HTTP/1.1 response bytes belonging to `org_b`.
- **Workload authentication tokens (`X-EdgeGate-Token`):** Scoped gateway identity tokens (never forwarded upstream).
- **Audit & authorization logs:** Structured JSON records of allow/deny decisions that must never contain raw credentials or sensitive headers.

## 3. Trust Boundaries
```text
[Untrusted Sandbox Container]
   (sandbox-net: internal=true, zero upstream API keys, no default internet route)
              │
              │  HTTP/1.1 + X-EdgeGate-Token (untrusted input)
              ▼
   ╔═════════════════════════╗
   ║     EdgeGate Gateway    ║  <-- Enforces parse, path validation, auth, policy,
   ║   (trusted choke point) ║      SSRF guard, header strip, credential injection,
   ╚═════════════════════════╝      no-redirect, bounded single-flight pooling
              │
              │  HTTP/1.1 + injected scoped credential (M1 plaintext to local/mock upstreams;
              ▼  M2 rustls HTTPS to external upstreams)
   [Declared Upstream Pool]
```

## 4. Threats & Milestone 1 Mitigations

| Threat Class | Attack Vector | Milestone 1 Mitigation |
|---|---|---|
| **Direct egress bypass** | Compromised sandbox calls upstream or public internet directly, bypassing EdgeGate. | Container runs on Docker `internal: true` network with no default route; only EdgeGate bridges `sandbox-net` and `upstream-net`. |
| **Credential leakage via env/fs** | Prompt injection or RCE reads environment variables or disk inside sandbox. | Sandbox holds zero upstream API keys; EdgeGate injects scoped credentials on the wire after policy authorization. |
| **Path-traversal policy bypass** | Client sends `/v1/allowed/../secret`, `/%2e%2e/`, backslashes `\`, `%00`, or `//` to evade `path_prefix` rules. | Fail-closed pre-policy path validator (`src/router.rs`) rejects raw/encoded dot-segments, backslashes, null bytes, and double slashes with `400 Bad Request`. |
| **Cross-tenant (`org_id`) access** | Workload from `org_a` calls a route or credential belonging to `org_b`. | Default-deny `PolicyEngine` (`src/policy.rs`) binds every rule and `SecretProvider` lookup to the authenticated `org_id`. |
| **Timing side-channel on auth** | Attacker probes `X-EdgeGate-Token` character-by-character. | Pre-hashed SHA-256 token digests verified with `subtle::ConstantTimeEq` (`src/auth.rs`). |
| **Auth/hop-by-hop header smuggling** | Client supplies forged `Authorization`/`X-Api-Key`, `Proxy-Authorization`, or `Connection`-listed headers. | Unconditionally strips `X-EdgeGate-Token`, `Proxy-Authorization`, RFC 9110 hop-by-hop headers (plus `Connection`-listed names), and the route's target credential header before injection; rewrites `Host` to backend authority. |
| **Redirect credential leak & SSRF** | Authorized upstream returns `302 Location: http://attacker/` or `http://169.254.169.254/`. | EdgeGate never automatically follows `3xx` redirects; the `3xx` is returned directly to the caller with zero credential re-injection. |
| **DNS rebinding & metadata SSRF** | Backend hostname resolves to loopback, RFC1918, cloud metadata (`169.254.169.254`), IPv6 ULA/link-local, or IPv4-mapped IPv6 (`::ffff:169.254.169.254`). | Resolve-validate-connect (`src/pool.rs`): resolves via `tokio::net::lookup_host`, checks every IPv4/IPv6/unwrapped IPv4-mapped IPv6 address against the blocklist (unless `allow_private_ip = true` is explicitly configured for local fixtures), and dials the validated `SocketAddr` directly. |
| **HTTP/1.1 stream desync / cross-tenant leak** | Client disconnects mid-response or upstream sends `Connection: close`; dirty socket is reused by another tenant. | Single-flight `SendRequest` checkout with `PooledBody` `Drop` guard (`src/pool.rs`): returns handle only after full EOF drain, `!Connection: close`, and `is_ready()`; otherwise drops socket immediately. |
| **Log secret leakage** | Raw credentials printed via `Debug`, `Display`, or structured request logs. | `SecretValue` wraps bytes in `ZeroizeOnDrop` with redacted `Debug` (`"[REDACTED]"`). Structured JSON logs emit only metadata (`request_id`, `org_id`, `workload_id`, `route`, `upstream`, `decision`, `status`, `latency_us`). |
| **HTTP request smuggling** | Malformed `Content-Length` / `Transfer-Encoding` framing. | Delegated to `hyper` v1 strict HTTP/1.1 parser; hop-by-hop stripper preserves `hyper`-managed framing headers. |
| **Pool exhaustion / DoS** | Slowloris or burst flood exhausts sockets or falsely ejects healthy backends. | Bounded `max_request_body_bytes`, explicit connect/response timeouts, per-upstream `Semaphore` backpressure (`503`), and passive ejection strictly isolated from local `503`. |

## 5. Explicit Non-Goals & Residual Risks (Milestone 1)
- **Malicious upstream credential reflection:** Response scrubbing alone cannot guarantee credential confidentiality if a compromised upstream deliberately reflects or encodes an injected secret inside a response body. EdgeGate M1 does not claim response scrubbing as a security boundary; trust in the authorized upstream's handling of its own credential is explicit.
- **Workload gateway token (`X-EdgeGate-Token`) inside sandbox:** In M1, compromised code inside the sandbox can read its own `X-EdgeGate-Token` and make authorized calls *within its policy scope* (it still cannot extract upstream keys or reach denied destinations). Milestone 2 adds transport-level socket identity (UDS/Boxlet) to remove even the gateway token from sandbox memory.
- **Plaintext HTTP/1.1 in M1:** Inbound and outbound TLS (`rustls`), HTTP/2, and HTTP/3 are deferred to Milestone 2. Do not expose M1 plaintext listeners over untrusted public networks.
- **Host/container escape:** Container kernel isolation is enforced by Docker/Linux (and future Boxlet integration), outside EdgeGate's process boundary.
