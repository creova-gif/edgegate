# Security Policy & Enforced Invariants

EdgeGate is designed as a high-assurance L7 security choke point between untrusted workloads (AI agents, ephemeral sandboxes, multi-tenant containers) and external or internal HTTP/HTTPS services.

## Reporting a Vulnerability

- **Do not open public GitHub issues for suspected security vulnerabilities.**
- Please report vulnerabilities privately via [GitHub Security Advisories](https://github.com/creova-gif/edgegate/security/advisories/new) for `creova-gif/edgegate`.
- Include a minimal reproduction config (`edgegate.toml`), request payload/headers, and expected vs. observed behavior.

---

## Enforced Security Invariants

Every request processed by EdgeGate is subject to the following non-negotiable security invariants, verified continuously by unit, integration, and adversarial test suites:

| Invariant ID | Security Property | Implementation Mechanism | Enforcing Module |
|---|---|---|---|
| **INV-01** | **Fail-Closed Pre-Policy Path Normalization** | Rejects paths not starting with `/`, double slashes (`//`), raw or percent-encoded dot-segments (`.`, `..`, `%2e`, `%2e%2e`, `.%2e`, `%2e.`), backslashes (`\`, `%5c`), encoded slashes (`%2f`), null bytes (`%00`), and ASCII control characters (`< 0x20`, `0x7f`) with `400 Bad Request` **before** route matching or policy evaluation. | [`src/router.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/router.rs) (`validate_request_path`) |
| **INV-02** | **Constant-Time Token Verification & Dual-Token Rollover** | Pre-computes SHA-256 digests of primary (`token` / `token_sha256`) and rollover (`secondary_token` / `secondary_token_sha256`) workload tokens at config compilation and compares candidate digests using `subtle::ConstantTimeEq` (`ct_eq`) to prevent character-by-character timing side channels while enabling zero-downtime key rotation. | [`src/auth.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/auth.rs) (`HeaderTokenAuthenticator`) |
| **INV-03** | **Zero-Token Transport-Bound Identity** | Dedicated per-sandbox Unix domain sockets (`[[server.unix_listeners]]` and `EdgeGateProxy::register_boxlet_sandbox`) bind workload identity (`workload_id`, `org_id`, `roles`) directly to the OS socket boundary, requiring zero bearer tokens inside the sandbox. | [`src/auth.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/auth.rs), [`src/proxy.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/proxy.rs) |
| **INV-04** | **Default-Deny Multi-Tenant & RBAC Policy** | Denies all requests unless an explicit policy rule matches `(org_id, workload_id, required_roles, route_id, method, path_prefix, required_headers)` using segment-boundary-safe prefix matching (`/v1/repos` never matches `/v1/repos-admin`). | [`src/policy.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/policy.rs) (`DefaultDenyPolicyEngine`) |
| **INV-05** | **Cross-Tenant Credential Isolation & Zeroization** | Scopes every secret lookup to `(identity.org_id, binding.credential_ref)`. Wraps secret bytes in `SecretValue` (`zeroize::ZeroizeOnDrop`) with `Debug` and `Display` unconditionally redacted to `"[REDACTED]"`. | [`src/secrets.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/secrets.rs) (`SecretValue`, `MockSecretProvider`) |
| **INV-06** | **Outbound Header Smuggling & Credential Override Prevention** | Unconditionally strips `X-EdgeGate-Token`, `Proxy-Authorization`, all RFC 9110 hop-by-hop headers, any header names dynamically listed in incoming `Connection` headers (except `content-length` and `transfer-encoding`), and the route's target credential header before injecting the upstream secret; rewrites `Host` to the backend's configured authority. | [`src/router.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/router.rs) (`sanitize_outbound_headers`) |
| **INV-07** | **Resolve-Validate-Connect SSRF Defense** | Resolves DNS once, validates all returned IPv4, IPv6, and unwrapped IPv4-mapped IPv6 (`::ffff:169.254.169.254`, `::ffff:127.0.0.1`) addresses against the private/loopback/link-local/metadata/CGNAT/ULA blocklist (unless `allow_private_ip = true` for local test fixtures), and connects directly to the validated `SocketAddr` to eliminate DNS-rebinding TOCTOU. | [`src/pool.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/pool.rs) (`resolve_and_validate_addr`, `is_blocked_ip`) |
| **INV-08** | **Zero Redirect Following (`3xx` Credential Leak Prevention)** | Never follows `301`/`302`/`307`/`308` upstream redirects; returns `3xx` responses directly to the caller so an injected upstream credential is never forwarded to a redirect target. | [`src/proxy.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/proxy.rs), [`src/pool.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/pool.rs) |
| **INV-09** | **HTTP/1.1 Stream Isolation (`PooledBody` Guard)** | Returns an HTTP/1.1 `SendRequest` handle to the idle pool **only** after the response body reaches clean EOF, `!Connection: close`, `!sender.is_closed()`, and `sender.is_ready()`. Early client disconnect or body error immediately drops the connection. | [`src/pool.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/pool.rs) (`PooledBody`) |
| **INV-10** | **Bounded Request Payloads & Concurrency** | Enforces `max_request_body_bytes` via `http_body_util::Limited` (`413 Payload Too Large`), per-workload token-bucket rate limits (`429 Too Many Requests`), and per-backend `Semaphore` concurrency caps (`503 Service Unavailable`). | [`src/proxy.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/proxy.rs), [`src/pool.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/pool.rs) |
| **INV-11** | **Secret-Free Structured Audit Logs & Flight Recorder** | Audit logs (`edgegate::audit`) and the `/_edgegate/replay` ring buffer record only sanitized routing, identity, timing, and status metadata—never request/response headers, bodies, or credentials. | [`src/telemetry.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/telemetry.rs) (`Telemetry`, `ReplayRecord`) |
| **INV-12** | **Response Credential Reflection Guard** | When `block_secret_reflection = true` is configured on `[routes.credential]`, EdgeGate inspects upstream response headers and buffered response body bytes for the injected secret and fails closed with `502 Bad Gateway` (`secret_reflections_blocked_total` + sanitized `/_edgegate/replay` entry) if a misconfigured or malicious upstream reflects the credential. | [`src/proxy.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/proxy.rs), [`src/telemetry.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/telemetry.rs) |
| **INV-13** | **Idempotent-Only Retry Safety** | When `max_idempotent_retries > 0` is configured on `[[pools]]`, EdgeGate retries connect/transport failures **exclusively** for safe HTTP methods (`GET`, `HEAD`, `OPTIONS`) against the next healthy backend and **never** retries state-mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`). | [`src/proxy.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/proxy.rs), [`src/config.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/config.rs) |
| **INV-14** | **Scoped Credential Rotation & Fail-Closed TTL Expiry** | Enforces optional `expires_at_epoch_s` TTL deadlines on `[[secrets]]`, failing closed with `403 Forbidden` the instant a credential expires, and supports live in-memory atomic secret rotation via `EdgeGateProxy::rotate_secret` (`secret_rotations_total`) with automatic zeroization of superseded secret values. | [`src/secrets.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/secrets.rs), [`src/proxy.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/proxy.rs) |
| **INV-15** | **Programmable Request-Attribute Policy Matching** | Enforces optional `required_headers` exact header/attribute predicates on `[[policies]]` (e.g., `required_headers = { "x-mcp-tool" = "github.read_repo" }` for Keelway MCP Gateway and IoRa tool-call governance), rejecting requests with missing or mismatched attribute values with `403 Forbidden` before any upstream connection or credential lookup occurs. | [`src/policy.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/policy.rs), [`src/config.rs`](file:///Users/justinmafie/Documents/antigravity/edgegate/src/config.rs) |

---

## Residual Risks & Explicit Non-Goals

1. **Obfuscated or Compressed Upstream Credential Reflection:**
   When `block_secret_reflection = true` (`INV-12`) is enabled on `[routes.credential]`, EdgeGate blocks verbatim reflection of the injected secret in upstream response headers and bodies (`502 Bad Gateway`). However, if a deliberately malicious upstream encodes, encrypts, or compresses the echoed credential before returning it, byte-pattern scrubbing cannot guarantee confidentiality against arbitrary steganography. Operators should only bind scoped credentials to trusted upstream authorities.
2. **Kernel / Container Escape Outside Network Namespace:**
   EdgeGate enforces network and L7 protocol boundaries. Host kernel isolation, seccomp filters, and container/VM sandboxing (`internal: true` Docker networks, Boxlet microVMs, mount namespaces) are the responsibility of the container runtime or hypervisor.
3. **Denial-of-Service Against Shared Upstream Quotas:**
   While EdgeGate enforces per-workload rate limits (`rate_limit_rps` / `rate_limit_burst`), request body size caps (`max_request_body_bytes`), and per-backend connection pool semaphores (`max_connections_per_upstream`), authorized workloads within their configured rate limits still consume upstream API quota.

---

## Adversarial Verification Commands

Run the full automated security and adversarial verification suite locally:

```bash
# 1. Run all unit, integration, and adversarial security tests (path traversal, SSRF,
#    header smuggling, cross-tenant isolation, 3xx redirect non-follow, dirty body drop,
#    TLS verification, UDS zero-token auth, circuit breakers, rate limiting, credential TTL expiry,
#    live secret rotation, dual-token rollover, and required_headers MCP attribute policies)
cargo test --all-targets

# 2. Run the interactive 5-scenario zero-secret security console demo
cargo run --example security_console_demo

# 3. Enforce strict static analysis (zero warnings, zero .unwrap()/.expect() in production code)
cargo clippy --all-targets -- -D warnings

# 4. Run the end-to-end Docker zero-bypass container proof
#    Proves that an isolated sandbox container with zero API keys and no default route
#    cannot reach the internet or upstream directly, yet succeeds through EdgeGate's policy engine
docker compose -f docker-compose.demo.yml up -d --build
./scripts/demo-verify.sh
docker compose -f docker-compose.demo.yml down
```
