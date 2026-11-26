# EdgeGate Systems Architecture

EdgeGate is a programmable Layer-7 (L7) reverse proxy and load balancer engineered in Rust (`tokio` + `hyper` v1 + `rustls` + `arc-swap`) to establish a **zero-secret network execution boundary** for AI agents, ephemeral code sandboxes, and untrusted multi-tenant workloads.

> **Core Invariant:** An untrusted workload must be able to invoke explicitly authorized upstream HTTP/1.1, HTTP/2, and HTTPS endpoints without ever possessing the underlying upstream API credentials in its environment variables, filesystem, or address space, and without possessing unrestricted outbound network authority.

---

## 1. System Overview & Zero-Secret Execution Model

Conventional agent sandboxes rely on either:
1. **Injecting raw secrets (`OPENAI_API_KEY`, `GITHUB_TOKEN`, internal service tokens) directly into the sandbox environment**, which immediately exposes those secrets to prompt injection, arbitrary code execution, or accidental telemetry logging; or
2. **Intercepting arbitrary outbound traffic via `HTTP_PROXY` MITM TLS proxies (`mitmproxy`, Squid)**, which requires distributing custom root CA certificates into every guest runtime and exposes the proxy to arbitrary-destination DNS-rebinding and SSRF attacks.

EdgeGate eliminates both failure modes by acting as an **explicit, default-deny L7 gateway** sitting on the boundary between an isolated internal sandbox network (or host-mounted Unix domain socket) and upstream networks:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Untrusted AI Agent / Ephemeral Sandbox (Docker internal:true or Boxlet MicroVM)  │
│  • Zero upstream API keys in env, disk, or memory                                │
│  • Zero default route to the public internet                                     │
└───────────────────┬──────────────────────────────────────────┬───────────────────┘
                    │ Zero-Token UDS Socket                    │ TCP / Inbound TLS (h2/http1.1)
                    │ (TransportBoundAuthenticator)            │ + X-EdgeGate-Token (SHA-256)
                    ▼                                          ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                              EdgeGate L7 Data Plane                              ║
║                                                                                  ║
║  [Step 0] Observability (`/_edgegate/healthz`, `/metrics`, `/replay`) &          ║
║     │     Authenticated Admin Control Plane (`/_edgegate/admin/{reload,          ║
║     │     secrets/rotate,audit}`, constant-time `X-EdgeGate-Admin-Token`,        ║
║     │     disabled fail-closed when `admin_token` is unconfigured)               ║
║     ▼                                                                            ║
║  [Step 1] Fail-Closed Path Normalization Guard (`validate_request_path`)         ║
║     │     Rejects `..`, `%2e`, `%2f`, `%5c`, `\`, `%00`, `//`, control chars     ║
║     ▼                                                                            ║
║  [Step 2] Workload Authentication (`WorkloadAuthenticator`)                      ║
║     │     Resolves `WorkloadIdentity { workload_id, org_id, roles }`             ║
║     │     (Supports zero-downtime primary + `secondary_token` rollover)          ║
║     ▼                                                                            ║
║  [Step 3] Deterministic Longest-Prefix & Host Router (`Router::match_route`)     ║
║     │                                                                            ║
║     ▼                                                                            ║
║  [Step 4] Default-Deny Multi-Tenant RBAC, Attribute & Query Policy (`INV-15/17`) ║
║     │     Enforces `(org_id, workload_id, required_roles, route_id, method, pfx, ║
║     │     required_headers, forbidden_query_params)` and resolves per-rule       ║
║     │     `max_body_bytes` ceiling (`403 Forbidden` on policy/query violation)   ║
║     ▼                                                                            ║
║  [Step 5] Per-Workload Token-Bucket Rate Limiter (`TokenBucketRateLimiter`)      ║
║     │     Enforces `rate_limit_rps` & `rate_limit_burst` (`429 Too Many Reqs`)   ║
║     ▼                                                                            ║
║  [Step 6] Weighted Load Balancer & 3-State Circuit Breaker (`PoolLoadBalancer`)  ║
║     │     Weighted `RoundRobin` | `LeastConnections` | `ConsistentHash` | `EWMA` ║
║     │     Acquires RAII `BackendLease` (`Closed` / `Open` / `HalfOpen` probe)    ║
║     ▼                                                                            ║
║  [Step 7] Outbound Header Sanitization, W3C `traceparent` & Credential Injection ║
║     │     Strips hop-by-hop, `X-EdgeGate-Token`, `Proxy-Authorization`, forged   ║
║     │     auth headers; verifies secret TTL (`expires_at_epoch_s`, `403` on      ║
║     │     expiry) and injects W3C `traceparent` + `(org_id, credential_ref)`     ║
║     ▼                                                                            ║
║  [Step 8] Bounded Body Collection (`http_body_util::Limited`, `413` on overflow) ║
║     │     Enforces `min(server.max_request_body_bytes, policy.max_body_bytes)`   ║
║     ▼                                                                            ║
║  [Step 9] Bounded Connection Pool + SSRF Defense + Idempotent Failover           ║
║     │     • DNS resolve -> IPv4/IPv6/mapped-v6 blocklist -> dial `SocketAddr`    ║
║     │     • HTTP/1.1 single-flight (`PooledBody` EOF-drain guard) or HTTP/2 `h2` ║
║     │     • Controlled failover (`max_idempotent_retries`) for `GET`/`HEAD`/     ║
║     │       `OPTIONS` only; never follows `3xx` or retries state-mutating verbs  ║
║     ▼                                                                            ║
║  [Step 10] Defense-in-Depth Response Credential Reflection Guard & Audit Chain   ║
║           • When `block_secret_reflection = true`, inspects upstream response    ║
║             headers and body; blocks leaked secrets with `502 Bad Gateway`       ║
║           • Appends SHA-256 hash-chained audit entry (`prev_hash` ->             ║
║             `entry_hash`, `INV-16`) & records lock-free microsecond histogram    ║
╚═══════════════════╤══════════════════════════════════════════╤═══════════════════╝
                    │ Primary Dispatch                         │ Async Non-Blocking Clone
                    ▼                                          ▼
     ┌─────────────────────────────┐            ┌─────────────────────────────┐
     │   Primary Upstream Pool     │            │   Optional Shadow Pool      │
     │ (HTTP/1.1, HTTP/2, rustls)  │            │ (Canary Status Diffing &    │
     └─────────────────────────────┘            │  Flight-Recorder Capture)   │
                                                └─────────────────────────────┘
```

---

## 2. Linear L7 Security Pipeline vs. Implicit Middleware Stacks

In `src/proxy.rs` (`EdgeGateProxy::handle_request_with_auth`), every request traverses an **explicit, linear, strongly-typed Rust control flow** rather than a dynamic chain of Tower `Layer`/`Service` middlewares communicating through untyped `http::Extensions` maps.

### Why a Linear Typed Pipeline Was Chosen Over Tower Middleware Layers

1. **Compile-Time Proof of Ordering & Data Dependencies:**
   In a dynamic middleware stack, a downstream layer must retrieve `req.extensions().get::<WorkloadIdentity>()` at runtime. Reordering two layers in a builder or forgetting to insert an authentication layer can silently cause an authorization or credential-injection layer to either panic or misbehave. In EdgeGate's linear pipeline, step `N+1` consumes the concrete Rust value produced by step `N`:
   - `DefaultDenyPolicyEngine::evaluate(&identity, &route.id, &method, &path)` requires a borrowed `&WorkloadIdentity` and `&CompiledRoute`.
   - `SecretProvider::get_secret(&identity.org_id, &binding.credential_ref)` cannot even be called without first holding both the authenticated `WorkloadIdentity` and the matched `CompiledRoute`.
2. **Strict Fail-Closed Pre-Policy Normalization:**
   Path-traversal attacks (`/v1/allowed/../admin`, `/v1/allowed/%2e%2e/admin`, `%2f`, `%5c`, `%00`, `//`) exploit discrepancies between how a policy middleware and an upstream router normalize URI paths. By executing `validate_request_path(&path)` at **Step 1** before authentication, routing, or policy evaluation, EdgeGate guarantees that every downstream component inspects the exact same canonical path string.
3. **Zero Per-Request Heap Allocations for Middleware Boxing:**
   Tower stacks frequently box futures (`Pin<Box<dyn Future<Output = ...> + Send>>`) or clone `Arc` layers across service boundaries. EdgeGate loads a single lock-free `Arc<RuntimeSnapshot>` via `ArcSwap::load_full()` at the start of the request and executes the entire pipeline inside one contiguous async state machine.
4. **Unconditional Header Sanitization Before Secret Injection:**
   `sanitize_outbound_headers` (`src/router.rs`) runs immediately before credential injection. It parses the incoming `Connection` header tokens, strips all RFC 9110 hop-by-hop headers (`connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `upgrade`) plus any dynamically listed `Connection` header names (while preserving `content-length` and `transfer-encoding` framing headers managed by `hyper`), strips `x-edgegate-token`, strips the route's target credential header (`Authorization`, `X-Api-Key`, etc.) so a workload can never smuggle or override upstream credentials, and rewrites `Host` to the selected backend's configured authority.

---

## 3. Connection Pool Architecture (`src/pool.rs`): Single-Flight HTTP/1.1 vs. Multiplexed HTTP/2

`ConnectionPool` maintains a bounded `UpstreamSlot` per `(pool_name, backend_id)` pair. Every slot enforces concurrency limits via `Arc< tokio::sync::Semaphore >` (`max_connections_per_upstream`). Local semaphore exhaustion immediately returns `EdgeGateError::PoolExhausted` (`503 Service Unavailable`) without blocking the async runtime and **without** penalizing the backend's circuit breaker.

### Single-Flight HTTP/1.1 Lifecycle & `PooledBody` RAII Guard

HTTP/1.1 connections are inherently vulnerable to cross-tenant stream desynchronization if a connection is returned to an idle pool before its response body is completely drained, or after an upstream signals `Connection: close`. EdgeGate prevents this by wrapping `hyper::body::Incoming` inside `PooledBody`:

```text
Checkout `Http1SendRequest` (from `idle_http1` VecDeque or fresh SSRF-validated dial)
       │
       ▼
Send Request -> Receive Response Headers + `hyper::body::Incoming`
       │
       ▼
Construct `PooledBody { inner: Incoming, state: Some(PoolReturnState) }`
  (Holds `Http1SendRequest`, `OwnedSemaphorePermit`, and LB `BackendLease`)
       │
       ├──► Case A: `inner.poll_frame()` reaches `Poll::Ready(None)` (Clean EOF)
       │      • Checks `!connection_close && !sender.is_closed() && sender.is_ready()`
       │      • Pushes `IdleHttp1Conn { sender, returned_at: Instant::now() }` to `idle_http1`
       │      • Releases `OwnedSemaphorePermit` and `BackendLease`
       │
       └──► Case B: Stream error OR client disconnects early (`PooledBody` dropped mid-body)
              • `state` is dropped without returning `sender` to `idle_http1`
              • Underlying TCP/TLS socket is closed immediately; zero dirty reuse
```

When checking out an idle HTTP/1.1 connection (`pop_fresh_http1`), EdgeGate evicts any entry where `now - returned_at > idle_ttl` or `sender.is_closed()`.

### Multiplexed HTTP/2 (`h2` TLS ALPN & `h2c` Prior-Knowledge)

When `backend.http2 = true` is configured on a backend:
- **Outbound TLS (`tls = true`):** `build_tls_connector` configures `rustls::ClientConfig::alpn_protocols = vec![b"h2", b"http/1.1"]` and negotiates HTTP/2 over TLS 1.2/1.3 using `hyper::client::conn::http2::handshake`.
- **Outbound Plaintext (`tls = false`):** Dials HTTP/2 prior-knowledge (`h2c`) over the validated TCP stream.
- **Multiplexed Sender Sharing:** Unlike HTTP/1.1 where a `SendRequest` handle is moved out of the idle queue for the duration of a single request, `UpstreamSlot` stores a cloneable `Option<Http2SendRequest<Full<Bytes>>>`. Concurrent requests clone the ready `Http2SendRequest` handle and multiplex HTTP/2 streams over the single underlying connection while still acquiring an `OwnedSemaphorePermit` from `slot.semaphore` to bound maximum concurrent streams per backend.
- **Inbound Auto-Detection & TLS Termination (`[server.tls]`):** Both TCP and Unix domain socket listeners use `hyper_util::server::conn::auto::Builder` to automatically serve both HTTP/1.1 and HTTP/2 (`h2c`) clients on the same socket. When `[server.tls]` is configured (`cert_pem`/`key_pem` or `cert_path`/`key_path`), EdgeGate wraps the TCP listener in `tokio_rustls::TlsAcceptor` (`rustls::ServerConfig`) advertising `alpn_protocols = vec![b"h2", b"http/1.1"]`, terminating TLS 1.2/1.3 and negotiating HTTP/2 (`h2`) or HTTP/1.1 seamlessly.

---

## 4. Load Balancing, Three-State Circuit Breakers & Idempotent Failover (`src/lb.rs`, `src/proxy.rs`)

### Three-State Per-Backend Circuit Breaker (`Closed` -> `Open` -> `HalfOpen`)

Every backend maintains an independent state machine (`CircuitState`) alongside an `AtomicBool` active health flag (`active_healthy`) updated by background HTTP health probes (`spawn_active_health_probes`):

```text
                  passive_failure_threshold consecutive
                  502 / 504 / upstream 5xx failures
     ┌──────────┐ ────────────────────────────────────► ┌──────────┐
     │  Closed  │                                       │   Open   │
     │ (Normal) │ ◄──────────────┐                      │ (Reject) │
     └──────────┘                │                      └────┬─────┘
          ▲                      │                           │
          │                      │ Trial probe               │ now >= until
          │                      │ fails (502/504/5xx)       │ (passive_cooldown elapsed)
          │                      │                           ▼
          │   Trial probe        │                    ┌──────────────┐
          └── succeeds (2xx-4xx) └─────────────────── │   HalfOpen   │
                                                      │ (Single-     │
                                                      │  Flight)     │
                                                      └──────────────┘
```

1. **Failure Isolation from Local `503` Pool Exhaustion:**
   `LoadBalancer::record_failure` is invoked **exclusively** on upstream connect/transport errors (`502 Bad Gateway`), upstream timeouts (`504 Gateway Timeout`), and upstream `5xx` server errors. Local `503` (`PoolExhausted`) responses never trip the circuit breaker, preventing cascading false ejections during local traffic spikes.
2. **Thundering-Herd Prevention via Single-Flight `HalfOpen` Probe:**
   When `Open { until }` expires (`now >= until`), the first arriving request atomically transitions the state to `HalfOpen { probe_in_flight: true }` and receives a `BackendLease` armed with a `half_open_probe` RAII guard. While `probe_in_flight == true`, all other concurrent requests bypass this backend.
   - If the probe request is aborted before reaching the upstream (e.g., outbound header validation or body limit failure), `BackendLease::drop` automatically resets `probe_in_flight: false` so the backend does not livelock.
   - Once dispatched (`lease.settle_probe()`), a `2xx`–`4xx` response calls `record_success`, resetting the circuit to `Closed { consecutive_failures: 0 }`. A `502`/`504`/`5xx` calls `record_failure`, immediately re-opening the circuit (`Open { until: now + cooldown }`).
3. **Controlled Idempotent Failover Retries (`max_idempotent_retries`):**
   Pools may configure `max_idempotent_retries` (default `0`). When an upstream attempt fails with a connect or transport error (`EdgeGateError::UpstreamConnect` / `EdgeGateError::UpstreamTimeout`), EdgeGate records the failure on the failed backend and—**only if the HTTP method is safe/idempotent (`GET`, `HEAD`, `OPTIONS`)**—selects the next healthy backend in the pool, increments `retries_total`, and re-dispatches the request. State-mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`) are **never** retried to prevent duplicate side effects.

### Four Load-Balancing Strategies (`LbStrategyConfig`) & Weighted Canary Splitting (`weight`)

Each `[[pools.backends]]` entry accepts an optional `weight` (default `1`, must be `> 0`) for proportional canary traffic splitting across healthy backends:

| Strategy | Configuration Value | Selection Mechanics & Complexity |
|---|---|---|
| **Round Robin (Weighted)** | `"round_robin"` | Lock-free `AtomicUsize::fetch_add(1, Relaxed)` cursor stepping through a weight-expanded schedule (`weight` slots per backend) and falling back across healthy candidates if the selected slot's circuit is open. |
| **Least Connections** | `"least_connections"` | Tracks active requests per backend via an `Arc<AtomicUsize>` incremented on `select` and decremented in `BackendLease::drop`. Scans from a rotating cursor to break ties fairly and releases any speculatively claimed `HalfOpen` probe if a strictly less-loaded backend is found. |
| **Consistent Hash (Weighted)** | `"consistent_hash"` | Computes a deterministic 64-bit FNV-1a hash (`fnv1a_64`) over the `X-EdgeGate-Routing-Key` request header (falling back to the authenticated `workload_id`) modulo the weight-expanded ring, probing linearly to the next healthy backend if the primary shard's circuit is open. |
| **Latency-Aware (EWMA)** | `"latency_aware"` | Maintains a lock-free `AtomicU64` Exponentially Weighted Moving Average of upstream response latency in microseconds ($\text{EWMA}_{t} = \frac{3 \cdot \text{EWMA}_{t-1} + L_t}{4}$, $\alpha = 0.25$) updated on every successful response, selecting the admissible backend with the lowest EWMA latency. |

---

## 5. Resolve-Validate-Connect SSRF Defense (`src/pool.rs`)

Standard HTTP clients resolve DNS inside their socket connector, creating two classic vulnerabilities:
1. Direct requests to private/loopback/link-local addresses (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254` cloud metadata).
2. **DNS Rebinding TOCTOU** where a hostname resolves to a public IP during a pre-flight check and rebinds to `127.0.0.1` or `169.254.169.254` when the HTTP client actually dials.

EdgeGate eliminates both via `resolve_and_validate_addr`:
1. **Explicit Resolution:** Resolves `(host, port)` once via `tokio::net::lookup_host` (or parses a literal `IpAddr`).
2. **Comprehensive Dual-Stack & Mapped-IPv6 Blocklist (`is_blocked_ip`):** Unless a pool explicitly sets `allow_private_ip = true` (used exclusively for local/container test fixtures), **every** resolved `SocketAddr` is validated against `is_blocked_ip`:
   - **IPv4 (`is_blocked_ipv4`):** Blocks loopback (`127.0.0.0/8`), RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local and cloud metadata (`169.254.0.0/16`, including `169.254.169.254`), CGNAT shared address space (`100.64.0.0/10`), unspecified (`0.0.0.0`), broadcast, and multicast.
   - **IPv6 (`is_blocked_ipv6`):** First unwraps **IPv4-mapped IPv6 addresses** via `v6.to_ipv4_mapped()` (catching `::ffff:169.254.169.254`, `::ffff:127.0.0.1`, and `::ffff:10.0.0.1`) and applies the full IPv4 blocklist; then blocks IPv6 loopback (`::1`), unspecified (`::`), multicast (`ff00::/8`), Unique Local Addresses (`fc00::/7`), and link-local (`fe80::/10`).
3. **Direct Validated Socket Dial:** `TcpStream::connect(validated_addr)` dials the verified `SocketAddr` directly without performing a second DNS lookup, closing the DNS-rebinding TOCTOU window completely.

---

## 6. Zero-Token Transport Identity & Dynamic Boxlet Attachment (`src/auth.rs`, `src/proxy.rs`)

Even a scoped gateway token (`X-EdgeGate-Token`) stored inside a sandbox can be exfiltrated by code running inside that sandbox and replayed from within the same sandbox network. To eliminate **all** bearer tokens from sandbox environments, EdgeGate supports **Transport-Bound Identity** over Unix domain sockets:

1. **Static Unix Listeners (`[[server.unix_listeners]]`):**
   Configured in `edgegate.toml` with `{ path, workload_id, org_id, roles }`. Each socket binds a dedicated `UnixListener` paired with a `TransportBoundAuthenticator` that stamps every request arriving over that socket with its pre-verified `WorkloadIdentity`.
2. **Dynamic Boxlet Sandbox Registration (`EdgeGateProxy::register_boxlet_sandbox`):**
   Container and microVM supervisors (such as Boxlet) can attach and detach ephemeral sandboxes at runtime without rewriting configuration files:
   ```rust
   let guard: BoxletSandboxGuard = proxy.register_boxlet_sandbox(
       PathBuf::from("/run/boxlet/sandbox-42.sock"),
       CompiledWorkload {
           workload_id: "boxlet-sandbox-42".to_string(),
           org_id: "org-alpha".to_string(),
           roles: ["inference:call".to_string()].into_iter().collect(),
       },
   )?;
   ```
   When the sandbox terminates and `BoxletSandboxGuard` is dropped, its `Drop` implementation aborts the listener task and unlinks `/run/boxlet/sandbox-42.sock` automatically.

---

## 7. Atomic Zero-Downtime Hot Reload (`ArcSwap<RuntimeSnapshot>`)

All mutable routing, authentication, policy, rate-limiting, secret, load-balancer, and connection-pool structures are compiled into an immutable `RuntimeSnapshot` held behind `Arc<ArcSwap<RuntimeSnapshot>>`:
- **Wait-Free Hot Path:** Every incoming request calls `self.runtime.load_full()` to obtain an `Arc<RuntimeSnapshot>`. Request processing never acquires a read lock (`RwLock`) on the configuration path.
- **Transactional Validation & Swap:** When `reload_from_file` or `reload_from_toml_str` is triggered (either programmatically or via `--watch-interval-ms`), EdgeGate parses and validates the new `CompiledConfig` off the hot path.
  - If validation fails (e.g., unknown pool reference, malformed PEM certificate, missing environment secret, duplicate route ID), EdgeGate increments `reload_failures_total`, logs a structured warning, and **keeps the current `RuntimeSnapshot` active**.
  - If validation succeeds, EdgeGate constructs a new `RuntimeSnapshot`, atomically swaps the pointer via `self.runtime.store(next)`, and increments `config_generation` and `reloads_total`. In-flight requests holding the previous `Arc<RuntimeSnapshot>` complete cleanly without interruption.

---

## 8. Rate Limiting, W3C Trace Propagation, Traffic Shadowing & Flight-Recorder Replay

### Per-Workload Token-Bucket Rate Limiting
Workloads can be configured with `rate_limit_rps` and `rate_limit_burst`. EdgeGate enforces per-workload token-bucket rate limiting immediately after policy authorization, returning `429 Too Many Requests` (`rate_limited_total`) before any upstream connection slot or credential lookup is consumed.

### W3C `traceparent` Propagation
EdgeGate preserves incoming valid W3C Trace Context `traceparent` headers (`00-<trace-id>-<span-id>-<flags>`) or synthesizes a fresh W3C `traceparent` header on outbound upstream requests, correlating audit logs, primary upstreams, and shadow pools end-to-end.

### Non-Blocking Traffic Shadowing (`shadow_pool`)
Routes configured with `shadow_pool = "<canary-pool>"` clone the sanitized, credential-injected outbound request after the primary response headers arrive and dispatch it asynchronously via `tokio::spawn` (`spawn_shadow_dispatch`).
- Shadow traffic is bounded by the shadow pool's own `Semaphore` and timeouts so a slow or failing canary never adds latency to primary responses.
- EdgeGate compares the primary and shadow HTTP status codes, incrementing `shadow_requests_total` and `shadow_mismatches_total`.

### Sanitized Flight-Recorder Replay (`GET /_edgegate/replay`)
Whenever an authorized request encounters an open circuit breaker (`503`), an upstream transport/timeout failure (`502`/`504`), an upstream `5xx` error, a blocked secret reflection (`secret_reflection_blocked` -> `502`), or a shadow status mismatch (`shadow_status_mismatch`), EdgeGate records a `ReplayRecord` in a bounded ring buffer (`replay_buffer_size`, default `64`):
```json
{
  "records": [
    {
      "request_id": 42,
      "org_id": "org-alpha",
      "workload_id": "sandbox-alpha",
      "method": "GET",
      "path": "/v1/github/repos/edgegate",
      "route": "github",
      "upstream": "canary-b",
      "status": 200,
      "shadow_status": 500,
      "reason": "shadow_status_mismatch",
      "latency_us": 812
    }
  ]
}
```
By strict design, `ReplayRecord` never stores request headers, response headers, request/response bodies, or secret values—giving operators instant diagnostic visibility with zero secret or PII exposure.

---

## 9. Defense-in-Depth Response Credential Reflection Guard & Graceful Connection Draining (`Milestone 5`)

### Response Credential Reflection Guard (`block_secret_reflection = true`)
While EdgeGate strips all incoming auth headers and never follows `3xx` redirects, a misconfigured debug endpoint or compromised upstream server could echo the incoming request headers or injected secret back inside its HTTP response headers or response body. When `block_secret_reflection = true` is set on `[routes.credential]`:
1. EdgeGate tracks the exact raw secret value injected into the outbound request for that route.
2. Before returning the upstream response to the workload, EdgeGate inspects all response header values and collects the bounded response body to scan for the raw secret bytes.
3. If the secret appears anywhere in the upstream response headers or body, EdgeGate immediately aborts the response, increments `secret_reflections_blocked_total`, records a sanitized `secret_reflection_blocked` entry in `/_edgegate/replay`, and returns `502 Bad Gateway` (`{"error":"upstream response blocked: credential reflection detected"}`) so the secret never crosses back into the sandbox.

### Graceful In-Flight Connection Draining (`drain_timeout_ms`)
Every active request increments an atomic `in_flight_requests` gauge via an RAII guard (`InFlightGuard`) that decrements on completion or cancellation. When the server receives a shutdown signal (`serve_until`), EdgeGate stops accepting new connections and waits up to `server.drain_timeout_ms` (default `5000 ms`) for `in_flight_requests` to reach `0` before terminating remaining tasks.

---

## 10. Scoped Credential Rotation, TTL Expiry, Request-Attribute Policies & Dual-Token Rollover (`Milestone 6`)

### Scoped Credential Rotation & Fail-Closed TTL Expiry (`INV-14`)
1. **TTL Deadline Enforcement (`expires_at_epoch_s`):** Each `[[secrets]]` entry may specify an optional `expires_at_epoch_s: Option<u64>`. During `SecretProvider::get_secret(&org_id, &credential_ref)`, EdgeGate compares the current system Unix epoch timestamp against `expires_at_epoch_s`. If `now >= expires_at_epoch_s`, EdgeGate immediately fails closed with `EdgeGateError::Forbidden` (`403 Forbidden`) before any upstream connection is dialed or header is injected.
2. **Live In-Memory Rotation (`EdgeGateProxy::rotate_secret`):** Operators and control-plane supervisors can call `proxy.rotate_secret(org_id, credential_ref, new_value, expires_at_epoch_s)` at runtime to atomically replace a tenant's scoped secret in-memory without performing a full configuration file reload. The superseded `SecretValue` is automatically zeroized on drop (`ZeroizeOnDrop`), and `secret_rotations_total` is incremented for Prometheus and JSON telemetry.

### Programmable Request-Attribute Policy Matching (`INV-15`)
Policy rules (`[[policies]]`) support an optional `required_headers: HashMap<String, String>` map (e.g., `required_headers = { "x-mcp-tool" = "github.read_repo" }`).
- Header names are normalized to lowercase `HeaderName` at configuration compile time.
- During `DefaultDenyPolicyEngine::evaluate`, a rule matches only if **every** `(header_name, expected_value)` pair in `required_headers` is present on the incoming request with an exact string match.
- This allows EdgeGate to act as an L7 attribute and Model Context Protocol (MCP) tool-call enforcement point alongside **Keelway MCP Gateway** and **IoRa**, ensuring an AI agent authorized to call an MCP endpoint can invoke `github.read_repo` while being blocked (`403 Forbidden`) from invoking `github.delete_repo` on the same route.

### Zero-Downtime Dual Workload Token Rollover (`secondary_token` / `secondary_token_sha256`)
Each `[[workloads]]` entry supports an optional `secondary_token` (or pre-hashed `secondary_token_sha256`) alongside the primary `token` / `token_sha256`. Both SHA-256 digests are registered in the compiled workload lookup table and verified using constant-time comparison (`subtle::ConstantTimeEq`), allowing orchestrators to roll workload bearer tokens with zero dropped requests during the rotation window.

---

## 11. Authenticated Admin Control Plane, Tamper-Evident Audit Ledger, Per-Rule Query/Body Limits & Prometheus Histograms (`Milestone 7` / `v0.7.0`)

### Authenticated Admin Control Plane API (`/_edgegate/admin/*`)
EdgeGate exposes an explicit control-plane HTTP API gated by `X-EdgeGate-Admin-Token` (`server.admin_token` or pre-hashed 64-hex-char `server.admin_token_sha256`):
1. **Fail-Closed When Unconfigured:** If neither `server.admin_token` nor `server.admin_token_sha256` is configured in `[server]`, all requests to `/_edgegate/admin/*` are rejected fail-closed (`403 Forbidden`) so control-plane mutations can never be accidentally exposed on a default listener.
2. **Constant-Time Verification:** Incoming `X-EdgeGate-Admin-Token` values are hashed with SHA-256 and compared against the compiled admin token digest using `subtle::ConstantTimeEq` (`401 Unauthorized` on missing/invalid token).
3. **Control-Plane Operations:**
   - `POST /_edgegate/admin/reload`: Atomically compiles and swaps a new configuration snapshot via `ArcSwap` without dropping in-flight connections.
   - `POST /_edgegate/admin/secrets/rotate`: Rotates a scoped `(org_id, credential_ref)` secret and optional `expires_at_epoch_s` TTL live in-memory (`secret_rotations_total`) with automatic zeroization of the superseded `SecretValue`.
   - `GET /_edgegate/admin/audit`: Returns the bounded SHA-256 hash-chained audit ledger (`records`, `chain_valid`, `head_hash`) after verifying the cryptographic hash chain from genesis.

### Cryptographic SHA-256 Hash-Chained Tamper-Evident Audit Ledger (`INV-16`)
Every gateway decision (`ALLOWED`, `BLOCKED`, `RATE_LIMITED`, `ERROR`) is appended to an in-memory tamper-evident audit ledger:
- Each `AuditLedgerEntry` computes `entry_hash = SHA-256(prev_hash | request_id | trace_id | org_id | workload_id | route | upstream | decision | status | latency_us)`, linking every decision to its predecessor (`prev_hash`).
- Operators can inspect and cryptographically verify the chain at `GET /_edgegate/admin/audit` and monitor continuous integrity via `audit_chain_valid` in `GET /_edgegate/metrics` (`edgegate_audit_chain_valid` in Prometheus format).

### Per-Rule Query-Parameter & Payload Resource Limits (`INV-17`, `forbidden_query_params`, `max_body_bytes`)
Policy rules (`[[policies]]`) support granular L7 query and payload resource controls:
- **`forbidden_query_params`:** Lists query parameter names (normalized case-insensitively at compile time) that are forbidden on matching requests. If a request URI query string contains any forbidden parameter name (including percent-encoded variants), `DefaultDenyPolicyEngine` rejects the request with `403 Forbidden` before upstream dispatch.
- **`max_body_bytes`:** Overrides or tightens the request payload size ceiling for a specific policy rule (`effective_limit = rule.max_body_bytes.unwrap_or(server.max_request_body_bytes)`). Payloads exceeding the matched rule's `max_body_bytes` are aborted via `http_body_util::Limited` with `413 Payload Too Large`.

### Lock-Free Prometheus Latency Histograms (`edgegate_request_duration_microseconds_bucket`)
`Telemetry` tracks end-to-end request duration in lock-free `AtomicU64` cumulative microsecond buckets (`le="100"`, `le="500"`, `le="1000"`, `le="5000"`, `le="10000"`, `le="50000"`, `le="+Inf"`), plus `_sum` and `_count`, exported at `GET /_edgegate/metrics?format=prometheus` (`edgegate_request_duration_microseconds_bucket`).
