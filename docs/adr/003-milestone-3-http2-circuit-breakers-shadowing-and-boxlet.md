# ADR-003: Milestone 3 — HTTP/2, Three-State Circuit Breakers, Consistent/Latency-Aware LB, Traffic Shadowing, Flight-Recorder Replay, and Boxlet Dynamic UDS
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
With Milestone 1 (HTTP/1.1 core, default-deny policy, SSRF guard, container zero-bypass) and Milestone 2 (outbound `rustls` TLS, atomic `ArcSwap` hot reload, static zero-token UDS listeners, RBAC, active health probes) merged into `main`, Milestone 3 completes the full architecture roadmap: HTTP/2 multiplexing, explicit three-state circuit breakers (`Closed`/`Open`/`HalfOpen`), consistent-hashing and latency-aware (EWMA) load balancing, non-blocking traffic shadowing with status-mismatch telemetry, a bounded flight-recorder ring buffer for failed/mismatched requests, and a dynamic Boxlet sandbox UDS registration API.

## Decision
1. **HTTP/2 Support (`hyper` `http2` + ALPN `h2`):**
   - Inbound TCP and UDS listeners use `hyper_util::server::conn::auto::Builder` (`TokioExecutor`) to serve both HTTP/1.1 and HTTP/2 (`h2c` prior-knowledge) seamlessly on the same listener.
   - Outbound backends with `http2 = true` negotiate `h2` via TLS ALPN (when `tls = true`) or prior-knowledge `h2c` (when `tls = false`) and multiplex requests over `hyper::client::conn::http2::SendRequest` while respecting the per-backend concurrency `Semaphore`.
2. **Three-State Circuit Breaker (`Closed` -> `Open` -> `HalfOpen`) & Advanced LB Strategies (`src/lb.rs`):**
   - Each backend maintains an explicit state machine: `Closed` trips to `Open` after `passive_failure_threshold` consecutive failures; after `passive_cooldown`, it enters `HalfOpen` and admits **at most one** concurrent trial request (`half_open_probe_in_flight`). A trial success resets to `Closed`; a trial failure immediately re-opens the circuit for another full cooldown.
   - `LbStrategyConfig` adds `ConsistentHash` (deterministic FNV-1a 64-bit hash over routing key) and `LatencyAware` (lock-free atomic EWMA latency in microseconds).
3. **Traffic Shadowing & Sanitized Flight-Recorder Ring Buffer (`src/proxy.rs`, `src/telemetry.rs`):**
   - Routes with `shadow_pool = "<pool>"` clone the sanitized outbound request and dispatch it asynchronously in a non-blocking background task to the shadow pool, comparing status codes against the primary response and tracking `shadow_requests_total` and `shadow_mismatches_total`.
   - A bounded ring buffer (`replay_buffer_size`, default `64`) records sanitized request/failure metadata (never headers, bodies, or secrets) for `5xx`/`502`/`503`/`504` errors and shadow mismatches, exposed at `GET /_edgegate/replay`.
4. **Dynamic Boxlet Sandbox Socket Registration (`EdgeGateProxy::register_boxlet_sandbox`):**
   - Provides a runtime API and `Drop`/cleanup handle for Boxlet (or any sandbox supervisor) to dynamically bind and tear down per-sandbox zero-token Unix domain sockets (`workload_id`, `org_id`, `roles`) on the fly without config file rewrites.

## Alternatives Considered
- **Blocking Primary Response on Shadow Pool:** Rejected because shadow/canary failures or high tail latency must never degrade primary production traffic.
- **Storing Full Request Bodies in the Flight Recorder:** Rejected in Milestone 3 to guarantee zero accidental PII/payload retention in memory; only sanitized routing/timing/status metadata is buffered.

## Consequences & Failure Modes
- **Positive:** Prevents thundering-herd recovery via single-flight `HalfOpen` circuit-breaker probes, supports multiplexed HTTP/2 upstreams, validates canary backends safely via live shadow traffic, and gives Boxlet a first-class Rust API for dynamic zero-token sandbox attachment.
- **Failure Modes Mitigated:** Half-open probe stampede (guarded by `AtomicBool` compare-exchange), shadow pool saturation (bounded by shadow pool's own `Semaphore` and connect/response timeouts), and unbounded flight-recorder memory growth (capped ring buffer `VecDeque`).
