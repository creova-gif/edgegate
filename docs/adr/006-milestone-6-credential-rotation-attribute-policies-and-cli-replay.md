# ADR-006: Milestone 6 — Scoped Credential Rotation & TTL Expiry, Programmable Request-Attribute Policy Matching, Zero-Downtime Dual Workload Token Rollover, and CLI Replay
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Following Milestone 5 (inbound TLS termination, response credential reflection guard, controlled idempotent retries, and graceful drain), production multi-tenant deployments of EdgeGate alongside **Boxlet** (execution sandboxes), **Keelway** (MCP tool governance), and **IoRa** (RAG and inference workflows) require four additional operational and security capabilities:

1. **Scoped Credential Rotation & Fail-Closed TTL Expiry:**
   Secrets stored in EdgeGate (`[[secrets]]`) could previously be rotated via atomic TOML reload (`SIGHUP` or `EdgeGateProxy::reload_from_toml_str`), but operators also needed:
   - Fine-grained programmatic in-memory credential rotation (`rotate_secret`) and explicit revocation (`revoke_secret`) without requiring a full configuration re-parse.
   - Optional secret TTL expiry (`ttl_ms` in `[[secrets]]`) so ephemeral credentials leased from external vaults automatically fail closed (`403 Forbidden`) once expired, emitting dedicated telemetry (`secret_rotations_total`, `secret_expired_blocked_total`) and flight-recorder replay events (`reason = "credential_expired"`).

2. **Programmable Request-Attribute Policy Matching (`required_headers`):**
   Evaluating egress policy solely on `(org_id, workload_id, required_roles, route_id, method, path_prefix)` is sufficient for coarse REST APIs, but MCP tool gateways (Keelway) and multi-model AI routers (IoRa) frequently multiplex tools or models over a single HTTP endpoint (e.g., `POST /v1/mcp/invoke` or `POST /v1/openai/chat/completions`) and distinguish sub-operations via request headers such as `X-Keelway-Tool` or `X-IoRa-Pipeline`. Policies must be able to enforce exact header constraints (`required_headers`) in the default-deny engine before any upstream socket or secret is touched.

3. **Zero-Downtime Dual Workload Token Rollover (`secondary_token` / `secondary_token_sha256`):**
   Rotating a workload's authentication token (`X-EdgeGate-Token`) in production previously required synchronized restarts between the workload and EdgeGate or risked brief `401 Unauthorized` spikes during propagation. Supporting an optional secondary token per workload allows staged, zero-downtime key rollover.

4. **Operator CLI Inspection (`status` / `replay`) & Live Security Console Demo:**
   Operators debugging blocked egress attempts, rate-limited sandboxes, or reflected credentials need first-class CLI subcommands (`edgegate status --url ...`, `edgegate replay --url ...`) and an interactive, self-contained runnable example (`cargo run --example security_console_demo`) demonstrating the five core security invariants end-to-end.

## Decision
1. **Scoped Credential Rotation & TTL Expiry (`src/secrets.rs`, `src/config.rs`, `src/proxy.rs`, `src/telemetry.rs`):**
   - Extend `SecretEntryConfig` with `ttl_ms: Option<u64>`.
   - Upgrade `MockSecretProvider` to use interior-mutable, thread-safe storage (`RwLock<HashMap<(String, String), StoredSecret>>`) where `StoredSecret` holds a `Zeroizing<String>` value and an optional `expires_at: Option<Instant>`.
   - Extend the `SecretProvider` trait with `rotate_secret(&self, org_id, credential_ref, new_value, ttl)` and `revoke_secret(&self, org_id, credential_ref)`, plus convenience methods on `EdgeGateProxy`.
   - When `get_secret` encounters an expired secret (`Instant::now() >= expires_at`), it fails closed with `EdgeGateError::Forbidden("expired credential ...")`, increments `edgegate_secret_expired_blocked_total`, and records a flight-recorder `ReplayRecord` with `reason = "credential_expired"`.

2. **Programmable Request-Attribute Policy Matching (`src/config.rs`, `src/policy.rs`, `src/proxy.rs`):**
   - Add `#[serde(default)] pub required_headers: HashMap<String, String>` to `PolicyRuleConfig` and compiled `(HeaderName, String)` pairs on `CompiledPolicyRule`.
   - Extend `PolicyEngine::evaluate_with_headers(&self, identity, route_id, method, path, headers)` so that a policy rule only matches if every required header is present on the inbound request and its ASCII value matches the expected value. If all candidate rules for the route fail on `required_headers`, the engine returns `PolicyDecision::Deny` explaining the missing/mismatched request header attribute.

3. **Zero-Downtime Dual Workload Token Rollover (`src/config.rs`, `src/auth.rs`):**
   - Add `secondary_token: Option<String>` and `secondary_token_sha256: Option<String>` to `WorkloadConfig`.
   - During config compilation, both primary and secondary token SHA-256 digests are validated (rejecting collisions across workloads) and mapped to the same `CompiledWorkload` identity in `HeaderTokenAuthenticator`, preserving constant-time `subtle::ConstantTimeEq` matching.

4. **CLI `status` / `replay` & Self-Contained Security Console Demo (`src/main.rs`, `examples/security_console_demo.rs`):**
   - Add `edgegate status` and `edgegate replay` subcommands to the `edgegate` CLI binary to query `/_edgegate/healthz`, `/_edgegate/metrics`, and `/_edgegate/replay` over HTTP/1.1.
   - Provide `examples/security_console_demo.rs` (`cargo run --example security_console_demo`) spinning up local mock `github-upstream` and `openai-upstream` servers alongside `EdgeGateProxy` to execute and render the 5 canonical security scenarios in a live terminal table.

## Alternatives Considered
- **External Redis/Vault network calls on every request for secret TTL checks:** Rejected for the hot path. Storing `expires_at: Option<Instant>` directly in the in-memory `SecretProvider` entry achieves sub-microsecond fail-closed TTL enforcement with zero network I/O on the request path while allowing background control-plane threads to call `rotate_secret`.
- **Full CEL / Rego expression engine for request-attribute matching:** Rejected due to compilation weight, dependency surface, and latency variance. Exact header key/value matching (`required_headers`) combined with role-based access control (`required_roles`), method, and path-prefix rules covers MCP tool routing and model governance with deterministic $O(H)$ overhead and zero heap allocations on evaluation.

## Consequences & Failure Modes
- **Positive:**
  - Ephemeral secrets automatically fail closed upon TTL expiration without requiring a full proxy reload.
  - Workloads can roll over `X-EdgeGate-Token` credentials with zero dropped requests by staging a secondary token before retiring the primary token.
  - Fine-grained L7 request-attribute headers (`required_headers`) allow Keelway and IoRa to enforce per-tool and per-model authorization policies at the gateway boundary.
  - Operators and security reviewers can run `cargo run --example security_console_demo` to immediately verify all five security posture guarantees locally.
- **Failure Modes & Mitigations:**
  - *Clock skew or premature expiry on very short TTLs:* Monotonic `std::time::Instant` is used for in-memory TTL tracking so wall-clock adjustments (NTP steps) cannot prematurely expire or extend active credentials.
  - *Duplicate primary/secondary tokens across workloads:* `CompiledConfig::compile` strictly rejects any duplicate token digest across primary and secondary slots at validation time (`edgegate check` / reload rejection).
