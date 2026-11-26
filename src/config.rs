use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderName, Method};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::EdgeGateError;

/// Raw TOML configuration loaded from `edgegate.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct RawConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub workloads: Vec<WorkloadConfig>,
    #[serde(default)]
    pub pools: Vec<PoolConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub policies: Vec<PolicyRuleConfig>,
    #[serde(default)]
    pub secrets: Vec<SecretEntryConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    #[serde(default = "default_max_body_bytes")]
    pub max_request_body_bytes: usize,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_response_timeout_ms")]
    pub response_timeout_ms: u64,
    /// Graceful shutdown in-flight request drain timeout (`Milestone 5`).
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u64,
    /// Bounded flight-recorder ring buffer capacity for failed/shadow-mismatched requests (`Milestone 3`).
    #[serde(default = "default_replay_buffer_size")]
    pub replay_buffer_size: usize,
    /// Optional inbound TLS (`rustls`) listener certificate/key configuration (`Milestone 5`).
    #[serde(default)]
    pub tls: Option<ServerTlsConfig>,
    /// Optional zero-token Unix domain socket listeners bound to specific workload identities.
    #[serde(default)]
    pub unix_listeners: Vec<UnixListenerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerTlsConfig {
    #[serde(default)]
    pub cert_pem: Option<String>,
    #[serde(default)]
    pub key_pem: Option<String>,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnixListenerConfig {
    pub path: PathBuf,
    pub workload_id: String,
    pub org_id: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkloadConfig {
    pub workload_id: String,
    pub org_id: String,
    /// Either plaintext `token` (hashed at startup for local dev/demo) or pre-hashed `token_sha256` (64 hex chars).
    pub token: Option<String>,
    pub token_sha256: Option<String>,
    /// Optional secondary plaintext or pre-hashed SHA-256 token for zero-downtime token rollover (`Milestone 6`).
    #[serde(default)]
    pub secondary_token: Option<String>,
    #[serde(default)]
    pub secondary_token_sha256: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PoolConfig {
    pub name: String,
    #[serde(default)]
    pub strategy: LbStrategyConfig,
    pub backends: Vec<BackendConfig>,
    #[serde(default = "default_max_conns_per_upstream")]
    pub max_connections_per_upstream: usize,
    #[serde(default = "default_idle_ttl_ms")]
    pub idle_ttl_ms: u64,
    #[serde(default = "default_failure_threshold")]
    pub passive_failure_threshold: u32,
    #[serde(default = "default_cooldown_ms")]
    pub passive_cooldown_ms: u64,
    /// Explicitly opt in to private/loopback IPs for local or container test pools.
    /// Defaults to `false` (strict SSRF blocklist enforced).
    #[serde(default)]
    pub allow_private_ip: bool,
    /// Optional custom CA certificate PEM bundle for outbound TLS verification on this pool.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    /// Optional active HTTP health probe path (e.g. `"/healthz"`).
    #[serde(default)]
    pub health_check_path: Option<String>,
    #[serde(default = "default_health_check_interval_ms")]
    pub health_check_interval_ms: u64,
    /// Controlled retry count for idempotent (`GET`/`HEAD`/`OPTIONS`) upstream transport errors (`Milestone 5`).
    #[serde(default)]
    pub max_idempotent_retries: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbStrategyConfig {
    #[default]
    RoundRobin,
    LeastConnections,
    ConsistentHash,
    LatencyAware,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub id: String,
    /// Authority in `host:port` format.
    pub address: String,
    /// Enable outbound TLS (`rustls`) to this backend.
    #[serde(default)]
    pub tls: bool,
    /// Optional SNI hostname override when `tls = true` (defaults to backend host).
    #[serde(default)]
    pub tls_sni: Option<String>,
    /// Use HTTP/2 (`h2` via TLS ALPN or prior-knowledge `h2c`) for outbound connections (`Milestone 3`).
    #[serde(default)]
    pub http2: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub id: String,
    pub path_prefix: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub strip_prefix: bool,
    pub pool: String,
    /// Optional shadow upstream pool for asynchronous live traffic mirroring & status diffing (`Milestone 3`).
    #[serde(default)]
    pub shadow_pool: Option<String>,
    /// Optional scoped credential injection binding.
    #[serde(default)]
    pub credential: Option<CredentialBindingConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialBindingConfig {
    pub credential_ref: String,
    /// Outbound header to inject (e.g. `Authorization`, `X-Api-Key`).
    pub header_name: String,
    /// Optional prefix prepended to secret value (e.g. `"Bearer "`).
    #[serde(default)]
    pub value_prefix: String,
    /// Inspect upstream response headers/body and block with `502` if the injected secret is reflected (`Milestone 5`).
    #[serde(default)]
    pub block_secret_reflection: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRuleConfig {
    pub org_id: String,
    /// Optional workload_id restriction; if omitted, applies to all workloads in `org_id`.
    #[serde(default)]
    pub workload_id: Option<String>,
    /// Optional RBAC roles required on the authenticated workload.
    #[serde(default)]
    pub required_roles: Vec<String>,
    pub route_id: String,
    pub methods: Vec<String>,
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,
    /// Optional required request headers (`header_name -> expected_value`) (`Milestone 6`).
    #[serde(default)]
    pub required_headers: HashMap<String, String>,
    /// Optional token-bucket refill rate in requests per second (`Milestone 4`).
    #[serde(default)]
    pub rate_limit_rps: Option<u32>,
    /// Optional token-bucket burst capacity (`Milestone 4`; defaults to `rate_limit_rps` when omitted).
    #[serde(default)]
    pub rate_limit_burst: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecretEntryConfig {
    pub org_id: String,
    pub credential_ref: String,
    /// Inline secret value (for local dev/tests) OR `env` variable name to read from process environment.
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub env: Option<String>,
    /// Optional UNIX epoch expiration timestamp in seconds (`Milestone 6`).
    #[serde(default)]
    pub expires_at_epoch_s: Option<u64>,
}

fn default_max_body_bytes() -> usize {
    1024 * 1024 // 1 MiB
}

fn default_connect_timeout_ms() -> u64 {
    2_000
}

fn default_response_timeout_ms() -> u64 {
    10_000
}

fn default_drain_timeout_ms() -> u64 {
    5_000
}

fn default_replay_buffer_size() -> usize {
    64
}

fn default_max_conns_per_upstream() -> usize {
    64
}

fn default_idle_ttl_ms() -> u64 {
    30_000
}

fn default_failure_threshold() -> u32 {
    3
}

fn default_cooldown_ms() -> u64 {
    5_000
}

fn default_health_check_interval_ms() -> u64 {
    5_000
}

fn default_path_prefix() -> String {
    "/".to_string()
}

/// Immutable, validated runtime snapshot stored in `ArcSwap<RuntimeSnapshot>`.
#[derive(Debug, Clone)]
pub struct CompiledConfig {
    pub listen_addr: SocketAddr,
    pub max_request_body_bytes: usize,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    pub drain_timeout: Duration,
    pub replay_buffer_size: usize,
    pub inbound_tls: Option<Arc<RustlsServerConfig>>,
    pub unix_listeners: Vec<CompiledUnixListener>,
    pub workloads: HashMap<[u8; 32], CompiledWorkload>,
    pub pools: HashMap<String, CompiledPool>,
    pub routes: Vec<CompiledRoute>,
    pub policies: Vec<CompiledPolicyRule>,
    pub secrets: HashMap<(String, String), CompiledSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSecret {
    pub value: String,
    pub expires_at_epoch_s: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledUnixListener {
    pub path: PathBuf,
    pub workload: CompiledWorkload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledWorkload {
    pub workload_id: String,
    pub org_id: String,
    pub roles: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledPool {
    pub name: String,
    pub strategy: LbStrategyConfig,
    pub backends: Vec<CompiledBackend>,
    pub max_connections_per_upstream: usize,
    pub idle_ttl: Duration,
    pub passive_failure_threshold: u32,
    pub passive_cooldown: Duration,
    pub allow_private_ip: bool,
    pub custom_ca_certs: Vec<CertificateDer<'static>>,
    pub health_check_path: Option<String>,
    pub health_check_interval: Duration,
    pub max_idempotent_retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledBackend {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub tls: bool,
    pub tls_sni: String,
    pub http2: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledRoute {
    pub id: String,
    pub path_prefix: String,
    pub host: Option<String>,
    pub strip_prefix: bool,
    pub pool: String,
    pub shadow_pool: Option<String>,
    pub credential: Option<CompiledCredentialBinding>,
}

#[derive(Debug, Clone)]
pub struct CompiledCredentialBinding {
    pub credential_ref: String,
    pub header_name: HeaderName,
    pub value_prefix: String,
    pub block_secret_reflection: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicyRule {
    pub org_id: String,
    pub workload_id: Option<String>,
    pub required_roles: HashSet<String>,
    pub route_id: String,
    pub methods: HashSet<Method>,
    pub path_prefix: String,
    pub required_headers: HashMap<String, String>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
}

impl CompiledConfig {
    pub fn from_file(path: &Path) -> Result<Arc<Self>, EdgeGateError> {
        let raw_text = std::fs::read_to_string(path).map_err(|e| {
            EdgeGateError::Config(format!("failed to read config {}: {e}", path.display()))
        })?;
        Self::from_toml_str(&raw_text)
    }

    pub fn from_toml_str(input: &str) -> Result<Arc<Self>, EdgeGateError> {
        let raw: RawConfig = toml::from_str(input)
            .map_err(|e| EdgeGateError::Config(format!("invalid TOML configuration: {e}")))?;
        Self::compile(raw).map(Arc::new)
    }

    pub fn compile(raw: RawConfig) -> Result<Self, EdgeGateError> {
        let listen_addr: SocketAddr = raw.server.listen_addr.parse().map_err(|e| {
            EdgeGateError::Config(format!(
                "invalid server.listen_addr '{}': {e}",
                raw.server.listen_addr
            ))
        })?;

        if raw.server.max_request_body_bytes == 0 {
            return Err(EdgeGateError::Config(
                "server.max_request_body_bytes must be > 0".to_string(),
            ));
        }
        if raw.server.connect_timeout_ms == 0
            || raw.server.response_timeout_ms == 0
            || raw.server.drain_timeout_ms == 0
        {
            return Err(EdgeGateError::Config(
                "server timeouts must be > 0".to_string(),
            ));
        }

        let inbound_tls = match raw.server.tls {
            Some(ref tls_cfg) => Some(compile_server_tls(tls_cfg)?),
            None => None,
        };

        let mut unix_listeners = Vec::with_capacity(raw.server.unix_listeners.len());
        let mut seen_uds_paths = HashSet::new();
        for u in raw.server.unix_listeners {
            if u.workload_id.trim().is_empty() || u.org_id.trim().is_empty() {
                return Err(EdgeGateError::Config(
                    "unix_listener workload_id and org_id must be non-empty".to_string(),
                ));
            }
            if u.path.as_os_str().is_empty() || !seen_uds_paths.insert(u.path.clone()) {
                return Err(EdgeGateError::Config(format!(
                    "empty or duplicate unix_listener path '{}'",
                    u.path.display()
                )));
            }
            unix_listeners.push(CompiledUnixListener {
                path: u.path,
                workload: CompiledWorkload {
                    workload_id: u.workload_id,
                    org_id: u.org_id,
                    roles: u.roles.into_iter().collect(),
                },
            });
        }

        let mut workloads = HashMap::with_capacity(raw.workloads.len());
        for w in raw.workloads {
            if w.workload_id.trim().is_empty() || w.org_id.trim().is_empty() {
                return Err(EdgeGateError::Config(
                    "workload_id and org_id must be non-empty".to_string(),
                ));
            }
            let digest = match (w.token, w.token_sha256) {
                (Some(plain), None) => {
                    if plain.is_empty() {
                        return Err(EdgeGateError::Config(format!(
                            "workload '{}' has empty token",
                            w.workload_id
                        )));
                    }
                    sha256_digest(plain.as_bytes())
                }
                (None, Some(hex_hash)) => decode_sha256_hex(&hex_hash).map_err(|msg| {
                    EdgeGateError::Config(format!(
                        "workload '{}' invalid token_sha256: {msg}",
                        w.workload_id
                    ))
                })?,
                (Some(_), Some(_)) => {
                    return Err(EdgeGateError::Config(format!(
                        "workload '{}' cannot set both token and token_sha256",
                        w.workload_id
                    )));
                }
                (None, None) => {
                    return Err(EdgeGateError::Config(format!(
                        "workload '{}' must set either token or token_sha256",
                        w.workload_id
                    )));
                }
            };
            let compiled_workload = CompiledWorkload {
                workload_id: w.workload_id.clone(),
                org_id: w.org_id,
                roles: w.roles.into_iter().collect(),
            };
            if workloads
                .insert(digest, compiled_workload.clone())
                .is_some()
            {
                return Err(EdgeGateError::Config(format!(
                    "duplicate workload token detected for '{}'",
                    w.workload_id
                )));
            }
            let secondary_digest = match (w.secondary_token, w.secondary_token_sha256) {
                (Some(plain), None) => {
                    if plain.is_empty() {
                        return Err(EdgeGateError::Config(format!(
                            "workload '{}' has empty secondary_token",
                            w.workload_id
                        )));
                    }
                    Some(sha256_digest(plain.as_bytes()))
                }
                (None, Some(hex_hash)) => Some(decode_sha256_hex(&hex_hash).map_err(|msg| {
                    EdgeGateError::Config(format!(
                        "workload '{}' invalid secondary_token_sha256: {msg}",
                        w.workload_id
                    ))
                })?),
                (Some(_), Some(_)) => {
                    return Err(EdgeGateError::Config(format!(
                        "workload '{}' cannot set both secondary_token and secondary_token_sha256",
                        w.workload_id
                    )));
                }
                (None, None) => None,
            };
            if let Some(sec_digest) = secondary_digest {
                if workloads.insert(sec_digest, compiled_workload).is_some() {
                    return Err(EdgeGateError::Config(format!(
                        "duplicate workload secondary_token detected for '{}'",
                        w.workload_id
                    )));
                }
            }
        }

        let mut pools = HashMap::with_capacity(raw.pools.len());
        for p in raw.pools {
            if p.name.trim().is_empty() {
                return Err(EdgeGateError::Config(
                    "pool name must be non-empty".to_string(),
                ));
            }
            if p.backends.is_empty() {
                return Err(EdgeGateError::Config(format!(
                    "pool '{}' must define at least one backend",
                    p.name
                )));
            }
            if p.max_connections_per_upstream == 0 {
                return Err(EdgeGateError::Config(format!(
                    "pool '{}' max_connections_per_upstream must be > 0",
                    p.name
                )));
            }
            if p.passive_failure_threshold == 0 {
                return Err(EdgeGateError::Config(format!(
                    "pool '{}' passive_failure_threshold must be > 0",
                    p.name
                )));
            }
            if let Some(ref hc_path) = p.health_check_path {
                if !hc_path.starts_with('/') {
                    return Err(EdgeGateError::Config(format!(
                        "pool '{}' health_check_path '{}' must start with '/'",
                        p.name, hc_path
                    )));
                }
            }

            let custom_ca_certs = match p.ca_cert_pem {
                Some(ref pem) => parse_pem_certs(pem).map_err(|msg| {
                    EdgeGateError::Config(format!("pool '{}' invalid ca_cert_pem: {msg}", p.name))
                })?,
                None => Vec::new(),
            };

            let mut compiled_backends = Vec::with_capacity(p.backends.len());
            let mut seen_ids = HashSet::new();
            for b in p.backends {
                if b.id.trim().is_empty() || !seen_ids.insert(b.id.clone()) {
                    return Err(EdgeGateError::Config(format!(
                        "pool '{}' has empty or duplicate backend id '{}'",
                        p.name, b.id
                    )));
                }
                let (host, port) = parse_authority(&b.address).map_err(|msg| {
                    EdgeGateError::Config(format!(
                        "pool '{}' backend '{}' invalid address '{}': {msg}",
                        p.name, b.id, b.address
                    ))
                })?;
                let tls_sni = b.tls_sni.unwrap_or_else(|| host.clone());
                if b.tls && tls_sni.trim().is_empty() {
                    return Err(EdgeGateError::Config(format!(
                        "pool '{}' backend '{}' tls_sni must be non-empty",
                        p.name, b.id
                    )));
                }
                compiled_backends.push(CompiledBackend {
                    id: b.id,
                    host,
                    port,
                    authority: b.address,
                    tls: b.tls,
                    tls_sni,
                    http2: b.http2,
                });
            }

            if pools
                .insert(
                    p.name.clone(),
                    CompiledPool {
                        name: p.name.clone(),
                        strategy: p.strategy,
                        backends: compiled_backends,
                        max_connections_per_upstream: p.max_connections_per_upstream,
                        idle_ttl: Duration::from_millis(p.idle_ttl_ms),
                        passive_failure_threshold: p.passive_failure_threshold,
                        passive_cooldown: Duration::from_millis(p.passive_cooldown_ms),
                        allow_private_ip: p.allow_private_ip,
                        custom_ca_certs,
                        health_check_path: p.health_check_path,
                        health_check_interval: Duration::from_millis(
                            p.health_check_interval_ms.max(100),
                        ),
                        max_idempotent_retries: p.max_idempotent_retries,
                    },
                )
                .is_some()
            {
                return Err(EdgeGateError::Config(format!(
                    "duplicate pool name '{}'",
                    p.name
                )));
            }
        }

        let mut routes = Vec::with_capacity(raw.routes.len());
        let mut route_ids = HashSet::new();
        for r in raw.routes {
            if r.id.trim().is_empty() || !route_ids.insert(r.id.clone()) {
                return Err(EdgeGateError::Config(format!(
                    "empty or duplicate route id '{}'",
                    r.id
                )));
            }
            if !r.path_prefix.starts_with('/') {
                return Err(EdgeGateError::Config(format!(
                    "route '{}' path_prefix '{}' must start with '/'",
                    r.id, r.path_prefix
                )));
            }
            if !pools.contains_key(&r.pool) {
                return Err(EdgeGateError::Config(format!(
                    "route '{}' references unknown pool '{}'",
                    r.id, r.pool
                )));
            }
            if let Some(ref sp) = r.shadow_pool {
                if !pools.contains_key(sp) {
                    return Err(EdgeGateError::Config(format!(
                        "route '{}' references unknown shadow_pool '{}'",
                        r.id, sp
                    )));
                }
            }
            let credential = match r.credential {
                Some(c) => {
                    if c.credential_ref.trim().is_empty() {
                        return Err(EdgeGateError::Config(format!(
                            "route '{}' credential_ref must be non-empty",
                            r.id
                        )));
                    }
                    let header_name =
                        HeaderName::from_bytes(c.header_name.as_bytes()).map_err(|e| {
                            EdgeGateError::Config(format!(
                                "route '{}' invalid credential header_name '{}': {e}",
                                r.id, c.header_name
                            ))
                        })?;
                    Some(CompiledCredentialBinding {
                        credential_ref: c.credential_ref,
                        header_name,
                        value_prefix: c.value_prefix,
                        block_secret_reflection: c.block_secret_reflection,
                    })
                }
                None => None,
            };

            routes.push(CompiledRoute {
                id: r.id,
                path_prefix: r.path_prefix,
                host: r.host.map(|h| h.to_ascii_lowercase()),
                strip_prefix: r.strip_prefix,
                pool: r.pool,
                shadow_pool: r.shadow_pool,
                credential,
            });
        }
        routes.sort_by(|a, b| {
            b.path_prefix
                .len()
                .cmp(&a.path_prefix.len())
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut policies = Vec::with_capacity(raw.policies.len());
        for pol in raw.policies {
            if !route_ids.contains(&pol.route_id) {
                return Err(EdgeGateError::Config(format!(
                    "policy references unknown route_id '{}'",
                    pol.route_id
                )));
            }
            if !pol.path_prefix.starts_with('/') {
                return Err(EdgeGateError::Config(format!(
                    "policy path_prefix '{}' must start with '/'",
                    pol.path_prefix
                )));
            }
            if pol.methods.is_empty() {
                return Err(EdgeGateError::Config(format!(
                    "policy for route '{}' must list at least one HTTP method",
                    pol.route_id
                )));
            }
            if pol.rate_limit_rps == Some(0) {
                return Err(EdgeGateError::Config(format!(
                    "policy for route '{}' rate_limit_rps must be > 0",
                    pol.route_id
                )));
            }
            if pol.rate_limit_burst == Some(0) {
                return Err(EdgeGateError::Config(format!(
                    "policy for route '{}' rate_limit_burst must be > 0",
                    pol.route_id
                )));
            }
            let mut methods = HashSet::with_capacity(pol.methods.len());
            for m in pol.methods {
                let parsed =
                    Method::from_bytes(m.to_ascii_uppercase().as_bytes()).map_err(|e| {
                        EdgeGateError::Config(format!("invalid HTTP method '{m}': {e}"))
                    })?;
                methods.insert(parsed);
            }
            let mut required_headers = HashMap::with_capacity(pol.required_headers.len());
            for (k, v) in pol.required_headers {
                let lower_key = k.trim().to_ascii_lowercase();
                if lower_key.is_empty() {
                    return Err(EdgeGateError::Config(format!(
                        "policy for route '{}' has empty required_headers key",
                        pol.route_id
                    )));
                }
                HeaderName::from_bytes(lower_key.as_bytes()).map_err(|e| {
                    EdgeGateError::Config(format!(
                        "policy for route '{}' invalid required_headers key '{k}': {e}",
                        pol.route_id
                    ))
                })?;
                required_headers.insert(lower_key, v);
            }
            policies.push(CompiledPolicyRule {
                org_id: pol.org_id,
                workload_id: pol.workload_id,
                required_roles: pol.required_roles.into_iter().collect(),
                route_id: pol.route_id,
                methods,
                path_prefix: pol.path_prefix,
                required_headers,
                rate_limit_rps: pol.rate_limit_rps,
                rate_limit_burst: pol.rate_limit_burst,
            });
        }

        let mut secrets = HashMap::with_capacity(raw.secrets.len());
        for s in raw.secrets {
            if s.org_id.trim().is_empty() || s.credential_ref.trim().is_empty() {
                return Err(EdgeGateError::Config(
                    "secret org_id and credential_ref must be non-empty".to_string(),
                ));
            }
            let resolved_value = match (s.value, s.env) {
                (Some(val), None) => val,
                (None, Some(env_var)) => std::env::var(&env_var).map_err(|_| {
                    EdgeGateError::Config(format!(
                        "secret '{}' for org '{}' requires unset environment variable '{}'",
                        s.credential_ref, s.org_id, env_var
                    ))
                })?,
                (Some(_), Some(_)) => {
                    return Err(EdgeGateError::Config(format!(
                        "secret '{}' cannot set both value and env",
                        s.credential_ref
                    )));
                }
                (None, None) => {
                    return Err(EdgeGateError::Config(format!(
                        "secret '{}' must set either value or env",
                        s.credential_ref
                    )));
                }
            };
            secrets.insert(
                (s.org_id, s.credential_ref),
                CompiledSecret {
                    value: resolved_value,
                    expires_at_epoch_s: s.expires_at_epoch_s,
                },
            );
        }

        Ok(Self {
            listen_addr,
            max_request_body_bytes: raw.server.max_request_body_bytes,
            connect_timeout: Duration::from_millis(raw.server.connect_timeout_ms),
            response_timeout: Duration::from_millis(raw.server.response_timeout_ms),
            drain_timeout: Duration::from_millis(raw.server.drain_timeout_ms),
            replay_buffer_size: raw.server.replay_buffer_size.max(1),
            inbound_tls,
            unix_listeners,
            workloads,
            pools,
            routes,
            policies,
            secrets,
        })
    }
}

fn compile_server_tls(cfg: &ServerTlsConfig) -> Result<Arc<RustlsServerConfig>, EdgeGateError> {
    let cert_pem = match (&cfg.cert_pem, &cfg.cert_path) {
        (Some(pem), None) => pem.clone(),
        (None, Some(path)) => std::fs::read_to_string(path).map_err(|e| {
            EdgeGateError::Config(format!(
                "failed to read server.tls.cert_path '{}': {e}",
                path.display()
            ))
        })?,
        (Some(_), Some(_)) => {
            return Err(EdgeGateError::Config(
                "server.tls cannot set both cert_pem and cert_path".to_string(),
            ));
        }
        (None, None) => {
            return Err(EdgeGateError::Config(
                "server.tls must set either cert_pem or cert_path".to_string(),
            ));
        }
    };

    let key_pem = match (&cfg.key_pem, &cfg.key_path) {
        (Some(pem), None) => pem.clone(),
        (None, Some(path)) => std::fs::read_to_string(path).map_err(|e| {
            EdgeGateError::Config(format!(
                "failed to read server.tls.key_path '{}': {e}",
                path.display()
            ))
        })?,
        (Some(_), Some(_)) => {
            return Err(EdgeGateError::Config(
                "server.tls cannot set both key_pem and key_path".to_string(),
            ));
        }
        (None, None) => {
            return Err(EdgeGateError::Config(
                "server.tls must set either key_pem or key_path".to_string(),
            ));
        }
    };

    let certs = parse_pem_certs(&cert_pem)
        .map_err(|msg| EdgeGateError::Config(format!("invalid server.tls certificate: {msg}")))?;
    let key = parse_pem_private_key(&key_pem)
        .map_err(|msg| EdgeGateError::Config(format!("invalid server.tls private key: {msg}")))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_cfg = RustlsServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| EdgeGateError::Config(format!("failed to configure TLS versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| EdgeGateError::Config(format!("invalid server.tls cert/key pair: {e}")))?;
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(tls_cfg))
}

fn parse_pem_private_key(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    let mut reader = Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("failed to parse PEM private key: {e}"))?
        .ok_or_else(|| "no private key found in PEM".to_string())
}

pub fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn decode_sha256_hex(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut reader = Cursor::new(pem.as_bytes());
    let mut certs = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        let cert = item.map_err(|e| format!("failed to parse PEM certificate: {e}"))?;
        certs.push(cert);
    }
    if certs.is_empty() {
        return Err("no certificates found in ca_cert_pem".to_string());
    }
    Ok(certs)
}

fn parse_authority(authority: &str) -> Result<(String, u16), String> {
    if authority.contains("://") || authority.contains('/') {
        return Err("expected host:port without scheme or path".to_string());
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port_part) = rest
            .split_once("]:")
            .ok_or_else(|| "IPv6 authority must be [addr]:port".to_string())?;
        let port: u16 = port_part
            .parse()
            .map_err(|e| format!("invalid port '{port_part}': {e}"))?;
        if host.is_empty() || port == 0 {
            return Err("empty host or zero port".to_string());
        }
        return Ok((host.to_string(), port));
    }
    let (host, port_part) = authority
        .rsplit_once(':')
        .ok_or_else(|| "expected host:port".to_string())?;
    let port: u16 = port_part
        .parse()
        .map_err(|e| format!("invalid port '{port_part}': {e}"))?;
    if host.is_empty() || port == 0 {
        return Err("empty host or zero port".to_string());
    }
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOML: &str = r#"
[server]
listen_addr = "127.0.0.1:8080"

[[workloads]]
workload_id = "agent-1"
org_id = "org-alpha"
token = "tok-alpha-1"
roles = ["repo:read"]

[[pools]]
name = "mock-api"
strategy = "consistent_hash"
allow_private_ip = true
backends = [
  { id = "a", address = "127.0.0.1:9001", tls = false, http2 = true },
  { id = "b", address = "127.0.0.1:9002", tls = true, tls_sni = "api.internal", http2 = true },
]

[[routes]]
id = "github"
path_prefix = "/v1/github"
strip_prefix = true
pool = "mock-api"
[routes.credential]
credential_ref = "github_pat"
header_name = "Authorization"
value_prefix = "Bearer "

[[policies]]
org_id = "org-alpha"
required_roles = ["repo:read"]
route_id = "github"
methods = ["GET"]
path_prefix = "/v1/github/repos"

[[secrets]]
org_id = "org-alpha"
credential_ref = "github_pat"
value = "ghp_secret_123"
"#;

    #[test]
    fn compiles_valid_config() {
        let cfg = CompiledConfig::from_toml_str(VALID_TOML);
        assert!(cfg.is_ok());
        let cfg = cfg.unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert_eq!(cfg.workloads.len(), 1);
        assert_eq!(cfg.pools.len(), 1);
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.policies.len(), 1);
    }

    #[test]
    fn rejects_unknown_pool_in_route() {
        let bad = VALID_TOML.replace("pool = \"mock-api\"", "pool = \"missing\"");
        let err = CompiledConfig::from_toml_str(&bad).unwrap_err();
        assert!(err.to_string().contains("unknown pool"));
    }

    #[test]
    fn rejects_route_with_scheme_in_backend_address() {
        let bad = VALID_TOML.replace("127.0.0.1:9001", "http://127.0.0.1:9001");
        let err = CompiledConfig::from_toml_str(&bad).unwrap_err();
        assert!(err.to_string().contains("without scheme"));
    }
}
