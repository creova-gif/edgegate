use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderName, HeaderValue, Method};
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
    /// Optional plaintext admin control-plane token (`Milestone 7`).
    #[serde(default)]
    pub admin_token: Option<String>,
    /// Optional pre-hashed SHA-256 admin control-plane token (64 hex chars, `Milestone 7`).
    #[serde(default)]
    pub admin_token_sha256: Option<String>,
    #[serde(default)]
    pub protect_observability: bool,
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
    #[serde(default)]
    pub client_ca_cert_pem: Option<String>,
    #[serde(default)]
    pub client_ca_cert_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnixListenerConfig {
    pub path: PathBuf,
    pub workload_id: String,
    pub org_id: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub max_concurrent_requests: Option<usize>,
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
    #[serde(default)]
    pub max_concurrent_requests: Option<usize>,
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
    /// Optional client certificate PEM chain for outbound mTLS authentication (`Milestone 8`).
    #[serde(default)]
    pub client_cert_pem: Option<String>,
    /// Optional client private key PEM for outbound mTLS authentication (`Milestone 8`).
    #[serde(default)]
    pub client_key_pem: Option<String>,
    /// Optional active HTTP health probe path (e.g. `"/healthz"`).
    #[serde(default)]
    pub health_check_path: Option<String>,
    #[serde(default = "default_health_check_interval_ms")]
    pub health_check_interval_ms: u64,
    /// Controlled retry count for idempotent (`GET`/`HEAD`/`OPTIONS`) upstream transport errors (`Milestone 5`).
    #[serde(default)]
    pub max_idempotent_retries: u32,
    #[serde(default = "default_dns_cache_ttl_ms")]
    pub dns_cache_ttl_ms: u64,
}

fn default_dns_cache_ttl_ms() -> u64 {
    10_000
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
    /// Relative load-balancing weight (`Milestone 7`; default `1`, must be `> 0`).
    #[serde(default = "default_backend_weight")]
    pub weight: u32,
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
    /// Optional per-route response timeout override in milliseconds (`Milestone 9`).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Optional maximum upstream response body size in bytes (`Milestone 9`).
    #[serde(default)]
    pub max_response_body_bytes: Option<usize>,
    /// Optional response header names to strip before returning responses to workloads (`Milestone 8`).
    #[serde(default)]
    pub strip_response_headers: Vec<String>,
    /// Optional response headers to inject on responses returned to workloads (`Milestone 8`).
    #[serde(default)]
    pub inject_response_headers: HashMap<String, String>,
    /// Optional scoped credential injection binding.
    #[serde(default)]
    pub credential: Option<CredentialBindingConfig>,
    /// Optional outbound cryptographic request signing binding (`INV-23`).
    #[serde(default)]
    pub request_signing: Option<RequestSigningConfig>,
    /// Optional outbound AWS SigV4 request signing configuration (`INV-25`).
    #[serde(default)]
    pub aws_sigv4: Option<AwsSigV4Config>,
    /// Optional route-level CORS preflight & browser interoperability policy (`INV-27`).
    #[serde(default)]
    pub cors: Option<CorsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_cors_methods")]
    pub allowed_methods: Vec<String>,
    #[serde(default = "default_cors_headers")]
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default = "default_cors_max_age_secs")]
    pub max_age_secs: u64,
}

fn default_cors_methods() -> Vec<String> {
    vec!["GET".to_string(), "POST".to_string(), "OPTIONS".to_string()]
}

fn default_cors_headers() -> Vec<String> {
    vec![
        "content-type".to_string(),
        "x-edgegate-token".to_string(),
        "traceparent".to_string(),
        "tracestate".to_string(),
    ]
}

fn default_cors_max_age_secs() -> u64 {
    600
}

#[derive(Debug, Clone)]
pub struct CompiledCorsConfig {
    pub allowed_origins: HashSet<String>,
    pub allow_methods_value: HeaderValue,
    pub allow_headers_value: HeaderValue,
    pub expose_headers_value: Option<HeaderValue>,
    pub max_age_value: HeaderValue,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsSigV4Config {
    pub access_key_ref: String,
    pub secret_key_ref: String,
    pub region: String,
    pub service: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledAwsSigV4 {
    pub access_key_ref: String,
    pub secret_key_ref: String,
    pub region: String,
    pub service: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsSigV4Headers {
    pub authorization: String,
    pub amz_date: String,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestSigningConfig {
    pub credential_ref: String,
    #[serde(default = "default_signature_header")]
    pub signature_header: String,
    #[serde(default = "default_timestamp_header")]
    pub timestamp_header: String,
}

fn default_signature_header() -> String {
    "x-edgegate-signature-256".to_string()
}

fn default_timestamp_header() -> String {
    "x-edgegate-timestamp".to_string()
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
    /// Optional forbidden query parameter keys blocked on this rule (`Milestone 7`).
    #[serde(default)]
    pub forbidden_query_params: Vec<String>,
    /// Optional egress DLP payload substrings blocked on outbound request bodies (`Milestone 8`).
    #[serde(default)]
    pub blocked_body_substrings: Vec<String>,
    /// Optional JSON-RPC 2.0 / MCP allowed tool-call methods (`Milestone 9`).
    #[serde(default)]
    pub allowed_jsonrpc_methods: Option<Vec<String>>,
    /// Optional per-rule request body size limit in bytes (`Milestone 7`; must be `> 0` if `Some`).
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
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

fn default_backend_weight() -> u32 {
    1
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
    pub admin_token_digest: Option<[u8; 32]>,
    pub protect_observability: bool,
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
    pub max_concurrent_requests: Option<usize>,
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
    pub client_cert_chain: Vec<CertificateDer<'static>>,
    pub client_key_pem: Option<String>,
    pub health_check_path: Option<String>,
    pub health_check_interval: Duration,
    pub max_idempotent_retries: u32,
    pub dns_cache_ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledBackend {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub weight: u32,
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
    pub response_timeout: Option<Duration>,
    pub max_response_body_bytes: Option<usize>,
    pub strip_response_headers: Vec<HeaderName>,
    pub inject_response_headers: Vec<(HeaderName, HeaderValue)>,
    pub credential: Option<CompiledCredentialBinding>,
    pub request_signing: Option<CompiledRequestSigning>,
    pub aws_sigv4: Option<CompiledAwsSigV4>,
    pub cors: Option<CompiledCorsConfig>,
}

#[derive(Debug, Clone)]
pub struct CompiledRequestSigning {
    pub credential_ref: String,
    pub signature_header: HeaderName,
    pub timestamp_header: HeaderName,
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
    pub forbidden_query_params: Vec<String>,
    pub blocked_body_substrings: Vec<String>,
    pub allowed_jsonrpc_methods: Option<Vec<String>>,
    pub max_body_bytes: Option<usize>,
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

        let admin_token_digest = match (raw.server.admin_token, raw.server.admin_token_sha256) {
            (Some(plain), None) => {
                if plain.trim().is_empty() {
                    return Err(EdgeGateError::Config(
                        "server.admin_token must be non-empty".to_string(),
                    ));
                }
                Some(sha256_digest(plain.trim().as_bytes()))
            }
            (None, Some(hex_hash)) => Some(decode_sha256_hex(&hex_hash).map_err(|msg| {
                EdgeGateError::Config(format!("invalid server.admin_token_sha256: {msg}"))
            })?),
            (Some(_), Some(_)) => {
                return Err(EdgeGateError::Config(
                    "server cannot set both admin_token and admin_token_sha256".to_string(),
                ));
            }
            (None, None) => None,
        };

        if raw.server.protect_observability && admin_token_digest.is_none() {
            return Err(EdgeGateError::Config(
                "server.protect_observability = true requires server.admin_token or server.admin_token_sha256".to_string(),
            ));
        }

        let inbound_tls = match raw.server.tls {
            Some(ref tls_cfg) => Some(compile_server_tls(tls_cfg)?),
            None => None,
        };

        let mut seen_workload_concurrency: HashMap<(String, String), Option<usize>> =
            HashMap::new();
        let mut unix_listeners = Vec::with_capacity(raw.server.unix_listeners.len());
        let mut seen_uds_paths = HashSet::new();
        for u in raw.server.unix_listeners {
            if u.workload_id.trim().is_empty() || u.org_id.trim().is_empty() {
                return Err(EdgeGateError::Config(
                    "unix_listener workload_id and org_id must be non-empty".to_string(),
                ));
            }
            if u.max_concurrent_requests == Some(0) {
                return Err(EdgeGateError::Config(
                    "max_concurrent_requests must be > 0".to_string(),
                ));
            }
            let key = (u.org_id.clone(), u.workload_id.clone());
            if let Some(&existing_limit) = seen_workload_concurrency.get(&key) {
                if existing_limit != u.max_concurrent_requests {
                    return Err(EdgeGateError::Config(format!(
                        "conflicting max_concurrent_requests for workload '{}' in org '{}'",
                        u.workload_id, u.org_id
                    )));
                }
            } else {
                seen_workload_concurrency.insert(key, u.max_concurrent_requests);
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
                    max_concurrent_requests: u.max_concurrent_requests,
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
            if w.max_concurrent_requests == Some(0) {
                return Err(EdgeGateError::Config(
                    "max_concurrent_requests must be > 0".to_string(),
                ));
            }
            let key = (w.org_id.clone(), w.workload_id.clone());
            if let Some(&existing_limit) = seen_workload_concurrency.get(&key) {
                if existing_limit != w.max_concurrent_requests {
                    return Err(EdgeGateError::Config(format!(
                        "conflicting max_concurrent_requests for workload '{}' in org '{}'",
                        w.workload_id, w.org_id
                    )));
                }
            } else {
                seen_workload_concurrency.insert(key, w.max_concurrent_requests);
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
                max_concurrent_requests: w.max_concurrent_requests,
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

            let (client_cert_chain, client_key_pem) = match (p.client_cert_pem, p.client_key_pem) {
                (Some(cert_pem), Some(key_pem)) => {
                    let certs = parse_pem_certs(&cert_pem).map_err(|msg| {
                        EdgeGateError::Config(format!(
                            "pool '{}' invalid client_cert_pem: {msg}",
                            p.name
                        ))
                    })?;
                    let key_der = parse_pem_private_key(&key_pem).map_err(|msg| {
                        EdgeGateError::Config(format!(
                            "pool '{}' invalid client_key_pem: {msg}",
                            p.name
                        ))
                    })?;
                    let provider = Arc::new(rustls::crypto::ring::default_provider());
                    rustls::ClientConfig::builder_with_provider(provider)
                        .with_safe_default_protocol_versions()
                        .map_err(|e| {
                            EdgeGateError::Config(format!(
                                "pool '{}' TLS version config error: {e}",
                                p.name
                            ))
                        })?
                        .with_root_certificates(rustls::RootCertStore::empty())
                        .with_client_auth_cert(certs.clone(), key_der)
                        .map_err(|e| {
                            EdgeGateError::Config(format!(
                                "pool '{}' mismatched client_cert_pem / client_key_pem: {e}",
                                p.name
                            ))
                        })?;
                    (certs, Some(key_pem))
                }
                (None, None) => (Vec::new(), None),
                (Some(_), None) | (None, Some(_)) => {
                    return Err(EdgeGateError::Config(format!(
                        "pool '{}' must set both client_cert_pem and client_key_pem for outbound mTLS",
                        p.name
                    )));
                }
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
                if b.weight == 0 {
                    return Err(EdgeGateError::Config(format!(
                        "pool '{}' backend '{}' weight must be > 0",
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
                    weight: b.weight,
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
                        client_cert_chain,
                        client_key_pem,
                        health_check_path: p.health_check_path,
                        health_check_interval: Duration::from_millis(
                            p.health_check_interval_ms.max(100),
                        ),
                        max_idempotent_retries: p.max_idempotent_retries,
                        dns_cache_ttl: Duration::from_millis(p.dns_cache_ttl_ms),
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
            if r.timeout_ms == Some(0) {
                return Err(EdgeGateError::Config(format!(
                    "route '{}' timeout_ms must be > 0",
                    r.id
                )));
            }
            if r.max_response_body_bytes == Some(0) {
                return Err(EdgeGateError::Config(format!(
                    "route '{}' max_response_body_bytes must be > 0",
                    r.id
                )));
            }
            let response_timeout = r.timeout_ms.map(Duration::from_millis);
            let max_response_body_bytes = r.max_response_body_bytes;
            let mut strip_response_headers = Vec::with_capacity(r.strip_response_headers.len());
            for raw_hdr in r.strip_response_headers {
                let trimmed = raw_hdr.trim();
                if trimmed.is_empty() {
                    return Err(EdgeGateError::Config(format!(
                        "route '{}' has empty strip_response_headers entry",
                        r.id
                    )));
                }
                let hdr_name = HeaderName::from_bytes(trimmed.as_bytes()).map_err(|e| {
                    EdgeGateError::Config(format!(
                        "route '{}' invalid strip_response_headers name '{raw_hdr}': {e}",
                        r.id
                    ))
                })?;
                strip_response_headers.push(hdr_name);
            }
            let mut inject_response_headers = Vec::with_capacity(r.inject_response_headers.len());
            let mut seen_inject = HashSet::new();
            for (raw_name, raw_val) in r.inject_response_headers {
                let trimmed = raw_name.trim();
                if trimmed.is_empty() {
                    return Err(EdgeGateError::Config(format!(
                        "route '{}' has empty inject_response_headers key",
                        r.id
                    )));
                }
                let hdr_name = HeaderName::from_bytes(trimmed.as_bytes()).map_err(|e| {
                    EdgeGateError::Config(format!(
                        "route '{}' invalid inject_response_headers key '{raw_name}': {e}",
                        r.id
                    ))
                })?;
                if !seen_inject.insert(hdr_name.clone()) {
                    return Err(EdgeGateError::Config(format!(
                        "route '{}' has duplicate inject_response_headers key '{}'",
                        r.id, hdr_name
                    )));
                }
                let hdr_val = HeaderValue::from_str(&raw_val).map_err(|e| {
                    EdgeGateError::Config(format!(
                        "route '{}' invalid inject_response_headers value for '{raw_name}': {e}",
                        r.id
                    ))
                })?;
                inject_response_headers.push((hdr_name, hdr_val));
            }
            inject_response_headers.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
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
            let request_signing = match r.request_signing {
                Some(s) => {
                    if s.credential_ref.trim().is_empty() {
                        return Err(EdgeGateError::Config(format!(
                            "route '{}' request_signing credential_ref must be non-empty",
                            r.id
                        )));
                    }
                    let signature_header = HeaderName::from_bytes(
                        s.signature_header.trim().as_bytes(),
                    )
                    .map_err(|e| {
                        EdgeGateError::Config(format!(
                            "route '{}' invalid request_signing signature_header '{}': {e}",
                            r.id, s.signature_header
                        ))
                    })?;
                    let timestamp_header = HeaderName::from_bytes(
                        s.timestamp_header.trim().as_bytes(),
                    )
                    .map_err(|e| {
                        EdgeGateError::Config(format!(
                            "route '{}' invalid request_signing timestamp_header '{}': {e}",
                            r.id, s.timestamp_header
                        ))
                    })?;
                    if signature_header == timestamp_header {
                        return Err(EdgeGateError::Config(format!(
                            "route '{}' request_signing signature_header and timestamp_header must be different",
                            r.id
                        )));
                    }
                    Some(CompiledRequestSigning {
                        credential_ref: s.credential_ref,
                        signature_header,
                        timestamp_header,
                    })
                }
                None => None,
            };

            let aws_sigv4 = match r.aws_sigv4 {
                Some(s) => {
                    if s.access_key_ref.trim().is_empty()
                        || s.secret_key_ref.trim().is_empty()
                        || s.region.trim().is_empty()
                        || s.service.trim().is_empty()
                    {
                        return Err(EdgeGateError::Config(format!(
                            "route '{}' aws_sigv4 access_key_ref, secret_key_ref, region, and service must be non-empty",
                            r.id
                        )));
                    }
                    Some(CompiledAwsSigV4 {
                        access_key_ref: s.access_key_ref.trim().to_string(),
                        secret_key_ref: s.secret_key_ref.trim().to_string(),
                        region: s.region.trim().to_string(),
                        service: s.service.trim().to_string(),
                    })
                }
                None => None,
            };

            if let (Some(ref cred), Some(ref signing)) = (&credential, &request_signing) {
                if cred.header_name == signing.signature_header
                    || cred.header_name == signing.timestamp_header
                {
                    return Err(EdgeGateError::Config(format!(
                        "route '{}' request_signing header collides with credential header '{}'",
                        r.id, cred.header_name
                    )));
                }
            }

            if aws_sigv4.is_some() {
                if let Some(ref cred) = credential {
                    if cred.header_name == http::header::AUTHORIZATION {
                        return Err(EdgeGateError::Config(format!(
                            "route '{}' cannot combine aws_sigv4 with Authorization credential injection",
                            r.id
                        )));
                    }
                }
                if let Some(ref signing) = request_signing {
                    let sig_str = signing.signature_header.as_str().to_ascii_lowercase();
                    let ts_str = signing.timestamp_header.as_str().to_ascii_lowercase();
                    if sig_str == "authorization"
                        || sig_str == "x-amz-date"
                        || sig_str == "x-amz-content-sha256"
                        || ts_str == "authorization"
                        || ts_str == "x-amz-date"
                        || ts_str == "x-amz-content-sha256"
                    {
                        return Err(EdgeGateError::Config(format!(
                            "route '{}' request_signing collides with aws_sigv4 headers",
                            r.id
                        )));
                    }
                }
            }

            let cors = match r.cors {
                Some(ref c) => {
                    if c.allowed_origins.is_empty() {
                        return Err(EdgeGateError::Config(format!(
                            "route '{}' cors.allowed_origins cannot be empty or wildcard '*'",
                            r.id
                        )));
                    }
                    let mut allowed_origins = HashSet::with_capacity(c.allowed_origins.len());
                    for orig in &c.allowed_origins {
                        let trimmed = orig.trim();
                        if trimmed.is_empty() || trimmed == "*" {
                            return Err(EdgeGateError::Config(format!(
                                "route '{}' cors.allowed_origins cannot be empty or wildcard '*'",
                                r.id
                            )));
                        }
                        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
                            return Err(EdgeGateError::Config(format!(
                                "route '{}' cors origin '{orig}' must start with http:// or https://",
                                r.id
                            )));
                        }
                        let normalized = trimmed.trim_end_matches('/').to_ascii_lowercase();
                        allowed_origins.insert(normalized);
                    }

                    let mut validated_methods = Vec::with_capacity(c.allowed_methods.len());
                    for m in &c.allowed_methods {
                        let trimmed = m.trim();
                        if trimmed.is_empty() {
                            return Err(EdgeGateError::Config(format!(
                                "route '{}' cors.allowed_methods contains empty method",
                                r.id
                            )));
                        }
                        let method = Method::from_bytes(trimmed.as_bytes()).map_err(|e| {
                            EdgeGateError::Config(format!(
                                "route '{}' invalid cors method '{trimmed}': {e}",
                                r.id
                            ))
                        })?;
                        let upper = method.as_str().to_ascii_uppercase();
                        if !validated_methods.contains(&upper) {
                            validated_methods.push(upper);
                        }
                    }
                    if validated_methods.is_empty() {
                        return Err(EdgeGateError::Config(format!(
                            "route '{}' cors.allowed_methods cannot be empty",
                            r.id
                        )));
                    }
                    let allow_methods_str = validated_methods.join(", ");
                    let allow_methods_value =
                        HeaderValue::from_str(&allow_methods_str).map_err(|e| {
                            EdgeGateError::Config(format!(
                                "route '{}' invalid cors allow_methods HeaderValue: {e}",
                                r.id
                            ))
                        })?;

                    let mut validated_headers = Vec::with_capacity(c.allowed_headers.len());
                    for h in &c.allowed_headers {
                        let trimmed = h.trim();
                        if trimmed.is_empty() {
                            return Err(EdgeGateError::Config(format!(
                                "route '{}' cors.allowed_headers contains empty header",
                                r.id
                            )));
                        }
                        let hdr = HeaderName::from_bytes(trimmed.as_bytes()).map_err(|e| {
                            EdgeGateError::Config(format!(
                                "route '{}' invalid cors allowed_header '{trimmed}': {e}",
                                r.id
                            ))
                        })?;
                        let lower = hdr.as_str().to_ascii_lowercase();
                        if !validated_headers.contains(&lower) {
                            validated_headers.push(lower);
                        }
                    }
                    let allow_headers_str = validated_headers.join(", ");
                    let allow_headers_value =
                        HeaderValue::from_str(&allow_headers_str).map_err(|e| {
                            EdgeGateError::Config(format!(
                                "route '{}' invalid cors allow_headers HeaderValue: {e}",
                                r.id
                            ))
                        })?;

                    let mut validated_expose = Vec::with_capacity(c.expose_headers.len());
                    for h in &c.expose_headers {
                        let trimmed = h.trim();
                        if trimmed.is_empty() {
                            return Err(EdgeGateError::Config(format!(
                                "route '{}' cors.expose_headers contains empty header",
                                r.id
                            )));
                        }
                        let hdr = HeaderName::from_bytes(trimmed.as_bytes()).map_err(|e| {
                            EdgeGateError::Config(format!(
                                "route '{}' invalid cors expose_header '{trimmed}': {e}",
                                r.id
                            ))
                        })?;
                        let lower = hdr.as_str().to_ascii_lowercase();
                        if !validated_expose.contains(&lower) {
                            validated_expose.push(lower);
                        }
                    }
                    let expose_headers_value = if validated_expose.is_empty() {
                        None
                    } else {
                        let expose_str = validated_expose.join(", ");
                        let val = HeaderValue::from_str(&expose_str).map_err(|e| {
                            EdgeGateError::Config(format!(
                                "route '{}' invalid cors expose_headers HeaderValue: {e}",
                                r.id
                            ))
                        })?;
                        Some(val)
                    };

                    let max_age_value = HeaderValue::from_str(&c.max_age_secs.to_string())
                        .map_err(|e| {
                            EdgeGateError::Config(format!(
                                "route '{}' invalid cors max_age HeaderValue: {e}",
                                r.id
                            ))
                        })?;

                    Some(CompiledCorsConfig {
                        allowed_origins,
                        allow_methods_value,
                        allow_headers_value,
                        expose_headers_value,
                        max_age_value,
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
                response_timeout,
                max_response_body_bytes,
                strip_response_headers,
                inject_response_headers,
                credential,
                request_signing,
                aws_sigv4,
                cors,
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
            if pol.max_body_bytes == Some(0) {
                return Err(EdgeGateError::Config(format!(
                    "policy for route '{}' max_body_bytes must be > 0",
                    pol.route_id
                )));
            }
            let mut forbidden_query_params = Vec::with_capacity(pol.forbidden_query_params.len());
            for param in pol.forbidden_query_params {
                let lower_param = param.trim().to_ascii_lowercase();
                if lower_param.is_empty() {
                    return Err(EdgeGateError::Config(format!(
                        "policy for route '{}' has empty forbidden_query_params entry",
                        pol.route_id
                    )));
                }
                forbidden_query_params.push(lower_param);
            }
            let mut blocked_body_substrings = Vec::with_capacity(pol.blocked_body_substrings.len());
            for pat in pol.blocked_body_substrings {
                if pat.trim().is_empty() {
                    return Err(EdgeGateError::Config(format!(
                        "policy for route '{}' has empty blocked_body_substrings entry",
                        pol.route_id
                    )));
                }
                blocked_body_substrings.push(pat);
            }
            let allowed_jsonrpc_methods = match pol.allowed_jsonrpc_methods {
                Some(methods) => {
                    let mut list = Vec::with_capacity(methods.len());
                    for m in methods {
                        let trimmed = m.trim();
                        if trimmed.is_empty() {
                            return Err(EdgeGateError::Config(format!(
                                "policy for route '{}' has empty allowed_jsonrpc_methods entry",
                                pol.route_id
                            )));
                        }
                        list.push(trimmed.to_string());
                    }
                    Some(list)
                }
                None => None,
            };
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
                forbidden_query_params,
                blocked_body_substrings,
                allowed_jsonrpc_methods,
                max_body_bytes: pol.max_body_bytes,
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
            admin_token_digest,
            protect_observability: raw.server.protect_observability,
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

    let client_ca_pem = match (&cfg.client_ca_cert_pem, &cfg.client_ca_cert_path) {
        (Some(pem), None) => Some(pem.clone()),
        (None, Some(path)) => Some(std::fs::read_to_string(path).map_err(|e| {
            EdgeGateError::Config(format!(
                "failed to read server.tls.client_ca_cert_path '{}': {e}",
                path.display()
            ))
        })?),
        (Some(_), Some(_)) => {
            return Err(EdgeGateError::Config(
                "server.tls cannot set both client_ca_cert_pem and client_ca_cert_path".to_string(),
            ));
        }
        (None, None) => None,
    };

    let certs = parse_pem_certs(&cert_pem)
        .map_err(|msg| EdgeGateError::Config(format!("invalid server.tls certificate: {msg}")))?;
    let key = parse_pem_private_key(&key_pem)
        .map_err(|msg| EdgeGateError::Config(format!("invalid server.tls private key: {msg}")))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = RustlsServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| EdgeGateError::Config(format!("failed to configure TLS versions: {e}")))?;

    let mut tls_cfg = if let Some(ref ca_pem) = client_ca_pem {
        let ca_certs = parse_pem_certs(ca_pem).map_err(|msg| {
            EdgeGateError::Config(format!("invalid server.tls client CA certificate: {msg}"))
        })?;
        let mut client_roots = rustls::RootCertStore::empty();
        for ca_cert in ca_certs {
            client_roots.add(ca_cert).map_err(|e| {
                EdgeGateError::Config(format!("invalid server.tls client root CA: {e}"))
            })?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            Arc::clone(&provider),
        )
        .build()
        .map_err(|e| {
            EdgeGateError::Config(format!("invalid server.tls client CA verifier: {e}"))
        })?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| EdgeGateError::Config(format!("invalid server.tls cert/key pair: {e}")))?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| EdgeGateError::Config(format!("invalid server.tls cert/key pair: {e}")))?
    };

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

/// Pure, safe RFC 2104 HMAC-SHA256 implementation producing raw 32 bytes (`INV-25`).
pub fn hmac_sha256_bytes(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        k_pad[..32].copy_from_slice(&digest);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    let mut k_ipad = [0u8; 64];
    let mut k_opad = [0u8; 64];
    for i in 0..64 {
        k_ipad[i] = k_pad[i] ^ 0x36;
        k_opad[i] = k_pad[i] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(k_ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(k_opad);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_hash);
    out
}

/// Pure, safe RFC 2104 HMAC-SHA256 implementation producing a lowercase hex digest (`INV-23`).
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    hex::encode(hmac_sha256_bytes(key, message))
}

/// Pure, safe conversion from UNIX epoch seconds to ISO 8601 AWS timestamps `(amz_date, date_stamp)` (`INV-25`).
/// Uses Howard Hinnant's civil-from-days algorithm using pure safe integer math.
pub fn format_amz_timestamps(epoch_secs: u64) -> (String, String) {
    let secs_of_day = (epoch_secs % 86400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let z = (epoch_secs / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };

    let date_stamp = format!("{y:04}{m:02}{d:02}");
    let amz_date = format!("{date_stamp}T{hour:02}{minute:02}{second:02}Z");
    (amz_date, date_stamp)
}

fn percent_decode_raw(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            let d1 = match h1 {
                b'0'..=b'9' => Some(h1 - b'0'),
                b'a'..=b'f' => Some(h1 - b'a' + 10),
                b'A'..=b'F' => Some(h1 - b'A' + 10),
                _ => None,
            };
            let d2 = match h2 {
                b'0'..=b'9' => Some(h2 - b'0'),
                b'a'..=b'f' => Some(h2 - b'a' + 10),
                b'A'..=b'F' => Some(h2 - b'A' + 10),
                _ => None,
            };
            if let (Some(d1), Some(d2)) = (d1, d2) {
                out.push((d1 << 4) | d2);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Pure-Rust AWS URI encoding according to SigV4 specifications (`RFC 3986`).
pub fn aws_uri_encode(input: &str, encode_slash: bool) -> String {
    let raw = percent_decode_raw(input);
    let mut out = String::with_capacity(raw.len());
    for b in raw {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b'/' if !encode_slash => {
                out.push('/');
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{:02X}", b);
            }
        }
    }
    out
}

/// Pure-Rust AWS Signature Version 4 calculation (`AWS4-HMAC-SHA256`, `INV-25`).
#[allow(clippy::too_many_arguments)]
pub fn compute_aws_sigv4_headers(
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query: Option<&str>,
    host: &str,
    payload: &[u8],
    amz_date: &str,
    date_stamp: &str,
) -> AwsSigV4Headers {
    let content_sha256 = hex::encode(sha256_digest(payload));
    let uri = if canonical_uri.is_empty() {
        "/".to_string()
    } else {
        aws_uri_encode(canonical_uri, false)
    };

    let sorted_query = match canonical_query {
        Some(q) if !q.is_empty() => {
            let mut pairs: Vec<(String, String)> = q
                .split('&')
                .filter(|s| !s.is_empty())
                .map(|pair| {
                    let (raw_k, raw_v) = if let Some((k, v)) = pair.split_once('=') {
                        (k, v)
                    } else {
                        (pair, "")
                    };
                    (aws_uri_encode(raw_k, true), aws_uri_encode(raw_v, true))
                })
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            pairs
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&")
        }
        _ => String::new(),
    };

    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host.trim(),
        content_sha256,
        amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        uri,
        sorted_query,
        canonical_headers,
        signed_headers,
        content_sha256
    );
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(sha256_digest(canonical_request.as_bytes()))
    );

    let k_date = hmac_sha256_bytes(
        format!("AWS4{secret_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256_bytes(&k_date, region.as_bytes());
    let k_service = hmac_sha256_bytes(&k_region, service.as_bytes());
    let k_signing = hmac_sha256_bytes(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256_bytes(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    AwsSigV4Headers {
        authorization,
        amz_date: amz_date.to_string(),
        content_sha256,
    }
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

    #[test]
    fn rfc4231_test_case_2_hmac_sha256() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(hmac_sha256_hex(key, data), expected);
    }

    #[test]
    fn test_format_amz_timestamps_epoch_zero() {
        let (amz_date, date_stamp) = format_amz_timestamps(0);
        assert_eq!(amz_date, "19700101T000000Z");
        assert_eq!(date_stamp, "19700101");
    }

    #[test]
    fn test_format_amz_timestamps_future_epoch() {
        let (amz_date, date_stamp) = format_amz_timestamps(1755216000);
        assert_eq!(amz_date, "20250815T000000Z");
        assert_eq!(date_stamp, "20250815");
    }

    #[test]
    fn test_compute_aws_sigv4_headers_deterministic() {
        let h1 = compute_aws_sigv4_headers(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
            "GET",
            "/test.txt",
            Some("b=2&a=1"),
            "examplebucket.s3.amazonaws.com",
            b"test payload",
            "20130524T000000Z",
            "20130524",
        );
        let h2 = compute_aws_sigv4_headers(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
            "GET",
            "/test.txt",
            Some("b=2&a=1"),
            "examplebucket.s3.amazonaws.com",
            b"test payload",
            "20130524T000000Z",
            "20130524",
        );
        assert_eq!(h1, h2);
        assert_eq!(h1.amz_date, "20130524T000000Z");
        assert!(h1.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"
        ));
        assert!(h1
            .authorization
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn test_aws_sigv4_canonical_query_encodes_reserved_chars() {
        let raw_query = "prefix=report:2026&b=1";
        let pre_encoded_query = "b=1&prefix=report%3A2026";

        let h1 = compute_aws_sigv4_headers(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
            "GET",
            "/test.txt",
            Some(raw_query),
            "examplebucket.s3.amazonaws.com",
            b"test payload",
            "20130524T000000Z",
            "20130524",
        );

        let h2 = compute_aws_sigv4_headers(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
            "GET",
            "/test.txt",
            Some(pre_encoded_query),
            "examplebucket.s3.amazonaws.com",
            b"test payload",
            "20130524T000000Z",
            "20130524",
        );

        assert_eq!(h1, h2);
        assert_eq!(aws_uri_encode("report:2026", true), "report%3A2026");
    }

    #[test]
    fn test_header_collision_credential_vs_request_signing() {
        let toml = VALID_TOML.to_string()
            + r#"
[routes.request_signing]
credential_ref = "github_pat"
signature_header = "Authorization"
timestamp_header = "X-Timestamp"
"#;
        let err = CompiledConfig::from_toml_str(&toml).unwrap_err();
        assert!(err.to_string().contains("collides with credential header"));
    }

    #[test]
    fn test_header_collision_aws_sigv4_vs_authorization_credential() {
        let toml = VALID_TOML.to_string()
            + r#"
[routes.aws_sigv4]
access_key_ref = "ak"
secret_key_ref = "sk"
region = "us-east-1"
service = "s3"
"#;
        let err = CompiledConfig::from_toml_str(&toml).unwrap_err();
        assert!(err
            .to_string()
            .contains("cannot combine aws_sigv4 with Authorization credential injection"));
    }

    #[test]
    fn test_header_collision_aws_sigv4_vs_request_signing_forbidden_header() {
        let base = VALID_TOML.replace(
            "[routes.credential]\ncredential_ref = \"github_pat\"\nheader_name = \"Authorization\"\nvalue_prefix = \"Bearer \"",
            "[routes.aws_sigv4]\naccess_key_ref = \"ak\"\nsecret_key_ref = \"sk\"\nregion = \"us-east-1\"\nservice = \"s3\"\n[routes.request_signing]\ncredential_ref = \"github_pat\"\nsignature_header = \"x-amz-date\"\ntimestamp_header = \"X-Custom-Time\"",
        );
        let err = CompiledConfig::from_toml_str(&base).unwrap_err();
        assert!(err.to_string().contains("collides with aws_sigv4 headers"));
    }

    #[test]
    fn test_protect_observability_requires_admin_token() {
        let toml = VALID_TOML.replace(
            "[server]\nlisten_addr = \"127.0.0.1:8080\"",
            "[server]\nlisten_addr = \"127.0.0.1:8080\"\nprotect_observability = true",
        );
        let err = CompiledConfig::from_toml_str(&toml).unwrap_err();
        assert!(err.to_string().contains("server.protect_observability = true requires server.admin_token or server.admin_token_sha256"));

        let toml_with_admin = toml.replace(
            "protect_observability = true",
            "protect_observability = true\nadmin_token = \"super_secret_admin_token\"",
        );
        assert!(CompiledConfig::from_toml_str(&toml_with_admin).is_ok());
    }

    #[test]
    fn test_cors_config_compilation_success() {
        let toml = VALID_TOML.to_string()
            + r#"
[routes.cors]
allowed_origins = ["https://app.example.com", "http://localhost:3000/"]
expose_headers = ["x-custom-response", "x-request-id"]
max_age_secs = 3600
"#;
        let compiled = CompiledConfig::from_toml_str(&toml).unwrap();
        let route = &compiled.routes[0];
        let cors = route.cors.as_ref().unwrap();
        assert!(cors.allowed_origins.contains("https://app.example.com"));
        assert!(cors.allowed_origins.contains("http://localhost:3000"));
        assert_eq!(
            cors.allow_methods_value.to_str().unwrap(),
            "GET, POST, OPTIONS"
        );
        assert_eq!(
            cors.allow_headers_value.to_str().unwrap(),
            "content-type, x-edgegate-token, traceparent, tracestate"
        );
        assert_eq!(
            cors.expose_headers_value
                .as_ref()
                .unwrap()
                .to_str()
                .unwrap(),
            "x-custom-response, x-request-id"
        );
        assert_eq!(cors.max_age_value.to_str().unwrap(), "3600");
    }

    #[test]
    fn test_cors_config_wildcard_origin_rejected() {
        let toml = VALID_TOML.to_string()
            + r#"
[routes.cors]
allowed_origins = ["*"]
"#;
        let err = CompiledConfig::from_toml_str(&toml).unwrap_err();
        assert!(err.to_string().contains("cannot be empty or wildcard '*'"));
    }

    #[test]
    fn test_cors_config_empty_origins_rejected() {
        let toml = VALID_TOML.to_string()
            + r#"
[routes.cors]
allowed_origins = []
"#;
        let err = CompiledConfig::from_toml_str(&toml).unwrap_err();
        assert!(err.to_string().contains("cannot be empty or wildcard '*'"));
    }

    #[test]
    fn test_cors_config_invalid_scheme_rejected() {
        let toml = VALID_TOML.to_string()
            + r#"
[routes.cors]
allowed_origins = ["ftp://bad.example.com"]
"#;
        let err = CompiledConfig::from_toml_str(&toml).unwrap_err();
        assert!(err
            .to_string()
            .contains("must start with http:// or https://"));
    }
}
