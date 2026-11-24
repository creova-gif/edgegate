use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderName, Method};
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkloadConfig {
    pub workload_id: String,
    pub org_id: String,
    /// Either plaintext `token` (hashed at startup for local dev/demo) or pre-hashed `token_sha256` (64 hex chars).
    pub token: Option<String>,
    pub token_sha256: Option<String>,
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbStrategyConfig {
    #[default]
    RoundRobin,
    LeastConnections,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub id: String,
    /// Authority in `host:port` format (plaintext HTTP/1.1 in Milestone 1).
    pub address: String,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRuleConfig {
    pub org_id: String,
    /// Optional workload_id restriction; if omitted, applies to all workloads in `org_id`.
    #[serde(default)]
    pub workload_id: Option<String>,
    pub route_id: String,
    pub methods: Vec<String>,
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecretEntryConfig {
    pub org_id: String,
    pub credential_ref: String,
    pub value: String,
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

fn default_path_prefix() -> String {
    "/".to_string()
}

/// Immutable, validated runtime snapshot stored in `ArcSwap<CompiledConfig>`.
#[derive(Debug, Clone)]
pub struct CompiledConfig {
    pub listen_addr: SocketAddr,
    pub max_request_body_bytes: usize,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    pub workloads: HashMap<[u8; 32], CompiledWorkload>,
    pub pools: HashMap<String, CompiledPool>,
    pub routes: Vec<CompiledRoute>,
    pub policies: Vec<CompiledPolicyRule>,
    pub secrets: HashMap<(String, String), String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledWorkload {
    pub workload_id: String,
    pub org_id: String,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledBackend {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub authority: String,
}

#[derive(Debug, Clone)]
pub struct CompiledRoute {
    pub id: String,
    pub path_prefix: String,
    pub host: Option<String>,
    pub strip_prefix: bool,
    pub pool: String,
    pub credential: Option<CompiledCredentialBinding>,
}

#[derive(Debug, Clone)]
pub struct CompiledCredentialBinding {
    pub credential_ref: String,
    pub header_name: HeaderName,
    pub value_prefix: String,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicyRule {
    pub org_id: String,
    pub workload_id: Option<String>,
    pub route_id: String,
    pub methods: HashSet<Method>,
    pub path_prefix: String,
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
        if raw.server.connect_timeout_ms == 0 || raw.server.response_timeout_ms == 0 {
            return Err(EdgeGateError::Config(
                "server timeouts must be > 0".to_string(),
            ));
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
            if workloads
                .insert(
                    digest,
                    CompiledWorkload {
                        workload_id: w.workload_id.clone(),
                        org_id: w.org_id,
                    },
                )
                .is_some()
            {
                return Err(EdgeGateError::Config(format!(
                    "duplicate workload token detected for '{}'",
                    w.workload_id
                )));
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
                compiled_backends.push(CompiledBackend {
                    id: b.id,
                    host,
                    port,
                    authority: b.address,
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
                credential,
            });
        }
        // Sort longest path_prefix first for deterministic matching.
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
            let mut methods = HashSet::with_capacity(pol.methods.len());
            for m in pol.methods {
                let parsed =
                    Method::from_bytes(m.to_ascii_uppercase().as_bytes()).map_err(|e| {
                        EdgeGateError::Config(format!("invalid HTTP method '{m}': {e}"))
                    })?;
                methods.insert(parsed);
            }
            policies.push(CompiledPolicyRule {
                org_id: pol.org_id,
                workload_id: pol.workload_id,
                route_id: pol.route_id,
                methods,
                path_prefix: pol.path_prefix,
            });
        }

        let mut secrets = HashMap::with_capacity(raw.secrets.len());
        for s in raw.secrets {
            if s.org_id.trim().is_empty() || s.credential_ref.trim().is_empty() {
                return Err(EdgeGateError::Config(
                    "secret org_id and credential_ref must be non-empty".to_string(),
                ));
            }
            secrets.insert((s.org_id, s.credential_ref), s.value);
        }

        Ok(Self {
            listen_addr,
            max_request_body_bytes: raw.server.max_request_body_bytes,
            connect_timeout: Duration::from_millis(raw.server.connect_timeout_ms),
            response_timeout: Duration::from_millis(raw.server.response_timeout_ms),
            workloads,
            pools,
            routes,
            policies,
            secrets,
        })
    }
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

[[pools]]
name = "mock-api"
strategy = "round_robin"
allow_private_ip = true
backends = [
  { id = "a", address = "127.0.0.1:9001" },
  { id = "b", address = "127.0.0.1:9002" },
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
