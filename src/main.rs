use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use edgegate::config::CompiledConfig;
use edgegate::proxy::{EdgeGateProxy, ADMIN_TOKEN_HEADER};
use edgegate::telemetry::init_json_logging;
use http::header::HOST;
use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1 as client_http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{error, info};

#[derive(Debug, Parser)]
#[command(
    name = "edgegate",
    version,
    about = "High-performance programmable L7 reverse proxy and load balancer for zero-secret execution"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the EdgeGate L7 reverse proxy server.
    Start {
        #[arg(short, long, default_value = "edgegate.toml")]
        config: PathBuf,
        /// Optional file-watch interval (ms) for automatic zero-downtime config hot reload.
        #[arg(long)]
        watch_interval_ms: Option<u64>,
    },
    /// Validate an EdgeGate TOML configuration file and exit.
    Validate {
        #[arg(short, long, default_value = "edgegate.toml")]
        config: PathBuf,
    },
    /// Fetch live JSON metrics (`/_edgegate/metrics`) from a running EdgeGate instance.
    Status {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        url: String,
        /// Optional custom CA certificate PEM file for HTTPS verification.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Optional client certificate PEM file for outbound mTLS client authentication.
        #[arg(long)]
        client_cert: Option<PathBuf>,
        /// Optional client private key PEM file for outbound mTLS client authentication.
        #[arg(long)]
        client_key: Option<PathBuf>,
    },
    /// Fetch live flight-recorder replay records (`/_edgegate/replay`) from a running EdgeGate instance.
    Replay {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        url: String,
        /// Optional custom CA certificate PEM file for HTTPS verification.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Optional client certificate PEM file for outbound mTLS client authentication.
        #[arg(long)]
        client_cert: Option<PathBuf>,
        /// Optional client private key PEM file for outbound mTLS client authentication.
        #[arg(long)]
        client_key: Option<PathBuf>,
    },
    /// Fetch and verify the cryptographic SHA-256 hash-chained audit ledger (`/_edgegate/admin/audit`).
    Audit {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        url: String,
        /// Admin control-plane token (falls back to EDGEGATE_ADMIN_TOKEN environment variable).
        #[arg(long)]
        admin_token: Option<String>,
        /// Optional custom CA certificate PEM file for HTTPS verification.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Optional client certificate PEM file for outbound mTLS client authentication.
        #[arg(long)]
        client_cert: Option<PathBuf>,
        /// Optional client private key PEM file for outbound mTLS client authentication.
        #[arg(long)]
        client_key: Option<PathBuf>,
        /// Allow sending admin token over cleartext HTTP to non-loopback hosts.
        #[arg(long)]
        allow_insecure_http: bool,
    },
}

async fn fetch_endpoint(
    base_url: &str,
    endpoint_path: &str,
    ca_cert: Option<&Path>,
    client_cert: Option<&Path>,
    client_key: Option<&Path>,
) -> Result<String, String> {
    fetch_endpoint_with_header(
        base_url,
        endpoint_path,
        None,
        ca_cert,
        client_cert,
        client_key,
    )
    .await
}

async fn fetch_endpoint_with_header(
    base_url: &str,
    endpoint_path: &str,
    extra_header: Option<(&str, &str)>,
    ca_cert: Option<&Path>,
    client_cert: Option<&Path>,
    client_key: Option<&Path>,
) -> Result<String, String> {
    let trimmed = base_url.trim_end_matches('/');
    let full_url = format!("{trimmed}{endpoint_path}");
    let uri: Uri = full_url
        .parse()
        .map_err(|e| format!("invalid URL '{full_url}': {e}"))?;

    let scheme = uri.scheme_str().unwrap_or("http");
    if ca_cert.is_some() && scheme != "https" {
        return Err("--ca-cert requires an https:// URL".to_string());
    }
    if client_cert.is_some() != client_key.is_some() {
        return Err("both --client-cert and --client-key must be provided together".to_string());
    }
    if client_cert.is_some() && scheme != "https" {
        return Err("--client-cert/--client-key requires an https:// URL".to_string());
    }
    let is_https = match scheme {
        "http" => false,
        "https" => true,
        other => {
            return Err(format!(
                "unsupported URL scheme '{other}' (expected http or https)"
            ))
        }
    };

    let host = uri
        .host()
        .ok_or_else(|| format!("missing host in URL '{full_url}'"))?;
    let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });
    let authority = format!("{host}:{port}");
    let path_and_query = uri.path_and_query().map_or(endpoint_path, |pq| pq.as_str());

    let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&authority))
        .await
        .map_err(|_| format!("connection timeout connecting to '{authority}'"))?
        .map_err(|e| format!("failed to connect to '{authority}': {e}"))?;

    let mut sender = if is_https {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca_path) = ca_cert {
            let pem_data = std::fs::read_to_string(ca_path)
                .map_err(|e| format!("failed to read ca_cert '{}': {e}", ca_path.display()))?;
            let mut reader = std::io::Cursor::new(pem_data.as_bytes());
            for cert_res in rustls_pemfile::certs(&mut reader) {
                let cert = cert_res.map_err(|e| format!("invalid CA cert PEM: {e}"))?;
                root_store
                    .add(cert)
                    .map_err(|e| format!("failed to add CA cert: {e}"))?;
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS version error: {e}"))?
            .with_root_certificates(root_store);
        let client_config = if let (Some(cert_path), Some(key_path)) = (client_cert, client_key) {
            let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| {
                format!("failed to read client_cert '{}': {e}", cert_path.display())
            })?;
            let mut cert_reader = std::io::Cursor::new(cert_pem.as_bytes());
            let mut certs = Vec::new();
            for cert_res in rustls_pemfile::certs(&mut cert_reader) {
                let cert = cert_res.map_err(|e| format!("invalid client cert PEM: {e}"))?;
                certs.push(cert);
            }
            if certs.is_empty() {
                return Err(format!(
                    "no certificates found in '{}'",
                    cert_path.display()
                ));
            }

            let key_pem = std::fs::read_to_string(key_path)
                .map_err(|e| format!("failed to read client_key '{}': {e}", key_path.display()))?;
            let mut key_reader = std::io::Cursor::new(key_pem.as_bytes());
            let key = rustls_pemfile::private_key(&mut key_reader)
                .map_err(|e| format!("failed to parse client private key: {e}"))?
                .ok_or_else(|| format!("no private key found in '{}'", key_path.display()))?;

            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("invalid client auth cert/key configuration: {e}"))?
        } else {
            builder.with_no_client_auth()
        };
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| format!("invalid TLS server name '{host}': {e}"))?;
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("TLS handshake failed with '{authority}': {e}"))?;
        let io = TokioIo::new(tls_stream);
        let (s, conn) = client_http1::handshake(io)
            .await
            .map_err(|e| format!("HTTPS HTTP/1.1 handshake failed with '{authority}': {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        s
    } else {
        let io = TokioIo::new(stream);
        let (s, conn) = client_http1::handshake(io)
            .await
            .map_err(|e| format!("HTTP/1.1 handshake failed with '{authority}': {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        s
    };

    let mut builder = Request::builder()
        .method("GET")
        .uri(path_and_query)
        .header(HOST, &authority);
    if let Some((hdr_name, hdr_val)) = extra_header {
        builder = builder.header(hdr_name, hdr_val);
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .map_err(|e| format!("failed to build request: {e}"))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("failed to read response body: {e}"))?
        .to_bytes();
    let body = String::from_utf8_lossy(&body_bytes).to_string();
    if !status.is_success() {
        return Err(format!("HTTP {}: {}", status.as_u16(), body));
    }
    Ok(body)
}

#[tokio::main]
async fn main() -> ExitCode {
    init_json_logging();
    let cli = Cli::parse();

    match cli.command {
        Command::Validate { config } => match CompiledConfig::from_file(&config) {
            Ok(compiled) => {
                info!(
                    listen_addr = %compiled.listen_addr,
                    unix_listeners = compiled.unix_listeners.len(),
                    workloads = compiled.workloads.len(),
                    pools = compiled.pools.len(),
                    routes = compiled.routes.len(),
                    policies = compiled.policies.len(),
                    "edgegate_config_valid"
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                error!(error = %err, "edgegate_config_invalid");
                ExitCode::FAILURE
            }
        },
        Command::Status {
            url,
            ca_cert,
            client_cert,
            client_key,
        } => {
            match fetch_endpoint(
                &url,
                "/_edgegate/metrics",
                ca_cert.as_deref(),
                client_cert.as_deref(),
                client_key.as_deref(),
            )
            .await
            {
                Ok(body) => {
                    println!("{body}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    error!(error = %err, "edgegate_status_error");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Replay {
            url,
            ca_cert,
            client_cert,
            client_key,
        } => {
            match fetch_endpoint(
                &url,
                "/_edgegate/replay",
                ca_cert.as_deref(),
                client_cert.as_deref(),
                client_key.as_deref(),
            )
            .await
            {
                Ok(body) => {
                    println!("{body}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    error!(error = %err, "edgegate_replay_error");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Audit {
            url,
            admin_token,
            ca_cert,
            client_cert,
            client_key,
            allow_insecure_http,
        } => {
            let uri: Uri = match url.parse() {
                Ok(u) => u,
                Err(e) => {
                    error!(error = %e, "invalid audit URL");
                    return ExitCode::FAILURE;
                }
            };
            let scheme = uri.scheme_str().unwrap_or("http");
            let host = uri.host().unwrap_or_default();
            let is_loopback = is_loopback_host(host);
            if (scheme == "http" || uri.scheme().is_none()) && !allow_insecure_http && !is_loopback
            {
                error!(
                    "refusing to send admin token over cleartext http:// to non-loopback host (use https:// or pass --allow-insecure-http)"
                );
                return ExitCode::FAILURE;
            }
            let resolved_token = admin_token.or_else(|| std::env::var("EDGEGATE_ADMIN_TOKEN").ok());
            let token = match resolved_token {
                Some(t) if !t.trim().is_empty() => t,
                _ => {
                    error!(
                        "missing admin token: specify --admin-token or set EDGEGATE_ADMIN_TOKEN"
                    );
                    return ExitCode::FAILURE;
                }
            };
            match fetch_endpoint_with_header(
                &url,
                "/_edgegate/admin/audit",
                Some((ADMIN_TOKEN_HEADER, token.as_str())),
                ca_cert.as_deref(),
                client_cert.as_deref(),
                client_key.as_deref(),
            )
            .await
            {
                Ok(body) => {
                    println!("{body}");
                    if let Err(reason) = edgegate::telemetry::verify_audit_json(&body) {
                        error!(error = %reason, "edgegate_audit_chain_invalid");
                        return ExitCode::FAILURE;
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    error!(error = %err, "edgegate_audit_error");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Start {
            config,
            watch_interval_ms,
        } => {
            let compiled = match CompiledConfig::from_file(&config) {
                Ok(c) => c,
                Err(err) => {
                    error!(error = %err, "edgegate_startup_config_error");
                    return ExitCode::FAILURE;
                }
            };
            let listen_addr = compiled.listen_addr;
            let proxy = Arc::new(EdgeGateProxy::new(compiled));

            if let Err(err) = proxy.spawn_unix_listeners() {
                error!(error = %err, "edgegate_unix_listener_error");
                return ExitCode::FAILURE;
            }
            let _probe_handle = proxy.spawn_active_health_probes();

            if let Some(poll_ms) = watch_interval_ms {
                let watch_proxy = Arc::clone(&proxy);
                let watch_path = config.clone();
                tokio::spawn(async move {
                    let mut last_mtime = std::fs::metadata(&watch_path)
                        .and_then(|m| m.modified())
                        .ok();
                    let mut ticker = tokio::time::interval(Duration::from_millis(poll_ms.max(100)));
                    loop {
                        ticker.tick().await;
                        let current_mtime = std::fs::metadata(&watch_path)
                            .and_then(|m| m.modified())
                            .ok();
                        if current_mtime.is_some() && current_mtime != last_mtime {
                            last_mtime = current_mtime;
                            let _ = watch_proxy.reload_from_file(&watch_path);
                        }
                    }
                });
            }

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(err) = proxy.bind_and_serve(listen_addr, shutdown_rx).await {
                error!(error = %err, "edgegate_server_error");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    let clean = host.trim_matches(['[', ']']);
    clean.eq_ignore_ascii_case("localhost")
        || clean
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_full_ipv4_and_ipv6_loopback_ranges() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("127.255.255.254"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("example.com"));
    }
}
