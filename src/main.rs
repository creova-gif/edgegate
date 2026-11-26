use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use edgegate::telemetry::init_json_logging;
use http::header::HOST;
use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1 as client_http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
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
    },
    /// Fetch live flight-recorder replay records (`/_edgegate/replay`) from a running EdgeGate instance.
    Replay {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        url: String,
    },
}

async fn fetch_endpoint(base_url: &str, endpoint_path: &str) -> Result<String, String> {
    let trimmed = base_url.trim_end_matches('/');
    let full_url = format!("{trimmed}{endpoint_path}");
    let uri: Uri = full_url
        .parse()
        .map_err(|e| format!("invalid URL '{full_url}': {e}"))?;
    let host = uri
        .host()
        .ok_or_else(|| format!("missing host in URL '{full_url}'"))?;
    let port = uri.port_u16().unwrap_or(80);
    let authority = format!("{host}:{port}");
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(endpoint_path);

    let stream = TcpStream::connect(&authority)
        .await
        .map_err(|e| format!("failed to connect to '{authority}': {e}"))?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = client_http1::handshake(io)
        .await
        .map_err(|e| format!("HTTP/1.1 handshake failed with '{authority}': {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri(path_and_query)
        .header(HOST, &authority)
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
        Command::Status { url } => match fetch_endpoint(&url, "/_edgegate/metrics").await {
            Ok(body) => {
                println!("{body}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                error!(error = %err, "edgegate_status_error");
                ExitCode::FAILURE
            }
        },
        Command::Replay { url } => match fetch_endpoint(&url, "/_edgegate/replay").await {
            Ok(body) => {
                println!("{body}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                error!(error = %err, "edgegate_replay_error");
                ExitCode::FAILURE
            }
        },
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
