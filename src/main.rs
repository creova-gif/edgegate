use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use edgegate::telemetry::init_json_logging;
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
    },
    /// Validate an EdgeGate TOML configuration file and exit.
    Validate {
        #[arg(short, long, default_value = "edgegate.toml")]
        config: PathBuf,
    },
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
        Command::Start { config } => {
            let compiled = match CompiledConfig::from_file(&config) {
                Ok(c) => c,
                Err(err) => {
                    error!(error = %err, "edgegate_startup_config_error");
                    return ExitCode::FAILURE;
                }
            };
            let listen_addr = compiled.listen_addr;
            let proxy = Arc::new(EdgeGateProxy::new(compiled));
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
