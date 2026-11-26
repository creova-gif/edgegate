use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

type DemoBody = Full<Bytes>;

async fn spawn_mock_github_upstream() -> Result<(SocketAddr, oneshot::Sender<()>), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("failed to bind mock github upstream: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("failed to read mock github local_addr: {e}"))?;
    let (tx, mut rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accept_res = listener.accept() => {
                    let Ok((stream, _)) = accept_res else { break };
                    tokio::spawn(async move {
                        let service = service_fn(|req: Request<Incoming>| async move {
                            let path = req.uri().path().to_string();
                            let auth = req
                                .headers()
                                .get(AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();

                            // Scenario 5: Compromised or misconfigured endpoint echoing back the injected secret
                            if path == "/repos/reflect-secret" {
                                let payload = format!(
                                    "{{\"leak\":\"reflected_header\",\"authorization\":\"{auth}\"}}"
                                );
                                let mut resp = Response::new(Full::new(Bytes::from(payload)));
                                *resp.status_mut() = StatusCode::OK;
                                resp.headers_mut().insert(
                                    CONTENT_TYPE,
                                    http::HeaderValue::from_static("application/json"),
                                );
                                return Ok::<_, Infallible>(resp);
                            }

                            // Scenario 1: Normal GitHub repository read verifying scoped credential injection
                            let has_expected_secret =
                                auth == "Bearer ghp_live_alpha_scoped_secret_99";
                            let body = format!(
                                "{{\"repo\":\"edgegate\",\"org\":\"org-alpha\",\"credential_injected\":{has_expected_secret}}}"
                            );
                            let mut resp = Response::new(Full::new(Bytes::from(body)));
                            *resp.status_mut() = if has_expected_secret {
                                StatusCode::OK
                            } else {
                                StatusCode::UNAUTHORIZED
                            };
                            resp.headers_mut().insert(
                                CONTENT_TYPE,
                                http::HeaderValue::from_static("application/json"),
                            );
                            Ok::<_, Infallible>(resp)
                        });
                        let _ = AutoConnBuilder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
    });

    Ok((addr, tx))
}

async fn spawn_mock_openai_upstream() -> Result<(SocketAddr, oneshot::Sender<()>), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("failed to bind mock openai upstream: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("failed to read mock openai local_addr: {e}"))?;
    let (tx, mut rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accept_res = listener.accept() => {
                    let Ok((stream, _)) = accept_res else { break };
                    tokio::spawn(async move {
                        let service = service_fn(|req: Request<Incoming>| async move {
                            let auth = req
                                .headers()
                                .get(AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let has_expected_secret =
                                auth == "Bearer sk-live-alpha-openai-secret-42";
                            let body = format!(
                                "{{\"id\":\"chatcmpl-edgegate\",\"object\":\"chat.completion\",\"credential_injected\":{has_expected_secret}}}"
                            );
                            let mut resp = Response::new(Full::new(Bytes::from(body)));
                            *resp.status_mut() = if has_expected_secret {
                                StatusCode::OK
                            } else {
                                StatusCode::UNAUTHORIZED
                            };
                            resp.headers_mut().insert(
                                CONTENT_TYPE,
                                http::HeaderValue::from_static("application/json"),
                            );
                            Ok::<_, Infallible>(resp)
                        });
                        let _ = AutoConnBuilder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
    });

    Ok((addr, tx))
}

async fn send_proxy_request(
    proxy_addr: SocketAddr,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: &'static str,
) -> Result<(StatusCode, String), String> {
    let stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| format!("connect error: {e}"))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("handshake error: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "edgegate.local");
    if let Some(t) = token {
        builder = builder.header("X-EdgeGate-Token", t);
    }

    let req: Request<DemoBody> = builder
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .map_err(|e| format!("request build error: {e}"))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("send_request error: {e}"))?;
    let status = resp.status();
    let collected = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("body collect error: {e}"))?
        .to_bytes();
    let text = String::from_utf8_lossy(&collected).to_string();
    Ok((status, text))
}

struct ConsoleRow {
    scenario: &'static str,
    security_control: &'static str,
    decision_label: String,
    passed: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (github_addr, _github_shutdown) = spawn_mock_github_upstream().await?;
    let (openai_addr, _openai_shutdown) = spawn_mock_openai_upstream().await?;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
max_request_body_bytes = 65536
connect_timeout_ms = 1000
response_timeout_ms = 2000
replay_buffer_size = 32

[[workloads]]
workload_id = "boxlet-agent-alpha"
org_id = "org-alpha"
token = "tok_alpha_sandbox_01"
roles = ["repo-reader", "ai-caller"]

[[workloads]]
workload_id = "boxlet-agent-beta"
org_id = "org-beta"
token = "tok_beta_sandbox_02"
roles = ["viewer"]

[[pools]]
name = "github-upstream"
strategy = "round_robin"
allow_private_ip = true

[[pools.backends]]
id = "github-1"
address = "{github_addr}"

[[pools]]
name = "openai-upstream"
strategy = "round_robin"
allow_private_ip = true

[[pools.backends]]
id = "openai-1"
address = "{openai_addr}"

[[routes]]
id = "github-repos"
path_prefix = "/v1/github"
strip_prefix = true
pool = "github-upstream"

[routes.credential]
credential_ref = "github-pat"
header_name = "Authorization"
value_prefix = "Bearer "
block_secret_reflection = true

[[routes]]
id = "openai-inference"
path_prefix = "/v1/openai"
strip_prefix = true
pool = "openai-upstream"

[routes.credential]
credential_ref = "openai-key"
header_name = "Authorization"
value_prefix = "Bearer "
block_secret_reflection = true

[[policies]]
org_id = "org-alpha"
workload_id = "boxlet-agent-alpha"
required_roles = ["repo-reader"]
route_id = "github-repos"
methods = ["GET"]
path_prefix = "/v1/github/repos"

[[policies]]
org_id = "org-alpha"
workload_id = "boxlet-agent-alpha"
required_roles = ["ai-caller"]
route_id = "openai-inference"
methods = ["POST"]
path_prefix = "/v1/openai/chat/completions"

[[secrets]]
org_id = "org-alpha"
credential_ref = "github-pat"
value = "ghp_live_alpha_scoped_secret_99"

[[secrets]]
org_id = "org-alpha"
credential_ref = "openai-key"
value = "sk-live-alpha-openai-secret-42"
"#
    );

    let compiled = CompiledConfig::from_toml_str(&toml_cfg)?;
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;
    let (proxy_shutdown_tx, proxy_shutdown_rx) = oneshot::channel::<()>();

    let proxy_runner = Arc::clone(&proxy);
    let proxy_task = tokio::spawn(async move {
        let _ = proxy_runner.serve(proxy_listener, proxy_shutdown_rx).await;
    });

    let mut rows = Vec::with_capacity(5);

    // 1. GitHub repository read (org-alpha authorized GET /v1/github/repos/edgegate)
    let (st1, body1) = send_proxy_request(
        proxy_addr,
        Method::GET,
        "/v1/github/repos/edgegate",
        Some("tok_alpha_sandbox_01"),
        "",
    )
    .await?;
    rows.push(ConsoleRow {
        scenario: "GitHub repository read",
        security_control: "Scoped credential injected",
        decision_label: format!("ALLOWED ({})", st1),
        passed: st1 == StatusCode::OK && body1.contains("\"credential_injected\":true"),
    });

    // 2. Unauthorized organization access (org-beta attempting GET /v1/github/repos/edgegate)
    let (st2, _body2) = send_proxy_request(
        proxy_addr,
        Method::GET,
        "/v1/github/repos/edgegate",
        Some("tok_beta_sandbox_02"),
        "",
    )
    .await?;
    rows.push(ConsoleRow {
        scenario: "Unauthorized organization access",
        security_control: "Tenant boundary enforced",
        decision_label: format!("BLOCKED ({})", st2),
        passed: st2 == StatusCode::FORBIDDEN,
    });

    // 3. OpenAI inference request (org-alpha authorized POST /v1/openai/chat/completions)
    let (st3, body3) = send_proxy_request(
        proxy_addr,
        Method::POST,
        "/v1/openai/chat/completions",
        Some("tok_alpha_sandbox_01"),
        "{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}",
    )
    .await?;
    rows.push(ConsoleRow {
        scenario: "OpenAI inference request",
        security_control: "Authorized upstream destination",
        decision_label: format!("ALLOWED ({})", st3),
        passed: st3 == StatusCode::OK && body3.contains("\"credential_injected\":true"),
    });

    // 4. Request to unapproved destination (org-alpha attempting GET /v1/unapproved/exfil)
    let (st4, _body4) = send_proxy_request(
        proxy_addr,
        Method::GET,
        "/v1/unapproved/exfil",
        Some("tok_alpha_sandbox_01"),
        "",
    )
    .await?;
    rows.push(ConsoleRow {
        scenario: "Request to unapproved destination",
        security_control: "Egress policy violation",
        decision_label: format!("BLOCKED ({})", st4),
        passed: st4 == StatusCode::FORBIDDEN,
    });

    // 5. Credential extraction / reflection attempt (org-alpha hitting /v1/github/repos/reflect-secret)
    let (st5, body5) = send_proxy_request(
        proxy_addr,
        Method::GET,
        "/v1/github/repos/reflect-secret",
        Some("tok_alpha_sandbox_01"),
        "",
    )
    .await?;
    rows.push(ConsoleRow {
        scenario: "Credential extraction / reflection attempt",
        security_control: "Credential reflection blocked",
        decision_label: format!("BLOCKED ({})", st5),
        passed: st5 == StatusCode::BAD_GATEWAY
            && !body5.contains("ghp_live_alpha_scoped_secret_99"),
    });

    let (_, metrics_json) =
        send_proxy_request(proxy_addr, Method::GET, "/_edgegate/metrics", None, "").await?;
    let (_, replay_json) =
        send_proxy_request(proxy_addr, Method::GET, "/_edgegate/replay", None, "").await?;

    let _ = proxy_shutdown_tx.send(());
    let _ = proxy_task.await;

    println!();
    println!("==========================================================================================================");
    println!("  EdgeGate Security Console — Zero-Secret Workload Egress & Credential Isolation Live Verification");
    println!("==========================================================================================================");
    println!(
        "  {:<44} | {:<33} | {:<22}",
        "Scenario", "Security Control", "Gateway Decision"
    );
    println!("-----------------------------------------------+-----------------------------------+----------------------");
    for row in &rows {
        let mark = if row.passed { "PASS" } else { "FAIL" };
        println!(
            "  {:<44} | {:<33} | {:<22} [{}]",
            row.scenario, row.security_control, row.decision_label, mark
        );
    }
    println!("==========================================================================================================");
    println!();
    println!("[/_edgegate/metrics Snapshot]");
    println!("{metrics_json}");
    println!();
    println!("[/_edgegate/replay Flight-Recorder Snapshot]");
    println!("{replay_json}");

    if rows.iter().any(|r| !r.passed) {
        return Err("one or more security console scenarios failed verification".into());
    }

    Ok(())
}
