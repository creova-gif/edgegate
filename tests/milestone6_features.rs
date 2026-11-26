use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::header::AUTHORIZATION;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

async fn spawn_echo_auth_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind upstream: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let auth = req
                        .headers()
                        .get(AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("NONE")
                        .to_string();
                    let mcp_tool = req
                        .headers()
                        .get("x-mcp-tool")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("NONE")
                        .to_string();
                    let body = format!("auth={auth};tool={mcp_tool};path={}", req.uri().path());
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    addr
}

async fn send_http1(addr: SocketAddr, req: Request<Full<Bytes>>) -> (StatusCode, String) {
    let stream = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    let io = TokioIo::new(stream);
    let (mut sender, conn) = client_http1::handshake(io)
        .await
        .unwrap_or_else(|e| panic!("handshake: {e}"));
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender
        .send_request(req)
        .await
        .unwrap_or_else(|e| panic!("send_request: {e}"));
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("collect body: {e}"))
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn dual_workload_token_rollover_required_headers_policy_and_live_secret_rotation() {
    let upstream_addr = spawn_echo_auth_upstream().await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "mcp-agent"
org_id = "org-alpha"
token = "tok-primary-v1"
secondary_token = "tok-secondary-v2"
roles = ["mcp:exec"]

[[pools]]
name = "mcp-pool"
allow_private_ip = true
backends = [
  {{ id = "up-1", address = "{upstream_addr}" }},
]

[[routes]]
id = "mcp-github"
path_prefix = "/v1/mcp/github"
strip_prefix = true
pool = "mcp-pool"
[routes.credential]
credential_ref = "github_pat"
header_name = "Authorization"
value_prefix = "Bearer "

[[policies]]
org_id = "org-alpha"
workload_id = "mcp-agent"
required_roles = ["mcp:exec"]
route_id = "mcp-github"
methods = ["POST"]
path_prefix = "/v1/mcp/github"
required_headers = {{ "X-MCP-Tool" = "github.read_repo" }}

[[secrets]]
org_id = "org-alpha"
credential_ref = "github_pat"
value = "ghp_initial_v1"
expires_at_epoch_s = 4102444800
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    assert_eq!(
        compiled.workloads.len(),
        2,
        "expected both primary and secondary workload token digests registered"
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let gw_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let proxy_runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = proxy_runner.serve(listener, rx).await;
    });

    // (a) Dual workload token rollover: both primary `token` and `secondary_token` authenticate
    //     to the same workload when the required header matches.
    for tok in ["tok-primary-v1", "tok-secondary-v2"] {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/mcp/github/invoke")
            .header("x-edgegate-token", tok)
            .header("x-mcp-tool", "github.read_repo")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap_or_else(|e| panic!("req: {e}"));
        let (status, body) = send_http1(gw_addr, req).await;
        assert_eq!(status, StatusCode::OK, "tok={tok}, body={body}");
        assert_eq!(
            body,
            "auth=Bearer ghp_initial_v1;tool=github.read_repo;path=/invoke"
        );
    }

    // (b) Programmable request-attribute policy matching (`required_headers`):
    //     Missing `x-mcp-tool` header or disallowed tool `"github.delete_repo"` returns 403 Forbidden.
    let missing_hdr_req = Request::builder()
        .method("POST")
        .uri("/v1/mcp/github/invoke")
        .header("x-edgegate-token", "tok-primary-v1")
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap_or_else(|e| panic!("missing_hdr_req: {e}"));
    let (status_missing, _) = send_http1(gw_addr, missing_hdr_req).await;
    assert_eq!(status_missing, StatusCode::FORBIDDEN);

    let wrong_hdr_req = Request::builder()
        .method("POST")
        .uri("/v1/mcp/github/invoke")
        .header("x-edgegate-token", "tok-secondary-v2")
        .header("x-mcp-tool", "github.delete_repo")
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap_or_else(|e| panic!("wrong_hdr_req: {e}"));
    let (status_wrong, _) = send_http1(gw_addr, wrong_hdr_req).await;
    assert_eq!(status_wrong, StatusCode::FORBIDDEN);

    // (c) Live credential rotation: `proxy.rotate_secret(...)` immediately injects the new secret
    //     without a full config reload and increments `secret_rotations_total`.
    proxy.rotate_secret(
        "org-alpha",
        "github_pat",
        "ghp_rotated_live_v2".to_string(),
        Some(4_102_444_800),
    );
    assert_eq!(proxy.telemetry().snapshot().secret_rotations_total, 1);

    let rotated_req = Request::builder()
        .method("POST")
        .uri("/v1/mcp/github/invoke")
        .header("x-edgegate-token", "tok-secondary-v2")
        .header("x-mcp-tool", "github.read_repo")
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap_or_else(|e| panic!("rotated_req: {e}"));
    let (status_rot, body_rot) = send_http1(gw_addr, rotated_req).await;
    assert_eq!(status_rot, StatusCode::OK);
    assert_eq!(
        body_rot,
        "auth=Bearer ghp_rotated_live_v2;tool=github.read_repo;path=/invoke"
    );

    // Expired credential rejection: rotating `expires_at_epoch_s = Some(1)` causes `403 Forbidden`.
    proxy.rotate_secret(
        "org-alpha",
        "github_pat",
        "ghp_expired_v3".to_string(),
        Some(1),
    );
    assert_eq!(proxy.telemetry().snapshot().secret_rotations_total, 2);

    let expired_req = Request::builder()
        .method("POST")
        .uri("/v1/mcp/github/invoke")
        .header("x-edgegate-token", "tok-primary-v1")
        .header("x-mcp-tool", "github.read_repo")
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap_or_else(|e| panic!("expired_req: {e}"));
    let (status_exp, _) = send_http1(gw_addr, expired_req).await;
    assert_eq!(status_exp, StatusCode::FORBIDDEN);

    // Verify JSON and Prometheus telemetry expose `secret_rotations_total: 2`.
    let metrics_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("metrics_req: {e}"));
    let (m_status, m_body) = send_http1(gw_addr, metrics_req).await;
    assert_eq!(m_status, StatusCode::OK);
    assert!(
        m_body.contains("\"secret_rotations_total\":2"),
        "metrics JSON missing secret_rotations_total: {m_body}"
    );

    let prom_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics?format=prometheus")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("prom_req: {e}"));
    let (p_status, p_body) = send_http1(gw_addr, prom_req).await;
    assert_eq!(p_status, StatusCode::OK);
    assert!(
        p_body.contains("edgegate_secret_rotations_total 2"),
        "prometheus output missing edgegate_secret_rotations_total: {p_body}"
    );
}
