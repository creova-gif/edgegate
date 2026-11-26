use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use edgegate::config::{CompiledConfig, CompiledWorkload};
use edgegate::proxy::EdgeGateProxy;
use http::header::AUTHORIZATION;
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::client::conn::http2 as client_http2;
use hyper::server::conn::http1 as server_http1;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream, UnixStream};

async fn spawn_http2_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind h2 upstream: {e}"));
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
                    let ver = format!("{:?}", req.version());
                    let auth = req
                        .headers()
                        .get(AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("NONE")
                        .to_string();
                    let body = format!("proto={ver};path={};auth={auth}", req.uri().path());
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = server_http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    addr
}

async fn spawn_status_upstream(status_code: StatusCode) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind status upstream: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits_clone);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let mut resp = Response::new(Full::new(Bytes::from_static(b"resp")));
                        *resp.status_mut() = status_code;
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    (addr, hits)
}

#[tokio::test]
async fn end_to_end_http2_inbound_and_outbound_with_credential_injection() {
    let h2_upstream = spawn_http2_upstream().await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "h2-agent"
org_id = "org-alpha"
token = "tok-h2"

[[pools]]
name = "h2-pool"
strategy = "consistent_hash"
allow_private_ip = true
backends = [
  {{ id = "h2-1", address = "{h2_upstream}", http2 = true }},
]

[[routes]]
id = "inference"
path_prefix = "/v1/openai"
strip_prefix = true
pool = "h2-pool"
[routes.credential]
credential_ref = "openai_key"
header_name = "Authorization"
value_prefix = "Bearer "

[[policies]]
org_id = "org-alpha"
route_id = "inference"
methods = ["GET"]
path_prefix = "/v1/openai"

[[secrets]]
org_id = "org-alpha"
credential_ref = "openai_key"
value = "sk_h2_secret_999"
"#
    );

    let compiled = CompiledConfig::from_toml_str(&toml_cfg)
        .unwrap_or_else(|e| panic!("compile h2 config: {e}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let gw_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = proxy.serve(listener, rx).await;
    });

    // Connect to EdgeGate using an HTTP/2 client (`h2c` prior knowledge) and send multiplexed requests!
    let stream = TcpStream::connect(gw_addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let io = TokioIo::new(stream);
    let (mut h2_sender, h2_conn) = client_http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap_or_else(|e| panic!("h2 handshake: {e}"));
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let req = Request::builder()
        .version(Version::HTTP_2)
        .method("GET")
        .uri("http://edgegate.local/v1/openai/models")
        .header("x-edgegate-token", "tok-h2")
        .header("x-edgegate-routing-key", "session-1")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));

    let resp = h2_sender
        .send_request(req)
        .await
        .unwrap_or_else(|e| panic!("h2 send: {e}"));
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"))
        .to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("proto=HTTP/2.0;path=/models;auth=Bearer sk_h2_secret_999"),
        "unexpected body: {text}"
    );
}

#[tokio::test]
async fn traffic_shadowing_replay_ring_buffer_and_dynamic_boxlet_sandbox() {
    let (primary_addr, primary_hits) = spawn_status_upstream(StatusCode::OK).await;
    // Shadow canary returns 500 so we trigger a shadow status mismatch + flight-recorder entry!
    let (shadow_addr, shadow_hits) = spawn_status_upstream(StatusCode::INTERNAL_SERVER_ERROR).await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
replay_buffer_size = 16

[[pools]]
name = "primary-pool"
strategy = "latency_aware"
allow_private_ip = true
backends = [
  {{ id = "primary-1", address = "{primary_addr}" }},
]

[[pools]]
name = "canary-shadow-pool"
strategy = "round_robin"
allow_private_ip = true
backends = [
  {{ id = "canary-1", address = "{shadow_addr}" }},
]

[[routes]]
id = "repos"
path_prefix = "/v1/github"
strip_prefix = true
pool = "primary-pool"
shadow_pool = "canary-shadow-pool"
[routes.credential]
credential_ref = "gh_pat"
header_name = "Authorization"
value_prefix = "Bearer "

[[policies]]
org_id = "org-boxlet"
required_roles = ["sandbox:exec"]
route_id = "repos"
methods = ["GET"]
path_prefix = "/v1/github"

[[secrets]]
org_id = "org-boxlet"
credential_ref = "gh_pat"
value = "ghp_boxlet_secret"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let gw_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));

    // Dynamically attach a Boxlet sandbox Unix domain socket at runtime!
    let boxlet_sock =
        std::env::temp_dir().join(format!("edgegate-boxlet-m3-{}.sock", std::process::id()));
    let boxlet_guard = proxy
        .register_boxlet_sandbox(
            boxlet_sock.clone(),
            CompiledWorkload {
                workload_id: "boxlet-vm-42".to_string(),
                org_id: "org-boxlet".to_string(),
                roles: ["sandbox:exec".to_string()].into_iter().collect(),
                max_concurrent_requests: None,
            },
        )
        .unwrap_or_else(|e| panic!("register_boxlet_sandbox: {e}"));

    let proxy_runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = proxy_runner.serve(listener, rx).await;
    });

    // 1. Send zero-token request over the dynamically attached Boxlet UDS socket.
    let uds_stream = UnixStream::connect(&boxlet_sock)
        .await
        .unwrap_or_else(|e| panic!("connect boxlet uds: {e}"));
    let io = TokioIo::new(uds_stream);
    let (mut uds_sender, uds_conn) = client_http1::handshake(io)
        .await
        .unwrap_or_else(|e| panic!("uds handshake: {e}"));
    tokio::spawn(async move {
        let _ = uds_conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("/v1/github/pulls")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let resp = uds_sender
        .send_request(req)
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await;

    // Wait briefly for the non-blocking background shadow dispatch to complete.
    tokio::time::sleep(Duration::from_millis(60)).await;

    assert_eq!(primary_hits.load(Ordering::SeqCst), 1);
    assert_eq!(shadow_hits.load(Ordering::SeqCst), 1);
    let snap = proxy.telemetry().snapshot();
    assert_eq!(snap.shadow_requests_total, 1);
    assert_eq!(snap.shadow_mismatches_total, 1);

    // 2. Query /_edgegate/replay and verify the sanitized shadow-mismatch record was captured
    //    with zero secrets!
    let tcp_stream = TcpStream::connect(gw_addr)
        .await
        .unwrap_or_else(|e| panic!("connect tcp: {e}"));
    let tcp_io = TokioIo::new(tcp_stream);
    let (mut tcp_sender, tcp_conn) = client_http1::handshake(tcp_io)
        .await
        .unwrap_or_else(|e| panic!("handshake: {e}"));
    tokio::spawn(async move {
        let _ = tcp_conn.await;
    });

    let replay_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/replay")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("replay req: {e}"));
    let replay_resp = tcp_sender
        .send_request(replay_req)
        .await
        .unwrap_or_else(|e| panic!("replay send: {e}"));
    assert_eq!(replay_resp.status(), StatusCode::OK);
    let replay_bytes = replay_resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("replay body: {e}"))
        .to_bytes();
    let replay_json = String::from_utf8_lossy(&replay_bytes);
    assert!(replay_json.contains("\"reason\":\"shadow_status_mismatch\""));
    assert!(replay_json.contains("\"workload_id\":\"boxlet-vm-42\""));
    assert!(replay_json.contains("\"shadow_status\":500"));
    assert!(!replay_json.contains("ghp_boxlet_secret"));

    // 3. Dropping BoxletSandboxGuard removes the socket file automatically.
    drop(boxlet_guard);
    assert!(!boxlet_sock.exists());
}
