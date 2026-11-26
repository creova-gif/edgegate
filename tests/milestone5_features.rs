use std::convert::Infallible;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::client::conn::http2 as client_http2;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

async fn spawn_reflection_and_echo_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind upstream: {e}"));
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
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let auth = req
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("NONE")
                            .to_string();
                        match req.uri().path() {
                            "/leak-body" => Ok::<_, Infallible>(Response::new(Full::new(
                                Bytes::from(format!("debug_echo={auth}")),
                            ))),
                            "/leak-header" => {
                                let mut resp =
                                    Response::new(Full::new(Bytes::from_static(b"safe_body")));
                                if let Ok(hv) = HeaderValue::from_str(&auth) {
                                    resp.headers_mut().insert("x-debug-auth", hv);
                                }
                                Ok::<_, Infallible>(resp)
                            }
                            _ => Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                                format!("clean_ok:path={}", req.uri().path()),
                            )))),
                        }
                    }
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    (addr, hits)
}

async fn send_http1(
    addr: SocketAddr,
    req: Request<Full<Bytes>>,
) -> (StatusCode, HeaderMap, String) {
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
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("collect body: {e}"))
        .to_bytes();
    (status, headers, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn inbound_tls_http2_alpn_works_end_to_end() {
    let certified = rcgen::generate_simple_self_signed(vec!["edgegate.local".to_string()])
        .unwrap_or_else(|e| panic!("rcgen: {e}"));
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();

    let (upstream_addr, _) = spawn_reflection_and_echo_upstream().await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
drain_timeout_ms = 2000

[server.tls]
cert_pem = '''
{cert_pem}'''
key_pem = '''
{key_pem}'''

[[workloads]]
workload_id = "tls-client"
org_id = "org-alpha"
token = "tok-m5-tls"
roles = ["api:call"]

[[pools]]
name = "m5-pool"
allow_private_ip = true
backends = [
  {{ id = "up-1", address = "{upstream_addr}" }},
]

[[routes]]
id = "m5-route"
path_prefix = "/v1/api"
strip_prefix = true
pool = "m5-pool"
[routes.credential]
credential_ref = "m5_secret"
header_name = "Authorization"
value_prefix = "Bearer "
block_secret_reflection = true

[[policies]]
org_id = "org-alpha"
required_roles = ["api:call"]
route_id = "m5-route"
methods = ["GET"]
path_prefix = "/v1/api"

[[secrets]]
org_id = "org-alpha"
credential_ref = "m5_secret"
value = "sk_live_m5_ultra_secret"
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
    let (tx, rx) = tokio::sync::oneshot::channel();
    let serve_handle = tokio::spawn(async move { proxy.serve(listener, rx).await });

    // Build a rustls client with h2 ALPN trusting our self-signed cert.
    let mut cert_reader = Cursor::new(cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .map(|r| r.unwrap_or_else(|e| panic!("cert: {e}")))
        .collect();
    let mut root_store = RootCertStore::empty();
    for c in certs {
        root_store
            .add(c)
            .unwrap_or_else(|e| panic!("add root cert: {e}"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("proto: {e}"))
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let tcp = TcpStream::connect(gw_addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let sni =
        ServerName::try_from("edgegate.local".to_string()).unwrap_or_else(|e| panic!("sni: {e}"));
    let tls_stream = connector
        .connect(sni, tcp)
        .await
        .unwrap_or_else(|e| panic!("tls connect: {e}"));
    assert_eq!(
        tls_stream.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "expected inbound TLS to negotiate h2 ALPN"
    );

    let io = TokioIo::new(tls_stream);
    let (mut h2_sender, h2_conn) = client_http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap_or_else(|e| panic!("h2 handshake: {e}"));
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let req = Request::builder()
        .version(Version::HTTP_2)
        .method("GET")
        .uri("https://edgegate.local/v1/api/models")
        .header("x-edgegate-token", "tok-m5-tls")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let resp = h2_sender
        .send_request(req)
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"))
        .to_bytes();
    assert_eq!(
        String::from_utf8_lossy(&body_bytes),
        "clean_ok:path=/models"
    );

    // Trigger graceful shutdown and verify clean exit.
    let _ = tx.send(());
    let serve_res = serve_handle
        .await
        .unwrap_or_else(|e| panic!("join serve: {e}"));
    assert!(serve_res.is_ok());
}

#[tokio::test]
async fn credential_reflection_guard_and_controlled_idempotent_retries() {
    let (live_addr, live_hits) = spawn_reflection_and_echo_upstream().await;

    // Reserve an ephemeral port and drop the listener immediately so backend-1 is guaranteed dead.
    let dead_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind dead: {e}"));
    let dead_addr = dead_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("dead local_addr: {e}"));
    drop(dead_listener);

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
replay_buffer_size = 32

[[workloads]]
workload_id = "agent-m5"
org_id = "org-alpha"
token = "tok-m5"
roles = ["api:rw"]

[[pools]]
name = "retry-pool"
strategy = "round_robin"
allow_private_ip = true
max_idempotent_retries = 1
passive_failure_threshold = 5
backends = [
  {{ id = "dead-1", address = "{dead_addr}" }},
  {{ id = "live-2", address = "{live_addr}" }},
]

[[routes]]
id = "guarded-api"
path_prefix = "/v1/api"
strip_prefix = true
pool = "retry-pool"
[routes.credential]
credential_ref = "guarded_secret"
header_name = "Authorization"
value_prefix = "Bearer "
block_secret_reflection = true

[[policies]]
org_id = "org-alpha"
required_roles = ["api:rw"]
route_id = "guarded-api"
methods = ["GET", "POST"]
path_prefix = "/v1/api"

[[secrets]]
org_id = "org-alpha"
credential_ref = "guarded_secret"
value = "sk_reflected_secret_999"
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
    let proxy_runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = proxy_runner.serve(listener, rx).await;
    });

    // 1. First request is GET /v1/api/clean: RoundRobin picks dead-1 first, fails with 502,
    //    and automatically retries idempotent GET on live-2 -> 200 OK!
    let get_req = Request::builder()
        .method("GET")
        .uri("/v1/api/clean")
        .header("x-edgegate-token", "tok-m5")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("get_req: {e}"));
    let (status1, _, body1) = send_http1(gw_addr, get_req).await;
    assert_eq!(status1, StatusCode::OK, "unexpected status1: {body1}");
    assert_eq!(body1, "clean_ok:path=/clean");
    assert_eq!(proxy.telemetry().snapshot().retries_total, 1);
    assert_eq!(live_hits.load(Ordering::SeqCst), 1);

    // 2. Next request is POST /v1/api/clean: RoundRobin cursor is back on dead-1 (index 2 % 2 == 0).
    //    Because POST is non-idempotent, EdgeGate MUST NOT retry -> returns 502 Bad Gateway!
    let post_req = Request::builder()
        .method("POST")
        .uri("/v1/api/clean")
        .header("x-edgegate-token", "tok-m5")
        .body(Full::new(Bytes::from_static(b"{\"item\":1}")))
        .unwrap_or_else(|e| panic!("post_req: {e}"));
    let (status2, _, _) = send_http1(gw_addr, post_req).await;
    assert_eq!(status2, StatusCode::BAD_GATEWAY);
    assert_eq!(
        proxy.telemetry().snapshot().retries_total,
        1,
        "POST must never increment retries_total"
    );

    // 3. Response Credential Reflection Guard: upstream echoes secret in body (/leak-body) -> blocked with 502!
    let leak_body_req = Request::builder()
        .method("GET")
        .uri("/v1/api/leak-body")
        .header("x-edgegate-token", "tok-m5")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("leak_body_req: {e}"));
    let (status3, _, body3) = send_http1(gw_addr, leak_body_req).await;
    assert_eq!(status3, StatusCode::BAD_GATEWAY);
    assert!(!body3.contains("sk_reflected_secret_999"));
    assert_eq!(
        proxy
            .telemetry()
            .snapshot()
            .secret_reflections_blocked_total,
        1
    );

    // 4. Response Credential Reflection Guard: upstream echoes secret in header (/leak-header) -> blocked with 502!
    let leak_hdr_req = Request::builder()
        .method("GET")
        .uri("/v1/api/leak-header")
        .header("x-edgegate-token", "tok-m5")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("leak_hdr_req: {e}"));
    let (status4, headers4, body4) = send_http1(gw_addr, leak_hdr_req).await;
    assert_eq!(status4, StatusCode::BAD_GATEWAY);
    assert!(headers4.get("x-debug-auth").is_none());
    assert!(!body4.contains("sk_reflected_secret_999"));
    assert_eq!(
        proxy
            .telemetry()
            .snapshot()
            .secret_reflections_blocked_total,
        2
    );

    // 5. Verify replay buffer and Prometheus metrics include reflection guard & retry counters.
    let replay_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/replay")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("replay_req: {e}"));
    let (_, _, replay_body) = send_http1(gw_addr, replay_req).await;
    assert!(replay_body.contains("\"reason\":\"credential_reflection_blocked\""));
    assert!(!replay_body.contains("sk_reflected_secret_999"));

    let prom_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics?format=prometheus")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("prom_req: {e}"));
    let (p_status, _, p_body) = send_http1(gw_addr, prom_req).await;
    assert_eq!(p_status, StatusCode::OK);
    assert!(p_body.contains("edgegate_secret_reflections_blocked_total 2"));
    assert!(p_body.contains("edgegate_retries_total 2"));
    assert!(p_body.contains("# TYPE edgegate_in_flight_requests gauge"));
}
