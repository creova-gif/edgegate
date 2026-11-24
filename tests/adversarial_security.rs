use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::header::{AUTHORIZATION, CONNECTION, LOCATION, PROXY_AUTHORIZATION};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

struct MockUpstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn spawn_mock_upstream(
    backend_label: &'static str,
    attacker_url: Option<String>,
) -> MockUpstream {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind mock upstream: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (tx, mut rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let hits = Arc::clone(&hits_clone);
                    let attacker_url = attacker_url.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let hits = Arc::clone(&hits);
                            let attacker_url = attacker_url.clone();
                            async move {
                                hits.fetch_add(1, Ordering::SeqCst);
                                let path = req.uri().path().to_string();
                                let auth = req
                                    .headers()
                                    .get(AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("NONE")
                                    .to_string();
                                let leaked_token = req.headers().get("x-edgegate-token").is_some();
                                let leaked_proxy_auth = req.headers().get(PROXY_AUTHORIZATION).is_some();

                                if path == "/repos/redirect" {
                                    let target = attacker_url
                                        .unwrap_or_else(|| "http://evil.invalid/steal".to_string());
                                    let mut resp = Response::new(Full::new(Bytes::from("redirect")));
                                    *resp.status_mut() = StatusCode::FOUND;
                                    if let Ok(val) = target.parse() {
                                        resp.headers_mut().insert(LOCATION, val);
                                    }
                                    return Ok::<_, Infallible>(resp);
                                }

                                if path == "/repos/slow" {
                                    tokio::time::sleep(Duration::from_millis(250)).await;
                                }

                                let body = format!(
                                    "backend={backend_label};path={path};auth={auth};leaked_tok={leaked_token};leaked_proxy_auth={leaked_proxy_auth}"
                                );
                                let mut resp = Response::new(Full::new(Bytes::from(body)));
                                if path == "/repos/close" {
                                    resp.headers_mut().insert(
                                        CONNECTION,
                                        http::HeaderValue::from_static("close"),
                                    );
                                }
                                Ok::<_, Infallible>(resp)
                            }
                        });
                        let _ = server_http1::Builder::new().serve_connection(io, svc).await;
                    });
                }
            }
        }
    });

    MockUpstream {
        addr,
        hits,
        _shutdown: tx,
    }
}

async fn spawn_edgegate(toml_cfg: &str) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let compiled = CompiledConfig::from_toml_str(toml_cfg)
        .unwrap_or_else(|e| panic!("invalid test config: {e}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind edgegate: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("edgegate local_addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = proxy.serve(listener, rx).await;
    });
    (addr, tx)
}

async fn send_raw(addr: SocketAddr, req: Request<Full<Bytes>>) -> (StatusCode, String) {
    let stream = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    let io = TokioIo::new(stream);
    let (mut sender, conn) = client_http1::handshake(io)
        .await
        .unwrap_or_else(|e| panic!("client handshake: {e}"));
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
async fn adversarial_security_and_load_balancing_suite() {
    let attacker = spawn_mock_upstream("attacker", None).await;
    let attacker_url = format!("http://{}/steal", attacker.addr);

    let up_a = spawn_mock_upstream("upstream-a", Some(attacker_url.clone())).await;
    let up_b = spawn_mock_upstream("upstream-b", Some(attacker_url)).await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
connect_timeout_ms = 1000
response_timeout_ms = 2000

[[workloads]]
workload_id = "agent-alpha"
org_id = "org-alpha"
token = "tok-alpha"

[[workloads]]
workload_id = "agent-beta"
org_id = "org-beta"
token = "tok-beta"

[[pools]]
name = "github-pool"
strategy = "round_robin"
max_connections_per_upstream = 8
allow_private_ip = true
backends = [
  {{ id = "upstream-a", address = "{}" }},
  {{ id = "upstream-b", address = "{}" }},
]

[[pools]]
name = "ssrf-strict-pool"
strategy = "round_robin"
allow_private_ip = false
backends = [
  {{ id = "metadata", address = "169.254.169.254:80" }},
]

[[pools]]
name = "ssrf-v6-mapped-pool"
strategy = "round_robin"
allow_private_ip = false
backends = [
  {{ id = "metadata-v6", address = "[::ffff:169.254.169.254]:80" }},
]

[[routes]]
id = "github"
path_prefix = "/v1/github"
strip_prefix = true
pool = "github-pool"
[routes.credential]
credential_ref = "github_pat"
header_name = "Authorization"
value_prefix = "Bearer "

[[routes]]
id = "ssrf-test"
path_prefix = "/v1/ssrf"
pool = "ssrf-strict-pool"

[[routes]]
id = "ssrf-v6-test"
path_prefix = "/v1/ssrf-v6"
pool = "ssrf-v6-mapped-pool"

[[policies]]
org_id = "org-alpha"
route_id = "github"
methods = ["GET"]
path_prefix = "/v1/github/repos"

[[policies]]
org_id = "org-alpha"
route_id = "ssrf-test"
methods = ["GET"]
path_prefix = "/v1/ssrf"

[[policies]]
org_id = "org-alpha"
route_id = "ssrf-v6-test"
methods = ["GET"]
path_prefix = "/v1/ssrf-v6"

[[secrets]]
org_id = "org-alpha"
credential_ref = "github_pat"
value = "ghp_alpha_real_secret"
"#,
        up_a.addr, up_b.addr
    );

    let (gw_addr, _gw_shutdown) = spawn_edgegate(&toml_cfg).await;

    // 1. Authorized requests succeed, inject scoped credential, strip client auth headers,
    //    and load-balance across upstream-a and upstream-b.
    let mut seen_a = false;
    let mut seen_b = false;
    for _ in 0..4 {
        let req = Request::builder()
            .method("GET")
            .uri("/v1/github/repos/edgegate")
            .header("x-edgegate-token", "tok-alpha")
            .header(AUTHORIZATION, "Bearer forged-client-key")
            .header(PROXY_AUTHORIZATION, "Basic forged")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|e| panic!("build req: {e}"));
        let (status, body) = send_raw(gw_addr, req).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert!(body.contains("auth=Bearer ghp_alpha_real_secret"));
        assert!(body.contains("leaked_tok=false"));
        assert!(body.contains("leaked_proxy_auth=false"));
        if body.contains("backend=upstream-a") {
            seen_a = true;
        }
        if body.contains("backend=upstream-b") {
            seen_b = true;
        }
    }
    assert!(
        seen_a && seen_b,
        "expected round-robin across both backends"
    );

    // 2. Cross-tenant org_id (org-beta) is blocked with 403.
    let cross_org = Request::builder()
        .method("GET")
        .uri("/v1/github/repos/edgegate")
        .header("x-edgegate-token", "tok-beta")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build req: {e}"));
    let (status, _) = send_raw(gw_addr, cross_org).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 3. Unapproved destination & disallowed HTTP method are blocked (default-deny).
    let unapproved_route = Request::builder()
        .method("GET")
        .uri("/v1/openai/chat")
        .header("x-edgegate-token", "tok-alpha")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build req: {e}"));
    let (status, _) = send_raw(gw_addr, unapproved_route).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let disallowed_method = Request::builder()
        .method("DELETE")
        .uri("/v1/github/repos/edgegate")
        .header("x-edgegate-token", "tok-alpha")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build req: {e}"));
    let (status, _) = send_raw(gw_addr, disallowed_method).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 4. Path traversal bypass attempts fail closed with 400.
    for bad_path in ["/v1/github/repos/../admin", "/v1/github/repos/%2e%2e/admin"] {
        let req = Request::builder()
            .method("GET")
            .uri(bad_path)
            .header("x-edgegate-token", "tok-alpha")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|e| panic!("build req: {e}"));
        let (status, _) = send_raw(gw_addr, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "path: {bad_path}");
    }

    // 5. Upstream 302 redirect is returned verbatim without EdgeGate following it or leaking credentials.
    let redirect_req = Request::builder()
        .method("GET")
        .uri("/v1/github/repos/redirect")
        .header("x-edgegate-token", "tok-alpha")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build req: {e}"));
    let (status, _) = send_raw(gw_addr, redirect_req).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        attacker.hits.load(Ordering::SeqCst),
        0,
        "EdgeGate must NEVER follow 3xx redirects or leak credentials to redirect target"
    );

    // 6. SSRF guard blocks IPv4 metadata and IPv4-mapped IPv6 metadata when allow_private_ip = false.
    for ssrf_path in ["/v1/ssrf/latest", "/v1/ssrf-v6/latest"] {
        let req = Request::builder()
            .method("GET")
            .uri(ssrf_path)
            .header("x-edgegate-token", "tok-alpha")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|e| panic!("build req: {e}"));
        let (status, _) = send_raw(gw_addr, req).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "ssrf path: {ssrf_path}");
    }

    // 7. Connection: close from upstream cleanly discards socket without poisoning subsequent calls.
    let close_req = Request::builder()
        .method("GET")
        .uri("/v1/github/repos/close")
        .header("x-edgegate-token", "tok-alpha")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build req: {e}"));
    let (status, _) = send_raw(gw_addr, close_req).await;
    assert_eq!(status, StatusCode::OK);

    let follow_up = Request::builder()
        .method("GET")
        .uri("/v1/github/repos/ok")
        .header("x-edgegate-token", "tok-alpha")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build req: {e}"));
    let (status, _) = send_raw(gw_addr, follow_up).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn local_pool_exhaustion_returns_503_without_ejecting_healthy_backend() {
    let up = spawn_mock_upstream("single", None).await;
    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
connect_timeout_ms = 1000
response_timeout_ms = 2000

[[workloads]]
workload_id = "agent-1"
org_id = "org-alpha"
token = "tok-1"

[[pools]]
name = "tight-pool"
strategy = "round_robin"
max_connections_per_upstream = 1
passive_failure_threshold = 1
passive_cooldown_ms = 60000
allow_private_ip = true
backends = [
  {{ id = "only", address = "{}" }},
]

[[routes]]
id = "api"
path_prefix = "/v1/github"
strip_prefix = true
pool = "tight-pool"

[[policies]]
org_id = "org-alpha"
route_id = "api"
methods = ["GET"]
path_prefix = "/v1/github"
"#,
        up.addr
    );

    let (gw_addr, _gw_shutdown) = spawn_edgegate(&toml_cfg).await;

    // Fire 1 slow request (holds the single pool permit for 250ms) and a concurrent second request.
    let slow_task = tokio::spawn(async move {
        let req = Request::builder()
            .method("GET")
            .uri("/v1/github/repos/slow")
            .header("x-edgegate-token", "tok-1")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|e| panic!("build slow req: {e}"));
        send_raw(gw_addr, req).await
    });

    tokio::time::sleep(Duration::from_millis(40)).await;

    let burst_req = Request::builder()
        .method("GET")
        .uri("/v1/github/repos/fast")
        .header("x-edgegate-token", "tok-1")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build burst req: {e}"));
    let (burst_status, _) = send_raw(gw_addr, burst_req).await;
    assert_eq!(burst_status, StatusCode::SERVICE_UNAVAILABLE);

    let (slow_status, _) = slow_task
        .await
        .unwrap_or_else(|e| panic!("join slow task: {e}"));
    assert_eq!(slow_status, StatusCode::OK);

    // Even with passive_failure_threshold = 1 and 60s cooldown, the local 503 must NOT have ejected the backend.
    let after_req = Request::builder()
        .method("GET")
        .uri("/v1/github/repos/after")
        .header("x-edgegate-token", "tok-1")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build after req: {e}"));
    let (after_status, _) = send_raw(gw_addr, after_req).await;
    assert_eq!(after_status, StatusCode::OK);
}
