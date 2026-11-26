use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

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
async fn operator_console_enforces_wcag_aa_accessibility_semantics_and_strict_csp() {
    let toml_cfg = r#"
[server]
listen_addr = "127.0.0.1:0"
replay_buffer_size = 16

[[workloads]]
workload_id = "agent-m12"
org_id = "org-m12"
token = "tok-m12"
roles = ["admin"]

[[pools]]
name = "m12-pool"
strategy = "round_robin"
allow_private_ip = true
backends = [
  { id = "up-1", address = "127.0.0.1:1" },
]

[[routes]]
id = "m12-route"
path_prefix = "/v1"
pool = "m12-pool"
"#;

    let compiled =
        CompiledConfig::from_toml_str(toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
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

    // 1. GET /_edgegate/console -> 200 OK and text/html
    let req = Request::builder()
        .method("GET")
        .uri("/_edgegate/console")
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, headers, body) = send_http1(gw_addr, req).await;
    assert_eq!(status, StatusCode::OK);

    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/html"),
        "content-type must start with text/html, got: {ct}"
    );

    // 2. Strict security headers
    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        csp.contains("default-src 'none'"),
        "CSP missing default-src 'none': {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP missing frame-ancestors 'none': {csp}"
    );
    assert!(
        csp.contains("connect-src 'self'"),
        "CSP missing connect-src 'self': {csp}"
    );

    assert_eq!(
        headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("referrer-policy").and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );

    // 3. Automated WCAG 2.1 AA & UX structural audit on HTML body
    assert!(
        body.contains("<html") && body.contains("lang=\"en\""),
        "HTML missing lang=\"en\""
    );
    assert!(
        body.contains("href=\"#main-content\""),
        "Missing skip navigation link (href=\"#main-content\")"
    );
    assert!(
        body.contains("<main") && body.contains("id=\"main-content\""),
        "Missing <main with id=\"main-content\""
    );
    assert!(
        body.contains("<nav") && body.contains("aria-label="),
        "Missing <nav with aria-label="
    );
    assert!(
        body.contains("aria-live=\"polite\"") && body.contains("role=\"status\""),
        "Missing live status region (aria-live=\"polite\" and role=\"status\")"
    );
    assert!(
        body.contains("<label for=") && body.contains("id="),
        "Missing explicit <label for= paired with matching input id="
    );
    assert!(
        body.contains("scope=\"col\"") && body.contains("<caption>"),
        "Missing accessible table headers (scope=\"col\") and <caption>"
    );
    assert!(
        body.contains(":focus-visible"),
        "Missing keyboard focus styling (:focus-visible)"
    );
    assert!(
        body.contains("prefers-reduced-motion") && body.contains("prefers-color-scheme"),
        "Missing motion & theme accessibility (prefers-reduced-motion and prefers-color-scheme)"
    );
    assert!(
        !body.contains("https://cdn"),
        "Body must not contain external CDN dependency https://cdn"
    );
    assert!(
        !body.contains("https://fonts"),
        "Body must not contain external fonts https://fonts"
    );
    assert!(
        !body.contains("localStorage"),
        "Body must not contain localStorage"
    );

    // 4. HEAD /_edgegate/console -> 200 OK with empty body
    let req_head = Request::builder()
        .method("HEAD")
        .uri("/_edgegate/console")
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status_head, _headers_head, body_head) = send_http1(gw_addr, req_head).await;
    assert_eq!(status_head, StatusCode::OK);
    assert!(
        body_head.is_empty(),
        "HEAD response body must be empty, got: {body_head}"
    );

    // 5. POST /_edgegate/console -> 405 (or 4xx)
    let req_post = Request::builder()
        .method("POST")
        .uri("/_edgegate/console")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from("hello")))
        .unwrap();
    let (status_post, _headers_post, _body_post) = send_http1(gw_addr, req_post).await;
    assert!(
        status_post == StatusCode::METHOD_NOT_ALLOWED || status_post.is_client_error(),
        "POST /_edgegate/console must return 405 or 4xx, got: {status_post}"
    );
}

async fn spawn_cors_upstream(hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind cors upstream: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let body = format!("agent-invoked:{}", req.uri().path());
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                    }
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn cors_preflight_short_circuits_approved_origins_and_enforces_origin_allowlist() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let upstream_addr = spawn_cors_upstream(Arc::clone(&upstream_hits)).await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
replay_buffer_size = 16

[[workloads]]
workload_id = "agent-m12"
org_id = "org-m12"
token = "tok-m12"
roles = ["agent:invoke"]

[[pools]]
name = "agent-pool"
strategy = "round_robin"
allow_private_ip = true
backends = [
  {{ id = "up-1", address = "{upstream_addr}" }},
]

[[routes]]
id = "agent-route"
path_prefix = "/v1/agent"
pool = "agent-pool"

[routes.cors]
allowed_origins = ["https://studio.edgegate.internal"]
allowed_methods = ["GET", "POST", "OPTIONS"]
allowed_headers = ["content-type", "x-edgegate-token", "traceparent"]
expose_headers = ["x-edgegate-trace-id"]
max_age_secs = 1200

[[policies]]
org_id = "org-m12"
workload_id = "agent-m12"
required_roles = ["agent:invoke"]
route_id = "agent-route"
methods = ["GET", "POST", "OPTIONS"]
path_prefix = "/v1/agent"
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
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = proxy.serve(listener, rx).await;
    });

    // (a) Send browser OPTIONS /v1/agent/invoke with approved Origin and Access-Control-Request-Method: POST (NO token!)
    let req_a = Request::builder()
        .method("OPTIONS")
        .uri("/v1/agent/invoke")
        .header("Host", "localhost")
        .header("Origin", "https://studio.edgegate.internal")
        .header("Access-Control-Request-Method", "POST")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status_a, headers_a, _body_a) = send_http1(gw_addr, req_a).await;
    assert_eq!(status_a, StatusCode::NO_CONTENT);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "Preflight OPTIONS must short-circuit upstream"
    );
    assert_eq!(
        headers_a
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://studio.edgegate.internal")
    );
    assert_eq!(
        headers_a.get("vary").and_then(|v| v.to_str().ok()),
        Some("Origin")
    );
    assert_eq!(
        headers_a
            .get("access-control-max-age")
            .and_then(|v| v.to_str().ok()),
        Some("1200")
    );
    let allow_methods = headers_a
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        allow_methods.contains("POST"),
        "access-control-allow-methods must contain POST, got: {allow_methods}"
    );

    // (b) Send browser OPTIONS /v1/agent/invoke with untrusted Origin: https://attacker.evil
    let req_b = Request::builder()
        .method("OPTIONS")
        .uri("/v1/agent/invoke")
        .header("Host", "localhost")
        .header("Origin", "https://attacker.evil")
        .header("Access-Control-Request-Method", "POST")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status_b, _headers_b, _body_b) = send_http1(gw_addr, req_b).await;
    assert_eq!(status_b, StatusCode::FORBIDDEN);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "Blocked preflight OPTIONS must not hit upstream"
    );

    // (c) Send authenticated POST /v1/agent/invoke with X-EdgeGate-Token and approved Origin
    let req_c = Request::builder()
        .method("POST")
        .uri("/v1/agent/invoke")
        .header("Host", "localhost")
        .header("X-EdgeGate-Token", "tok-m12")
        .header("Origin", "https://studio.edgegate.internal")
        .body(Full::new(Bytes::from(r#"{"action":"invoke"}"#)))
        .unwrap();
    let (status_c, headers_c, _body_c) = send_http1(gw_addr, req_c).await;
    assert_eq!(status_c, StatusCode::OK);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        1,
        "Authenticated POST with approved origin must hit upstream"
    );
    assert_eq!(
        headers_c
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://studio.edgegate.internal")
    );
    assert_eq!(
        headers_c
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok()),
        Some("x-edgegate-trace-id")
    );
    assert_eq!(
        headers_c.get("vary").and_then(|v| v.to_str().ok()),
        Some("Origin")
    );

    // (d) Send authenticated POST /v1/agent/invoke with X-EdgeGate-Token and untrusted Origin
    let req_d = Request::builder()
        .method("POST")
        .uri("/v1/agent/invoke")
        .header("Host", "localhost")
        .header("X-EdgeGate-Token", "tok-m12")
        .header("Origin", "https://attacker.evil")
        .body(Full::new(Bytes::from(r#"{"action":"invoke"}"#)))
        .unwrap();
    let (status_d, _headers_d, _body_d) = send_http1(gw_addr, req_d).await;
    assert_eq!(status_d, StatusCode::FORBIDDEN);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        1,
        "Blocked untrusted POST must not hit upstream"
    );
}

async fn spawn_echo_trace_and_state_upstream() -> SocketAddr {
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
                    let tp = req
                        .headers()
                        .get("traceparent")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("NONE")
                        .to_string();
                    let ts = req
                        .headers()
                        .get("tracestate")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("NONE")
                        .to_string();
                    let body = format!("tp={tp}|ts={ts}");
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn w3c_tracestate_propagates_valid_vendor_context_and_strips_malformed_headers() {
    let upstream_addr = spawn_echo_trace_and_state_upstream().await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
replay_buffer_size = 16

[[workloads]]
workload_id = "agent-m12"
org_id = "org-m12"
token = "tok-m12"
roles = ["api:read"]

[[pools]]
name = "trace-pool"
strategy = "round_robin"
allow_private_ip = true
backends = [
  {{ id = "up-1", address = "{upstream_addr}" }},
]

[[routes]]
id = "trace-route"
path_prefix = "/v1/trace"
pool = "trace-pool"

[[policies]]
org_id = "org-m12"
workload_id = "agent-m12"
required_roles = ["api:read"]
route_id = "trace-route"
methods = ["GET"]
path_prefix = "/v1/trace"
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
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = proxy.serve(listener, rx).await;
    });

    // 1. Valid traceparent and valid tracestate are preserved and forwarded
    let req1 = Request::builder()
        .method("GET")
        .uri("/v1/trace/test")
        .header("Host", "localhost")
        .header("X-EdgeGate-Token", "tok-m12")
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .header("tracestate", "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status1, _headers1, body1) = send_http1(gw_addr, req1).await;
    assert_eq!(status1, StatusCode::OK);
    assert!(
        body1.contains("tp=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        "Expected traceparent propagated, got: {body1}"
    );
    assert!(
        body1.contains("ts=congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"),
        "Expected tracestate propagated, got: {body1}"
    );

    // 2. Malformed tracestate (no equals sign) -> stripped cleanly
    let req2 = Request::builder()
        .method("GET")
        .uri("/v1/trace/test")
        .header("Host", "localhost")
        .header("X-EdgeGate-Token", "tok-m12")
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .header("tracestate", "invalid_no_equals_sign")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status2, _headers2, body2) = send_http1(gw_addr, req2).await;
    assert_eq!(status2, StatusCode::OK);
    assert!(
        body2.contains("ts=NONE"),
        "Malformed tracestate must be stripped, got: {body2}"
    );

    // 3. Oversized 600-byte tracestate -> stripped cleanly
    let oversized_ts = format!("vendor={}", "a".repeat(593)); // 7 + 593 = 600 bytes
    assert_eq!(oversized_ts.len(), 600);
    let req3 = Request::builder()
        .method("GET")
        .uri("/v1/trace/test")
        .header("Host", "localhost")
        .header("X-EdgeGate-Token", "tok-m12")
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .header("tracestate", oversized_ts)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status3, _headers3, body3) = send_http1(gw_addr, req3).await;
    assert_eq!(status3, StatusCode::OK);
    assert!(
        body3.contains("ts=NONE"),
        "Oversized tracestate must be stripped, got: {body3}"
    );
}

#[tokio::test]
async fn config_validation_rejects_wildcard_cors_origin() {
    let toml_wildcard = r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "agent-m12"
org_id = "org-m12"
token = "tok-m12"
roles = ["api:read"]

[[pools]]
name = "m12-pool"
strategy = "round_robin"
allow_private_ip = true
backends = [
  { id = "up-1", address = "127.0.0.1:8080" },
]

[[routes]]
id = "cors-wildcard"
path_prefix = "/v1"
pool = "m12-pool"

[routes.cors]
allowed_origins = ["*"]

[[policies]]
org_id = "org-m12"
workload_id = "agent-m12"
required_roles = ["api:read"]
route_id = "cors-wildcard"
methods = ["GET"]
path_prefix = "/v1"
"#;

    let res = CompiledConfig::from_toml_str(toml_wildcard);
    assert!(res.is_err(), "Expected error for wildcard CORS origin");
    let err_str = res.err().unwrap().to_string().to_ascii_lowercase();
    assert!(
        err_str.contains("wildcard"),
        "Expected error message to contain 'wildcard', got: {err_str}"
    );
}
