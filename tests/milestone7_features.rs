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

async fn spawn_labeled_upstream(label: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind {label}: {e}"));
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
                let svc = service_fn(move |req: Request<Incoming>| async move {
                    let auth = req
                        .headers()
                        .get(AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("NONE")
                        .to_string();
                    let body = format!("backend={label};auth={auth};path={}", req.uri().path());
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
async fn weighted_canary_lb_query_and_body_guards_admin_control_plane_and_hash_chained_audit() {
    let addr_a = spawn_labeled_upstream("backend-a").await;
    let addr_b = spawn_labeled_upstream("backend-b").await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
admin_token = "adm-secret-token-m7"

[[workloads]]
workload_id = "iora-agent"
org_id = "org-alpha"
token = "tok-m7"
roles = ["rag:query"]

[[pools]]
name = "canary-pool"
strategy = "round_robin"
allow_private_ip = true
backends = [
  {{ id = "backend-a", address = "{addr_a}", weight = 3 }},
  {{ id = "backend-b", address = "{addr_b}", weight = 1 }},
]

[[routes]]
id = "rag-route"
path_prefix = "/v1/rag"
strip_prefix = true
pool = "canary-pool"
[routes.credential]
credential_ref = "rag_api_key"
header_name = "Authorization"
value_prefix = "Bearer "

[[policies]]
org_id = "org-alpha"
workload_id = "iora-agent"
required_roles = ["rag:query"]
route_id = "rag-route"
methods = ["GET", "POST"]
path_prefix = "/v1/rag"
forbidden_query_params = ["debug", "api_key"]
max_body_bytes = 16

[[secrets]]
org_id = "org-alpha"
credential_ref = "rag_api_key"
value = "rag_key_v1"
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

    // (a) Weighted canary load balancing: weight = 3 on backend-a, weight = 1 on backend-b
    //     distributes 4 requests 3:1.
    let mut hits_a = 0usize;
    let mut hits_b = 0usize;
    for _ in 0..4 {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/rag/search?limit=10")
            .header("x-edgegate-token", "tok-m7")
            .body(Full::new(Bytes::from_static(b"{\"q\":\"ok\"}")))
            .unwrap_or_else(|e| panic!("req: {e}"));
        let (status, body) = send_http1(gw_addr, req).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert!(body.contains("auth=Bearer rag_key_v1"));
        if body.contains("backend=backend-a") {
            hits_a += 1;
        } else if body.contains("backend=backend-b") {
            hits_b += 1;
        }
    }
    assert_eq!(hits_a, 3, "expected 3 requests routed to backend-a");
    assert_eq!(hits_b, 1, "expected 1 request routed to backend-b");

    // (b) Per-rule `forbidden_query_params = ["debug", "api_key"]` blocks `?debug=true` with 403,
    //     and per-rule `max_body_bytes = 16` blocks a 32-byte body with 413 Payload Too Large.
    let forbidden_q_req = Request::builder()
        .method("GET")
        .uri("/v1/rag/search?limit=5&debug=true")
        .header("x-edgegate-token", "tok-m7")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("forbidden_q_req: {e}"));
    let (fq_status, _) = send_http1(gw_addr, forbidden_q_req).await;
    assert_eq!(fq_status, StatusCode::FORBIDDEN);

    let oversized_body_req = Request::builder()
        .method("POST")
        .uri("/v1/rag/search")
        .header("x-edgegate-token", "tok-m7")
        .body(Full::new(Bytes::from_static(
            b"0123456789abcdef0123456789abcdef",
        )))
        .unwrap_or_else(|e| panic!("oversized_body_req: {e}"));
    let (ob_status, _) = send_http1(gw_addr, oversized_body_req).await;
    assert_eq!(ob_status, StatusCode::PAYLOAD_TOO_LARGE);

    // (c) Authenticated Admin Control Plane rejects unauthenticated calls with 401
    //     and succeeds with `X-EdgeGate-Admin-Token`.
    for (method, path) in [
        ("GET", "/_edgegate/admin/audit"),
        ("POST", "/_edgegate/admin/reload"),
        ("POST", "/_edgegate/admin/secrets/rotate"),
    ] {
        let unauth_req = Request::builder()
            .method(method)
            .uri(path)
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|e| panic!("unauth_req: {e}"));
        let (u_status, _) = send_http1(gw_addr, unauth_req).await;
        assert_eq!(
            u_status,
            StatusCode::UNAUTHORIZED,
            "expected 401 for unauthenticated {method} {path}"
        );
    }

    // Rotate secret via `POST /_edgegate/admin/secrets/rotate` with valid admin token.
    let rotate_payload = r#"
org_id = "org-alpha"
credential_ref = "rag_api_key"
value = "rag_key_rotated_v2"
expires_at_epoch_s = 4102444800
"#;
    let admin_rot_req = Request::builder()
        .method("POST")
        .uri("/_edgegate/admin/secrets/rotate")
        .header("x-edgegate-admin-token", "adm-secret-token-m7")
        .body(Full::new(Bytes::from(rotate_payload)))
        .unwrap_or_else(|e| panic!("admin_rot_req: {e}"));
    let (rot_status, rot_body) = send_http1(gw_addr, admin_rot_req).await;
    assert_eq!(rot_status, StatusCode::OK, "rot_body: {rot_body}");
    assert!(rot_body.contains("\"status\":\"rotated\""));

    let verify_rot_req = Request::builder()
        .method("GET")
        .uri("/v1/rag/search")
        .header("x-edgegate-token", "tok-m7")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("verify_rot_req: {e}"));
    let (v_status, v_body) = send_http1(gw_addr, verify_rot_req).await;
    assert_eq!(v_status, StatusCode::OK);
    assert!(v_body.contains("auth=Bearer rag_key_rotated_v2"));

    // Reload configuration via `POST /_edgegate/admin/reload` with valid admin token.
    let reloaded_toml =
        toml_cfg.replace("value = \"rag_key_v1\"", "value = \"rag_key_reloaded_v3\"");
    let admin_reload_req = Request::builder()
        .method("POST")
        .uri("/_edgegate/admin/reload")
        .header("x-edgegate-admin-token", "adm-secret-token-m7")
        .body(Full::new(Bytes::from(reloaded_toml)))
        .unwrap_or_else(|e| panic!("admin_reload_req: {e}"));
    let (rel_status, rel_body) = send_http1(gw_addr, admin_reload_req).await;
    assert_eq!(rel_status, StatusCode::OK, "rel_body: {rel_body}");
    assert!(rel_body.contains("\"status\":\"reloaded\""));
    assert!(rel_body.contains("\"config_generation\":2"));

    // (d) Cryptographic SHA-256 hash-chained audit trail (`GET /_edgegate/admin/audit`)
    //     and Prometheus latency histogram (`edgegate_request_duration_microseconds_bucket`).
    assert!(proxy.telemetry().verify_audit_chain());
    let entries = proxy.telemetry().audit_entries();
    assert!(entries.len() >= 7);
    assert_eq!(entries[0].prev_hash, "0".repeat(64));
    for window in entries.windows(2) {
        assert_eq!(
            window[1].prev_hash, window[0].entry_hash,
            "broken hash chain link between seq {} and {}",
            window[0].seq, window[1].seq
        );
    }

    let audit_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/admin/audit")
        .header("x-edgegate-admin-token", "adm-secret-token-m7")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("audit_req: {e}"));
    let (a_status, a_body) = send_http1(gw_addr, audit_req).await;
    assert_eq!(a_status, StatusCode::OK);
    assert!(
        a_body.contains("\"valid\":true"),
        "audit JSON invalid: {a_body}"
    );
    assert!(a_body.contains(&format!("\"prev_hash\":\"{}\"", "0".repeat(64))));
    assert!(a_body.contains(&format!("\"prev_hash\":\"{}\"", entries[0].entry_hash)));

    let prom_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics?format=prometheus")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("prom_req: {e}"));
    let (p_status, p_body) = send_http1(gw_addr, prom_req).await;
    assert_eq!(p_status, StatusCode::OK);
    assert!(
        p_body.contains("# TYPE edgegate_request_duration_microseconds histogram"),
        "missing histogram type in prometheus output: {p_body}"
    );
    assert!(
        p_body.contains("edgegate_request_duration_microseconds_bucket{le=\"100\"}"),
        "missing histogram bucket in prometheus output: {p_body}"
    );
    assert!(
        p_body.contains("edgegate_request_duration_microseconds_bucket{le=\"+Inf\"}"),
        "missing +Inf bucket in prometheus output: {p_body}"
    );

    let json_metrics_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("json_metrics_req: {e}"));
    let (jm_status, jm_body) = send_http1(gw_addr, json_metrics_req).await;
    assert_eq!(jm_status, StatusCode::OK);
    assert!(jm_body.contains("\"audit_chain_valid\":true"));
}
