use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::header::{ACCEPT, RETRY_AFTER};
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

async fn spawn_echo_trace_upstream() -> SocketAddr {
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
                        .unwrap_or("MISSING")
                        .to_string();
                    let mut resp =
                        Response::new(Full::new(Bytes::from(format!("upstream_tp={tp}"))));
                    if req.uri().path() == "/fail500" {
                        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    }
                    Ok::<_, Infallible>(resp)
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    addr
}

async fn send_req(addr: SocketAddr, req: Request<Full<Bytes>>) -> (StatusCode, HeaderMap, String) {
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
async fn token_bucket_rate_limiting_w3c_traceparent_and_prometheus_metrics() {
    let upstream_addr = spawn_echo_trace_upstream().await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
replay_buffer_size = 16

[[workloads]]
workload_id = "agent-m4"
org_id = "org-alpha"
token = "tok-m4"
roles = ["api:read"]

[[pools]]
name = "m4-pool"
strategy = "round_robin"
allow_private_ip = true
backends = [
  {{ id = "up-1", address = "{upstream_addr}" }},
]

[[routes]]
id = "traced-api"
path_prefix = "/v1/api"
strip_prefix = true
pool = "m4-pool"

[[policies]]
org_id = "org-alpha"
workload_id = "agent-m4"
required_roles = ["api:read"]
route_id = "traced-api"
methods = ["GET"]
path_prefix = "/v1/api"
rate_limit_rps = 1
rate_limit_burst = 2
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

    // 1. First request (within burst = 2) with explicit valid W3C traceparent is preserved and echoed.
    let explicit_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let explicit_tp = format!("00-{explicit_trace_id}-00f067aa0ba902b7-01");
    let req1 = Request::builder()
        .method("GET")
        .uri("/v1/api/ok")
        .header("x-edgegate-token", "tok-m4")
        .header("traceparent", &explicit_tp)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req1: {e}"));
    let (status1, headers1, body1) = send_req(gw_addr, req1).await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(
        headers1
            .get("x-edgegate-trace-id")
            .and_then(|v| v.to_str().ok()),
        Some(explicit_trace_id)
    );
    assert!(
        body1.contains(&format!("upstream_tp={explicit_tp}")),
        "unexpected body1: {body1}"
    );

    // 2. Second request (consumes 2nd burst token) without traceparent generates valid W3C traceparent
    //    and records trace_id in /_edgegate/replay on upstream 500.
    let req2 = Request::builder()
        .method("GET")
        .uri("/v1/api/fail500")
        .header("x-edgegate-token", "tok-m4")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req2: {e}"));
    let (status2, headers2, body2) = send_req(gw_addr, req2).await;
    assert_eq!(status2, StatusCode::INTERNAL_SERVER_ERROR);
    let gen_trace_id = headers2
        .get("x-edgegate-trace-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| panic!("missing x-edgegate-trace-id header"))
        .to_string();
    assert_eq!(gen_trace_id.len(), 32);
    assert!(
        body2.contains(&format!("upstream_tp=00-{gen_trace_id}-")),
        "expected generated W3C traceparent in upstream body, got: {body2}"
    );

    // 3. Third immediate request exceeds burst = 2 -> 429 Too Many Requests with retry-after: 1.
    let req3 = Request::builder()
        .method("GET")
        .uri("/v1/api/ok")
        .header("x-edgegate-token", "tok-m4")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req3: {e}"));
    let (status3, headers3, body3) = send_req(gw_addr, req3).await;
    assert_eq!(status3, StatusCode::TOO_MANY_REQUESTS, "body3: {body3}");
    assert_eq!(
        headers3.get(RETRY_AFTER).and_then(|v| v.to_str().ok()),
        Some("1")
    );
    assert!(headers3.get("x-edgegate-trace-id").is_some());

    // 4. Verify /_edgegate/replay includes trace_id for recorded events.
    let replay_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/replay")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("replay_req: {e}"));
    let (r_status, _, r_body) = send_req(gw_addr, replay_req).await;
    assert_eq!(r_status, StatusCode::OK);
    assert!(
        r_body.contains(&format!("\"trace_id\":\"{gen_trace_id}\"")),
        "replay body missing trace_id: {r_body}"
    );

    // 5. Verify GET /_edgegate/metrics?format=prometheus and Accept: text/plain return Prometheus metrics.
    let prom_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics?format=prometheus")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("prom_req: {e}"));
    let (p_status, p_headers, p_body) = send_req(gw_addr, prom_req).await;
    assert_eq!(p_status, StatusCode::OK);
    assert!(p_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/plain")));
    assert!(p_body.contains("# TYPE edgegate_requests_rate_limited_total counter"));
    assert!(p_body.contains("edgegate_requests_rate_limited_total 1"));
    assert!(p_body.contains("edgegate_requests_allowed_total 2"));
    assert!(p_body.contains("edgegate_config_generation 1"));

    let accept_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics")
        .header(ACCEPT, "text/plain")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("accept_req: {e}"));
    let (a_status, _, a_body) = send_req(gw_addr, accept_req).await;
    assert_eq!(a_status, StatusCode::OK);
    assert!(a_body.contains("edgegate_requests_rate_limited_total 1"));
}
