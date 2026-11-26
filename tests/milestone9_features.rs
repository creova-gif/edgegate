use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::header::{HeaderValue, RETRY_AFTER};
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http1 as client_http1;
use hyper::client::conn::http2 as client_http2;
use hyper::server::conn::http1 as server_http1;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::Notify;

struct ChannelBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, Infallible>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
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
async fn per_workload_bulkhead_concurrency_quota_isolates_noisy_neighbor() {
    let slow_entered = Arc::new(Notify::new());
    let slow_release = Arc::new(Notify::new());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind up: {e}"));
    let up_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("up addr: {e}"));

    let slow_entered_clone = Arc::clone(&slow_entered);
    let slow_release_clone = Arc::clone(&slow_release);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let slow_entered = Arc::clone(&slow_entered_clone);
            let slow_release = Arc::clone(&slow_release_clone);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let slow_entered = Arc::clone(&slow_entered);
                    let slow_release = Arc::clone(&slow_release);
                    async move {
                        if req.uri().path() == "/slow" {
                            slow_entered.notify_waiters();
                            slow_release.notified().await;
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                b"slow-done",
                            ))))
                        } else {
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                b"fast-done",
                            ))))
                        }
                    }
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "noisy-agent"
org_id = "org-alpha"
token = "tok-noisy"
max_concurrent_requests = 1

[[workloads]]
workload_id = "vip-agent"
org_id = "org-alpha"
token = "tok-vip"
max_concurrent_requests = 4

[[pools]]
name = "api-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr}" }}
]

[[routes]]
id = "api-route"
path_prefix = "/v1/api"
strip_prefix = true
pool = "api-pool"

[[policies]]
org_id = "org-alpha"
route_id = "api-route"
methods = ["GET"]
path_prefix = "/v1/api"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    let gw_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind gw: {e}"));
    let gw_addr = gw_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("gw addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = runner.serve(gw_listener, rx).await;
    });

    // 1. Dispatch 1st request from noisy-agent to /v1/api/slow
    let slow_client_handle = tokio::spawn(async move {
        let req = Request::builder()
            .method("GET")
            .uri("/v1/api/slow")
            .header("host", "edgegate.local")
            .header("x-edgegate-token", "tok-noisy")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|e| panic!("req: {e}"));
        send_http1(gw_addr, req).await
    });

    // Wait until upstream receives it so it is in-flight
    slow_entered.notified().await;

    // 2. While 1st request is in-flight, send 2nd request from noisy-agent -> assert 429 Too Many Requests
    let noisy_req2 = Request::builder()
        .method("GET")
        .uri("/v1/api/slow")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-noisy")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (status2, headers2, _) = send_http1(gw_addr, noisy_req2).await;
    assert_eq!(status2, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        headers2.get(RETRY_AFTER),
        Some(&HeaderValue::from_static("1"))
    );
    assert_eq!(proxy.telemetry().snapshot().bulkhead_rejected_total, 1);

    // 3. While noisy-agent is still holding its 1 slot, send request from vip-agent to /v1/api/fast -> assert 200 OK
    let vip_req = Request::builder()
        .method("GET")
        .uri("/v1/api/fast")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-vip")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (vip_status, _, vip_body) = send_http1(gw_addr, vip_req).await;
    assert_eq!(vip_status, StatusCode::OK);
    assert_eq!(vip_body, "fast-done");

    // 4. Release barrier so noisy-agent's 1st request completes 200 OK
    slow_release.notify_waiters();
    let (slow_status, _, slow_body) = slow_client_handle.await.unwrap();
    assert_eq!(slow_status, StatusCode::OK);
    assert_eq!(slow_body, "slow-done");

    // 5. Subsequent noisy-agent request succeeds 200 OK
    let noisy_req3 = Request::builder()
        .method("GET")
        .uri("/v1/api/fast")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-noisy")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (status3, _, body3) = send_http1(gw_addr, noisy_req3).await;
    assert_eq!(status3, StatusCode::OK);
    assert_eq!(body3, "fast-done");
}

#[tokio::test]
async fn jsonrpc_mcp_method_allowlist_enforces_single_and_batch_tool_governance() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind up: {e}"));
    let up_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("up addr: {e}"));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"{\"jsonrpc\":\"2.0\",\"result\":\"ok\"}",
                    ))))
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "mcp-agent"
org_id = "org-alpha"
token = "tok-mcp"

[[pools]]
name = "mcp-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr}" }}
]

[[routes]]
id = "mcp-route"
path_prefix = "/v1/mcp"
strip_prefix = true
pool = "mcp-pool"

[[policies]]
org_id = "org-alpha"
route_id = "mcp-route"
methods = ["POST"]
path_prefix = "/v1/mcp"
allowed_jsonrpc_methods = ["tools/list", "resources/read"]
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    let gw_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind gw: {e}"));
    let gw_addr = gw_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("gw addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = runner.serve(gw_listener, rx).await;
    });

    // 1. Single allowed call -> 200 OK
    let req1 = Request::builder()
        .method("POST")
        .uri("/v1/mcp/rpc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mcp")
        .body(Full::new(Bytes::from_static(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
        )))
        .unwrap();
    let (s1, _, _) = send_http1(gw_addr, req1).await;
    assert_eq!(s1, StatusCode::OK);

    // 2. Batch allowed call -> 200 OK
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/mcp/rpc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mcp")
        .body(Full::new(Bytes::from_static(
            b"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"},{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\"}]",
        )))
        .unwrap();
    let (s2, _, _) = send_http1(gw_addr, req2).await;
    assert_eq!(s2, StatusCode::OK);

    // 3. Single unauthorized method -> 403 Forbidden
    let req3 = Request::builder()
        .method("POST")
        .uri("/v1/mcp/rpc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mcp")
        .body(Full::new(Bytes::from_static(
            b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"rm_rf\"}}",
        )))
        .unwrap();
    let (s3, _, _) = send_http1(gw_addr, req3).await;
    assert_eq!(s3, StatusCode::FORBIDDEN);

    // 4. Batch smuggling (1 allowed + 1 forbidden) -> 403 Forbidden
    let req4 = Request::builder()
        .method("POST")
        .uri("/v1/mcp/rpc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mcp")
        .body(Full::new(Bytes::from_static(
            b"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"},{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"admin/shutdown\"}]",
        )))
        .unwrap();
    let (s4, _, _) = send_http1(gw_addr, req4).await;
    assert_eq!(s4, StatusCode::FORBIDDEN);

    // 5. Malformed / non-JSON body -> 403 Forbidden
    let req5 = Request::builder()
        .method("POST")
        .uri("/v1/mcp/rpc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mcp")
        .body(Full::new(Bytes::from_static(b"not-json")))
        .unwrap();
    let (s5, _, _) = send_http1(gw_addr, req5).await;
    assert_eq!(s5, StatusCode::FORBIDDEN);

    // Verify proxy telemetry and replay
    assert_eq!(proxy.telemetry().snapshot().jsonrpc_blocked_total, 3);

    let replay_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/replay")
        .header("host", "edgegate.local")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (rep_status, _, rep_body) = send_http1(gw_addr, replay_req).await;
    assert_eq!(rep_status, StatusCode::OK);
    assert!(rep_body.contains("\"reason\":\"jsonrpc_method_blocked\""));
}

#[tokio::test]
async fn per_route_timeout_override_and_max_response_body_bytes_guard() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind up: {e}"));
    let up_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("up addr: {e}"));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    if req.uri().path().ends_with("/slow-op") {
                        tokio::time::sleep(Duration::from_millis(150)).await;
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"done"))))
                    } else if req.uri().path().ends_with("/giant-body") {
                        let giant = vec![b'A'; 128];
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(giant))))
                    } else {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"12345678",
                        ))))
                    }
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
response_timeout_ms = 5000

[[workloads]]
workload_id = "sla-agent"
org_id = "org-alpha"
token = "tok-sla"

[[pools]]
name = "sla-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr}" }}
]

[[routes]]
id = "fast-sla"
path_prefix = "/v1/fast"
strip_prefix = true
pool = "sla-pool"
timeout_ms = 50

[[routes]]
id = "long-sla"
path_prefix = "/v1/long"
strip_prefix = true
pool = "sla-pool"
timeout_ms = 2000

[[routes]]
id = "capped-resp"
path_prefix = "/v1/capped"
strip_prefix = true
pool = "sla-pool"
max_response_body_bytes = 32

[[policies]]
org_id = "org-alpha"
route_id = "fast-sla"
methods = ["GET"]
path_prefix = "/v1/fast"

[[policies]]
org_id = "org-alpha"
route_id = "long-sla"
methods = ["GET"]
path_prefix = "/v1/long"

[[policies]]
org_id = "org-alpha"
route_id = "capped-resp"
methods = ["GET"]
path_prefix = "/v1/capped"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    let gw_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind gw: {e}"));
    let gw_addr = gw_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("gw addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = runner.serve(gw_listener, rx).await;
    });

    // 1. Route fast-sla (timeout_ms = 50) -> hitting /v1/fast/slow-op returns 504 Gateway Timeout
    let req1 = Request::builder()
        .method("GET")
        .uri("/v1/fast/slow-op")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-sla")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s1, _, _) = send_http1(gw_addr, req1).await;
    assert_eq!(s1, StatusCode::GATEWAY_TIMEOUT);

    // 2. Route long-sla (timeout_ms = 2000) -> hitting /v1/long/slow-op returns 200 OK
    let req2 = Request::builder()
        .method("GET")
        .uri("/v1/long/slow-op")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-sla")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s2, _, body2) = send_http1(gw_addr, req2).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(body2, "done");

    // 3. Route capped-resp (max_response_body_bytes = 32) -> hitting /v1/capped/giant-body returns 502 Bad Gateway
    let req3 = Request::builder()
        .method("GET")
        .uri("/v1/capped/giant-body")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-sla")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s3, _, _) = send_http1(gw_addr, req3).await;
    assert_eq!(s3, StatusCode::BAD_GATEWAY);

    // Small 8-byte response on capped-resp returns 200 OK
    let req4 = Request::builder()
        .method("GET")
        .uri("/v1/capped/small")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-sla")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s4, _, body4) = send_http1(gw_addr, req4).await;
    assert_eq!(s4, StatusCode::OK);
    assert_eq!(body4, "12345678");
}

#[tokio::test]
async fn http2_response_trailer_stripping_and_cli_audit_verification() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind h2 up: {e}"));
    let up_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("up addr: {e}"));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    let (tx, rx) =
                        tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(2);
                    tokio::spawn(async move {
                        let _ = tx
                            .send(Ok(Frame::data(Bytes::from_static(b"h2-payload"))))
                            .await;
                        let mut trailers = HeaderMap::new();
                        trailers.insert(
                            "x-internal-trailer",
                            HeaderValue::from_static("secret-trailer"),
                        );
                        trailers.insert("x-safe-trailer", HeaderValue::from_static("ok-trailer"));
                        let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    });

                    let body: BoxBody<Bytes, Infallible> = BoxBody::new(ChannelBody { rx });

                    Ok::<_, Infallible>(Response::new(body))
                });
                let _ = server_http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
admin_token = "adm-m9"

[[workloads]]
workload_id = "h2-agent"
org_id = "org-alpha"
token = "tok-h2"

[[pools]]
name = "h2-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr}", http2 = true }}
]

[[routes]]
id = "h2-route"
path_prefix = "/v1/h2"
strip_prefix = true
pool = "h2-pool"
strip_response_headers = ["x-internal-trailer"]

[[policies]]
org_id = "org-alpha"
route_id = "h2-route"
methods = ["GET"]
path_prefix = "/v1/h2"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    let gw_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind gw: {e}"));
    let gw_addr = gw_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("gw addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = runner.serve(gw_listener, rx).await;
    });

    // Send HTTP/2 prior-knowledge request to EdgeGate
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

    let h2_req = Request::builder()
        .method("GET")
        .uri("/v1/h2/data")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-h2")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = h2_sender.send_request(h2_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let collected = resp.into_body().collect().await.unwrap();
    let trailers = collected
        .trailers()
        .cloned()
        .expect("trailers must be present");
    let body_bytes = collected.to_bytes();
    assert_eq!(body_bytes, Bytes::from_static(b"h2-payload"));
    assert!(
        trailers.get("x-internal-trailer").is_none(),
        "x-internal-trailer must be stripped"
    );
    assert_eq!(
        trailers.get("x-safe-trailer").and_then(|v| v.to_str().ok()),
        Some("ok-trailer"),
        "x-safe-trailer must be preserved"
    );

    // Fetch GET /_edgegate/admin/audit with X-EdgeGate-Admin-Token: adm-m9
    let audit_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/admin/audit")
        .header("host", "edgegate.local")
        .header("x-edgegate-admin-token", "adm-m9")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (audit_status, _, audit_body) = send_http1(gw_addr, audit_req).await;
    assert_eq!(audit_status, StatusCode::OK);

    // Verify audit JSON
    let count = edgegate::telemetry::verify_audit_json(&audit_body).expect("valid audit JSON");
    assert!(count >= 1);

    // Tampering test: status: 200 -> status: 201
    assert!(audit_body.contains("\"status\":200"));
    let tampered_body = audit_body.replacen("\"status\":200", "\"status\":201", 1);
    assert!(edgegate::telemetry::verify_audit_json(&tampered_body).is_err());
}
