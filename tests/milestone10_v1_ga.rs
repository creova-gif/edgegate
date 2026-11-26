use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::header::HeaderValue;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
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
async fn outbound_hmac_sha256_request_signing_injects_verified_signature_and_strips_forged_headers()
{
    #[derive(Default)]
    struct CapturedRequest {
        timestamp: String,
        signature: String,
        body: Bytes,
    }

    let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured);

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
            let captured = Arc::clone(&captured_clone);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let captured = Arc::clone(&captured);
                    async move {
                        let ts = req
                            .headers()
                            .get("x-edgegate-timestamp")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let sig = req
                            .headers()
                            .get("x-edgegate-signature-256")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let body_bytes = req
                            .into_body()
                            .collect()
                            .await
                            .unwrap_or_else(|e| panic!("collect upstream req body: {e}"))
                            .to_bytes();

                        *captured.lock().unwrap() = Some(CapturedRequest {
                            timestamp: ts,
                            signature: sig,
                            body: body_bytes,
                        });

                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
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
workload_id = "webhook-agent"
org_id = "org-alpha"
token = "tok-webhook"

[[pools]]
name = "webhook-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr}" }}
]

[[routes]]
id = "webhook-route"
path_prefix = "/v1/webhooks"
strip_prefix = true
pool = "webhook-pool"

[routes.request_signing]
credential_ref = "webhook_hmac_secret"
signature_header = "x-edgegate-signature-256"
timestamp_header = "x-edgegate-timestamp"

[[policies]]
org_id = "org-alpha"
route_id = "webhook-route"
methods = ["POST"]
path_prefix = "/v1/webhooks"

[[secrets]]
org_id = "org-alpha"
credential_ref = "webhook_hmac_secret"
value = "whsec_test_signing_key_v1"
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

    let req = Request::builder()
        .method("POST")
        .uri("/v1/webhooks/deliver")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-webhook")
        .header("x-edgegate-signature-256", "sha256=deadbeef")
        .header("x-edgegate-timestamp", "1")
        .body(Full::new(Bytes::from_static(
            b"{\"event\":\"agent.completed\"}",
        )))
        .unwrap();

    let (status, _, body) = send_http1(gw_addr, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    let data = captured
        .lock()
        .unwrap()
        .take()
        .expect("upstream must capture request");

    assert_ne!(
        data.timestamp, "1",
        "forged timestamp 1 must be replaced with fresh UNIX timestamp"
    );
    let ts: u64 = data
        .timestamp
        .parse()
        .expect("injected timestamp must parse as u64");

    let expected_hex = edgegate::config::hmac_sha256_hex(
        b"whsec_test_signing_key_v1",
        format!("{ts}.{{\"event\":\"agent.completed\"}}").as_bytes(),
    );
    let expected_sig = format!("sha256={expected_hex}");

    assert_eq!(data.signature, expected_sig);
    assert_eq!(
        data.body,
        Bytes::from_static(b"{\"event\":\"agent.completed\"}")
    );
    assert_eq!(proxy.telemetry().snapshot().signed_requests_total, 1);
}

#[tokio::test]
async fn streaming_response_holds_workload_bulkhead_until_eof_and_preserves_count_across_hot_reload(
) {
    let stream_release = Arc::new(Notify::new());
    let stream_release_clone = Arc::clone(&stream_release);
    let stream_count = Arc::new(AtomicUsize::new(0));
    let stream_count_clone = Arc::clone(&stream_count);

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
            let stream_release = Arc::clone(&stream_release_clone);
            let stream_count = Arc::clone(&stream_count_clone);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let stream_release = Arc::clone(&stream_release);
                    let stream_count = Arc::clone(&stream_count);
                    async move {
                        if req.uri().path().ends_with("/stream") {
                            let count = stream_count.fetch_add(1, Ordering::SeqCst);
                            if count == 0 {
                                let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(2);
                                tokio::spawn(async move {
                                    let _ = tx
                                        .send(Ok(Frame::data(Bytes::from_static(b"chunk-1"))))
                                        .await;
                                    stream_release.notified().await;
                                    let _ = tx
                                        .send(Ok(Frame::data(Bytes::from_static(b"chunk-2"))))
                                        .await;
                                });
                                let body: BoxBody<Bytes, Infallible> =
                                    BoxBody::new(ChannelBody { rx });
                                Ok::<_, Infallible>(Response::new(body))
                            } else {
                                Ok::<_, Infallible>(Response::new(BoxBody::new(
                                    Full::new(Bytes::from_static(b"stream-ok"))
                                        .map_err(|e| match e {}),
                                )))
                            }
                        } else {
                            Ok::<_, Infallible>(Response::new(BoxBody::new(
                                Full::new(Bytes::from_static(b"fast-ok")).map_err(|e| match e {}),
                            )))
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
workload_id = "stream-agent"
org_id = "org-alpha"
token = "tok-stream"
max_concurrent_requests = 1

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

    // Client 1 sends GET /v1/api/stream, awaits send_request so 200 OK headers return,
    // while holding open body stream without finishing
    let stream1 = TcpStream::connect(gw_addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let io1 = TokioIo::new(stream1);
    let (mut sender1, conn1) = client_http1::handshake(io1)
        .await
        .unwrap_or_else(|e| panic!("handshake: {e}"));
    tokio::spawn(async move {
        let _ = conn1.await;
    });

    let req1 = Request::builder()
        .method("GET")
        .uri("/v1/api/stream")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-stream")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp1 = sender1
        .send_request(req1)
        .await
        .unwrap_or_else(|e| panic!("send_request: {e}"));
    assert_eq!(resp1.status(), StatusCode::OK);

    // Client 2 sends request while Client 1's response body is still open -> 429 Too Many Requests
    let req2 = Request::builder()
        .method("GET")
        .uri("/v1/api/stream")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-stream")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status2, _, _) = send_http1(gw_addr, req2).await;
    assert_eq!(
        status2,
        StatusCode::TOO_MANY_REQUESTS,
        "bulkhead permit must be held across streaming response body lifetime"
    );

    // Trigger hot reload keeping max_concurrent_requests = 1
    let reload_res = proxy.reload_from_toml_str(&toml_cfg);
    assert!(reload_res.is_ok(), "hot reload must succeed");

    // Client 3 sends request after hot reload -> STILL 429 Too Many Requests
    let req3 = Request::builder()
        .method("GET")
        .uri("/v1/api/stream")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-stream")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status3, _, _) = send_http1(gw_addr, req3).await;
    assert_eq!(
        status3,
        StatusCode::TOO_MANY_REQUESTS,
        "hot reload must not lose active stream bulkhead count"
    );

    // Notify upstream to finish Client 1's stream and collect full body
    stream_release.notify_waiters();
    let body1 = resp1
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("collect client 1 body: {e}"))
        .to_bytes();
    assert_eq!(body1, Bytes::from_static(b"chunk-1chunk-2"));

    // Now send Client 4 request -> 200 OK
    let req4 = Request::builder()
        .method("GET")
        .uri("/v1/api/stream")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-stream")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status4, _, _) = send_http1(gw_addr, req4).await;
    assert_eq!(
        status4,
        StatusCode::OK,
        "subsequent request must succeed after stream finishes and permit is released"
    );
}

#[tokio::test]
async fn max_response_body_bytes_preserves_allowed_http2_trailers_and_does_not_trip_shared_circuit_breaker(
) {
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
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let path = req.uri().path();
                    if path.ends_with("/grpc-ok") {
                        let (tx, rx) =
                            tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(2);
                        tokio::spawn(async move {
                            let _ = tx
                                .send(Ok(Frame::data(Bytes::from_static(b"grpc-payload"))))
                                .await;
                            let mut trailers = HeaderMap::new();
                            trailers.insert("grpc-status", HeaderValue::from_static("0"));
                            trailers
                                .insert("x-internal-debug", HeaderValue::from_static("strip-me"));
                            let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                        });

                        let body: BoxBody<Bytes, Infallible> = BoxBody::new(ChannelBody { rx });
                        Ok::<_, Infallible>(Response::new(body))
                    } else if path.ends_with("/large") {
                        let large = vec![b'X'; 128];
                        Ok::<_, Infallible>(Response::new(BoxBody::new(
                            Full::new(Bytes::from(large)).map_err(|e| match e {}),
                        )))
                    } else {
                        Ok::<_, Infallible>(Response::new(BoxBody::new(
                            Full::new(Bytes::from_static(b"tiny")).map_err(|e| match e {}),
                        )))
                    }
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

[[workloads]]
workload_id = "h2-agent"
org_id = "org-alpha"
token = "tok-h2"

[[pools]]
name = "shared-pool"
allow_private_ip = true
passive_failure_threshold = 1
passive_cooldown_ms = 60000
backends = [
  {{ id = "b1", address = "{up_addr}", http2 = true }}
]

[[routes]]
id = "strict-route"
path_prefix = "/v1/strict"
strip_prefix = true
pool = "shared-pool"
max_response_body_bytes = 32
strip_response_headers = ["x-internal-debug"]

[[routes]]
id = "sibling-route"
path_prefix = "/v1/sibling"
strip_prefix = true
pool = "shared-pool"

[[policies]]
org_id = "org-alpha"
route_id = "strict-route"
methods = ["GET"]
path_prefix = "/v1/strict"

[[policies]]
org_id = "org-alpha"
route_id = "sibling-route"
methods = ["GET"]
path_prefix = "/v1/sibling"
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

    // Send HTTP/2 prior-knowledge connection to EdgeGate
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

    // (a) Call /v1/strict/grpc-ok over HTTP/2 -> assert 200 OK, body "grpc-payload",
    // trailer grpc-status == "0" is PRESERVED, and trailer x-internal-debug is STRIPPED!
    let h2_req = Request::builder()
        .method("GET")
        .uri("/v1/strict/grpc-ok")
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
    assert_eq!(body_bytes, Bytes::from_static(b"grpc-payload"));
    assert_eq!(
        trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("0"),
        "grpc-status trailer must be preserved"
    );
    assert!(
        trailers.get("x-internal-debug").is_none(),
        "x-internal-debug trailer must be stripped"
    );

    // (b) Call /v1/strict/large twice -> both return 502 Bad Gateway (exceeds 32-byte cap)
    for i in 1..=2 {
        let large_req = Request::builder()
            .method("GET")
            .uri("/v1/strict/large")
            .header("host", "edgegate.local")
            .header("x-edgegate-token", "tok-h2")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let large_resp = h2_sender.send_request(large_req).await.unwrap();
        assert_eq!(
            large_resp.status(),
            StatusCode::BAD_GATEWAY,
            "call {i} to capped route exceeding limit must return 502"
        );
    }

    // Immediately call /v1/sibling/small -> assert 200 OK "tiny"
    // (proving route-level response cap did NOT trip the shared pool circuit breaker even with passive_failure_threshold = 1!)
    let small_req = Request::builder()
        .method("GET")
        .uri("/v1/sibling/small")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-h2")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let small_resp = h2_sender.send_request(small_req).await.unwrap();
    assert_eq!(
        small_resp.status(),
        StatusCode::OK,
        "shared pool circuit breaker must not trip from route-level response body cap violations"
    );
    let small_body = small_resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(small_body, Bytes::from_static(b"tiny"));
}

#[tokio::test]
async fn jsonrpc_empty_allowlist_denies_all_and_requires_strict_2_0_envelope() {
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
                        b"{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}}",
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
id = "mcp-locked-route"
path_prefix = "/v1/mcp-locked"
strip_prefix = true
pool = "mcp-pool"

[[routes]]
id = "mcp-strict-route"
path_prefix = "/v1/mcp-strict"
strip_prefix = true
pool = "mcp-pool"

[[policies]]
org_id = "org-alpha"
route_id = "mcp-locked-route"
methods = ["POST"]
path_prefix = "/v1/mcp-locked"
allowed_jsonrpc_methods = []

[[policies]]
org_id = "org-alpha"
route_id = "mcp-strict-route"
methods = ["POST"]
path_prefix = "/v1/mcp-strict"
allowed_jsonrpc_methods = ["tools/list"]
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

    // 1. /v1/mcp-locked with allowed_jsonrpc_methods = [] denies any method
    let req1 = Request::builder()
        .method("POST")
        .uri("/v1/mcp-locked/rpc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mcp")
        .body(Full::new(Bytes::from_static(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
        )))
        .unwrap();
    let (s1, _, _) = send_http1(gw_addr, req1).await;
    assert_eq!(
        s1,
        StatusCode::FORBIDDEN,
        "empty allowed_jsonrpc_methods must deny all methods"
    );

    // 2. /v1/mcp-strict with allowed_jsonrpc_methods = ["tools/list"]
    // Missing "jsonrpc" field -> 403 Forbidden
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/mcp-strict/rpc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mcp")
        .body(Full::new(Bytes::from_static(
            b"{\"id\":1,\"method\":\"tools/list\"}",
        )))
        .unwrap();
    let (s2, _, _) = send_http1(gw_addr, req2).await;
    assert_eq!(
        s2,
        StatusCode::FORBIDDEN,
        "missing jsonrpc envelope field must be rejected with 403"
    );

    // 3. Wrong "jsonrpc" version ("1.0") -> 403 Forbidden
    let req3 = Request::builder()
        .method("POST")
        .uri("/v1/mcp-strict/rpc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mcp")
        .body(Full::new(Bytes::from_static(
            b"{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"tools/list\"}",
        )))
        .unwrap();
    let (s3, _, _) = send_http1(gw_addr, req3).await;
    assert_eq!(
        s3,
        StatusCode::FORBIDDEN,
        "non-2.0 jsonrpc envelope version must be rejected with 403"
    );

    // 4. Valid {"jsonrpc":"2.0","id":1,"method":"tools/list"} -> 200 OK
    let req4 = Request::builder()
        .method("POST")
        .uri("/v1/mcp-strict/rpc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mcp")
        .body(Full::new(Bytes::from_static(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
        )))
        .unwrap();
    let (s4, _, _) = send_http1(gw_addr, req4).await;
    assert_eq!(
        s4,
        StatusCode::OK,
        "valid jsonrpc 2.0 allowed method must succeed with 200 OK"
    );
}

#[test]
fn cli_audit_blocks_remote_cleartext_http_token_transmission() {
    let binary = env!("CARGO_BIN_EXE_edgegate");

    // edgegate audit --url http://example.com:8080 --admin-token secret123 -> non-zero exit status
    let output1 = std::process::Command::new(binary)
        .args([
            "audit",
            "--url",
            "http://example.com:8080",
            "--admin-token",
            "secret123",
        ])
        .output()
        .expect("failed to execute edgegate binary");
    assert!(
        !output1.status.success(),
        "edgegate audit must refuse remote cleartext HTTP without needing network/DNS"
    );

    // edgegate audit --url http://127.0.0.1:8080 --admin-token secret123 --ca-cert /tmp/nonexistent.pem -> non-zero exit status
    let output2 = std::process::Command::new(binary)
        .args([
            "audit",
            "--url",
            "http://127.0.0.1:8080",
            "--admin-token",
            "secret123",
            "--ca-cert",
            "/tmp/nonexistent.pem",
        ])
        .output()
        .expect("failed to execute edgegate binary");
    assert!(
        !output2.status.success(),
        "edgegate audit must reject --ca-cert when URL scheme is http"
    );
}
