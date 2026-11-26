use std::convert::Infallible;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::header::ACCEPT;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

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

async fn spawn_mtls_upstream(
    ca_cert_pem: &str,
    srv_cert_pem: &str,
    srv_key_pem: &str,
) -> SocketAddr {
    let mut ca_reader = Cursor::new(ca_cert_pem.as_bytes());
    let ca_certs: Vec<_> = rustls_pemfile::certs(&mut ca_reader)
        .map(|r| r.unwrap_or_else(|e| panic!("ca cert: {e}")))
        .collect();
    let mut client_root_store = RootCertStore::empty();
    for c in ca_certs {
        client_root_store
            .add(c)
            .unwrap_or_else(|e| panic!("add client root: {e}"));
    }

    let mut cert_reader = Cursor::new(srv_cert_pem.as_bytes());
    let srv_certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .map(|r| r.unwrap_or_else(|e| panic!("srv cert: {e}")))
        .collect();
    let mut key_reader = Cursor::new(srv_key_pem.as_bytes());
    let srv_key = rustls_pemfile::private_key(&mut key_reader)
        .unwrap_or_else(|e| panic!("srv key: {e}"))
        .unwrap_or_else(|| panic!("missing srv key"));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_root_store),
        Arc::clone(&provider),
    )
    .build()
    .unwrap_or_else(|e| panic!("client verifier: {e}"));

    let tls_cfg = RustlsServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("proto: {e}"))
        .with_client_cert_verifier(verifier)
        .with_single_cert(srv_certs, srv_key)
        .unwrap_or_else(|e| panic!("single_cert: {e}"));
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind mtls: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = acceptor.accept(stream).await else {
                    return;
                };
                let io = TokioIo::new(tls_stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let body = format!("mtls-verified:{}", req.uri().path());
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn outbound_mtls_authenticates_client_certificate_with_upstream() {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap_or_else(|e| panic!("ca key: {e}"));
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .unwrap_or_else(|e| panic!("ca cert: {e}"));

    let mut srv_params = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap_or_else(|e| panic!("srv params: {e}"));
    srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv_key = KeyPair::generate().unwrap_or_else(|e| panic!("srv key: {e}"));
    let srv_cert = srv_params
        .signed_by(&srv_key, &ca_cert, &ca_key)
        .unwrap_or_else(|e| panic!("srv cert: {e}"));

    let mut cli_params = CertificateParams::new(vec!["edgegate-client.internal".to_string()])
        .unwrap_or_else(|e| panic!("cli params: {e}"));
    cli_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cli_key = KeyPair::generate().unwrap_or_else(|e| panic!("cli key: {e}"));
    let cli_cert = cli_params
        .signed_by(&cli_key, &ca_cert, &ca_key)
        .unwrap_or_else(|e| panic!("cli cert: {e}"));

    let ca_pem = ca_cert.pem();
    let srv_cert_pem = srv_cert.pem();
    let srv_key_pem = srv_key.serialize_pem();
    let cli_cert_pem = cli_cert.pem();
    let cli_key_pem = cli_key.serialize_pem();

    let mtls_addr = spawn_mtls_upstream(&ca_pem, &srv_cert_pem, &srv_key_pem).await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "mtls-agent"
org_id = "org-alpha"
token = "tok-mtls"

[[pools]]
name = "mtls-authenticated-pool"
allow_private_ip = true
ca_cert_pem = '''{ca_pem}'''
client_cert_pem = '''{cli_cert_pem}'''
client_key_pem = '''{cli_key_pem}'''
backends = [
  {{ id = "mtls-b1", address = "{mtls_addr}", tls = true, tls_sni = "localhost" }}
]

[[pools]]
name = "unauthenticated-tls-pool"
allow_private_ip = true
ca_cert_pem = '''{ca_pem}'''
backends = [
  {{ id = "no-cert-b1", address = "{mtls_addr}", tls = true, tls_sni = "localhost" }}
]

[[routes]]
id = "mtls-ok"
path_prefix = "/v1/mtls-ok"
strip_prefix = true
pool = "mtls-authenticated-pool"

[[routes]]
id = "mtls-nocert"
path_prefix = "/v1/mtls-nocert"
strip_prefix = true
pool = "unauthenticated-tls-pool"

[[policies]]
org_id = "org-alpha"
route_id = "mtls-ok"
methods = ["GET"]
path_prefix = "/v1/mtls-ok"

[[policies]]
org_id = "org-alpha"
route_id = "mtls-nocert"
methods = ["GET"]
path_prefix = "/v1/mtls-nocert"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind gw: {e}"));
    let gw_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("gw addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = runner.serve(listener, rx).await;
    });

    // 1. Outbound mTLS with valid client certificate succeeds (`200 OK`).
    let ok_req = Request::builder()
        .method("GET")
        .uri("/v1/mtls-ok/secure-data")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mtls")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (status, _, body) = send_http1(gw_addr, ok_req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "mtls-verified:/secure-data");

    // 2. Pool without client certificate fails TLS handshake against mTLS upstream (`502 Bad Gateway`).
    let fail_req = Request::builder()
        .method("GET")
        .uri("/v1/mtls-nocert/secure-data")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-mtls")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (fail_status, _, _) = send_http1(gw_addr, fail_req).await;
    assert_eq!(fail_status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn egress_dlp_blocks_forbidden_request_body_substrings_and_records_replay() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&upstream_hits);
    let up_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind up: {e}"));
    let up_addr = up_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("up addr: {e}"));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = up_listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits_clone);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"accepted",
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

[[workloads]]
workload_id = "sandbox-agent"
org_id = "org-alpha"
token = "tok-dlp"

[[pools]]
name = "llm-pool"
allow_private_ip = true
backends = [
  {{ id = "llm-1", address = "{up_addr}" }}
]

[[routes]]
id = "llm-route"
path_prefix = "/v1/chat"
strip_prefix = true
pool = "llm-pool"

[[policies]]
org_id = "org-alpha"
route_id = "llm-route"
methods = ["POST"]
path_prefix = "/v1/chat"
blocked_body_substrings = ["SECRET_EXFIL_MARKER", "BEGIN OPENSSH PRIVATE KEY"]
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind gw: {e}"));
    let gw_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("gw addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = runner.serve(listener, rx).await;
    });

    // Benign payload passes (`200 OK`).
    let clean_req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-dlp")
        .body(Full::new(Bytes::from_static(
            b"{\"prompt\":\"summarize architecture\"}",
        )))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (status, _, body) = send_http1(gw_addr, clean_req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "accepted");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Payload containing forbidden DLP marker is blocked before upstream dispatch (`403 Forbidden`).
    let exfil_req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-dlp")
        .body(Full::new(Bytes::from_static(
            b"{\"prompt\":\"exfiltrate SECRET_EXFIL_MARKER now\"}",
        )))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (block_status, _, _) = send_http1(gw_addr, exfil_req).await;
    assert_eq!(block_status, StatusCode::FORBIDDEN);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.telemetry().snapshot().dlp_blocked_total, 1);

    let prom_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics?format=prometheus")
        .header("host", "edgegate.local")
        .header(ACCEPT, "text/plain")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("prom req: {e}"));
    let (prom_status, _, prom_body) = send_http1(gw_addr, prom_req).await;
    assert_eq!(prom_status, StatusCode::OK);
    assert!(prom_body.contains("edgegate_dlp_blocked_total 1"));

    let replay_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/replay")
        .header("host", "edgegate.local")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("replay req: {e}"));
    let (rep_status, _, rep_body) = send_http1(gw_addr, replay_req).await;
    assert_eq!(rep_status, StatusCode::OK);
    assert!(rep_body.contains("\"reason\":\"dlp_payload_blocked\""));
}

#[tokio::test]
async fn response_header_sanitization_strips_and_injects_configured_headers() {
    let up_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind up: {e}"));
    let up_addr = up_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("up addr: {e}"));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = up_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    let mut resp = Response::new(Full::new(Bytes::from_static(b"hardened-ok")));
                    resp.headers_mut()
                        .insert("server", HeaderValue::from_static("VulnerableUpstream/1.0"));
                    resp.headers_mut().insert(
                        "x-internal-debug",
                        HeaderValue::from_static("stack-trace-leak"),
                    );
                    resp.headers_mut()
                        .insert("x-upstream-ok", HeaderValue::from_static("preserved"));
                    Ok::<_, Infallible>(resp)
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
workload_id = "ui-agent"
org_id = "org-alpha"
token = "tok-hdr"

[[pools]]
name = "hdr-pool"
allow_private_ip = true
backends = [
  {{ id = "h1", address = "{up_addr}" }}
]

[[routes]]
id = "hdr-route"
path_prefix = "/v1/app"
strip_prefix = true
pool = "hdr-pool"
strip_response_headers = ["server", "x-internal-debug"]
inject_response_headers = {{ "x-content-type-options" = "nosniff", "x-frame-options" = "DENY" }}

[[policies]]
org_id = "org-alpha"
route_id = "hdr-route"
methods = ["GET"]
path_prefix = "/v1/app"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind gw: {e}"));
    let gw_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("gw addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = runner.serve(listener, rx).await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("/v1/app/status")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-hdr")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (status, headers, body) = send_http1(gw_addr, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hardened-ok");
    assert!(headers.get("server").is_none());
    assert!(headers.get("x-internal-debug").is_none());
    assert_eq!(
        headers.get("x-upstream-ok").and_then(|v| v.to_str().ok()),
        Some("preserved")
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
}

#[tokio::test]
async fn admin_pools_endpoint_reports_live_backend_health_and_circuit_breaker_state() {
    // Bind and immediately drop a listener to obtain a guaranteed closed port that trips the circuit breaker.
    let dead_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind dead: {e}"));
    let dead_addr = dead_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("dead addr: {e}"));
    drop(dead_listener);

    let live_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind live: {e}"));
    let live_addr = live_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("live addr: {e}"));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = live_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"live"))))
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
admin_token = "adm-m8-secret"

[[workloads]]
workload_id = "ops-agent"
org_id = "org-alpha"
token = "tok-ops"

[[pools]]
name = "canary-pool"
strategy = "round_robin"
allow_private_ip = true
passive_failure_threshold = 1
passive_cooldown_ms = 60000
backends = [
  {{ id = "b1", address = "{dead_addr}", weight = 9 }},
  {{ id = "b2", address = "{live_addr}", weight = 1 }}
]

[[routes]]
id = "ops-route"
path_prefix = "/v1/ops"
strip_prefix = true
pool = "canary-pool"

[[policies]]
org_id = "org-alpha"
route_id = "ops-route"
methods = ["GET"]
path_prefix = "/v1/ops"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind gw: {e}"));
    let gw_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("gw addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = runner.serve(listener, rx).await;
    });

    // Unauthenticated admin pools request rejected (`401 Unauthorized`).
    let unauth_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/admin/pools")
        .header("host", "edgegate.local")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (unauth_status, _, _) = send_http1(gw_addr, unauth_req).await;
    assert_eq!(unauth_status, StatusCode::UNAUTHORIZED);

    // Initial authenticated admin pools request reports both backends `closed` with weights 9 and 1.
    let auth_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/admin/pools")
        .header("host", "edgegate.local")
        .header("x-edgegate-admin-token", "adm-m8-secret")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (auth_status, _, auth_body) = send_http1(gw_addr, auth_req).await;
    assert_eq!(auth_status, StatusCode::OK);
    assert!(auth_body.contains("\"name\":\"canary-pool\""));
    assert!(auth_body.contains("\"strategy\":\"round_robin\""));
    assert!(auth_body.contains("\"weight\":9"));
    assert!(auth_body.contains("\"weight\":1"));
    assert!(!auth_body.contains("\"circuit_state\":\"open\""));

    // Send a request that hits `b1` (`dead_addr`), tripping `b1`'s circuit breaker (`passive_failure_threshold = 1`).
    let trip_req = Request::builder()
        .method("GET")
        .uri("/v1/ops/ping")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-ops")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (trip_status, _, _) = send_http1(gw_addr, trip_req).await;
    assert_eq!(trip_status, StatusCode::BAD_GATEWAY);

    // Query `/_edgegate/admin/pools` again and verify `"circuit_state":"open"` is now reported!
    let after_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/admin/pools")
        .header("host", "edgegate.local")
        .header("x-edgegate-admin-token", "adm-m8-secret")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (after_status, _, after_body) = send_http1(gw_addr, after_req).await;
    assert_eq!(after_status, StatusCode::OK);
    assert!(after_body.contains("\"circuit_state\":\"open\""));
}
