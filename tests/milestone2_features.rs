use std::convert::Infallible;
use std::io::Cursor;
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
use rustls::ServerConfig as RustlsServerConfig;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio_rustls::TlsAcceptor;

async fn spawn_https_upstream(cert_pem: &str, key_pem: &str) -> SocketAddr {
    let mut cert_reader = Cursor::new(cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .map(|r| r.unwrap_or_else(|e| panic!("cert: {e}")))
        .collect();
    let mut key_reader = Cursor::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .unwrap_or_else(|e| panic!("key: {e}"))
        .unwrap_or_else(|| panic!("missing private key"));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls_cfg = RustlsServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("proto: {e}"))
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap_or_else(|e| panic!("single_cert: {e}"));
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind https: {e}"));
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
                    let auth = req
                        .headers()
                        .get(AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("NONE")
                        .to_string();
                    let body = format!("tls=true;path={};auth={auth}", req.uri().path());
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    addr
}

async fn send_tcp(addr: SocketAddr, req: Request<Full<Bytes>>) -> (StatusCode, String) {
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
        .unwrap_or_else(|e| panic!("send: {e}"));
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"))
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn outbound_tls_verifies_certificate_and_sni_and_injects_secret() {
    let certified = rcgen::generate_simple_self_signed(vec!["api.internal".to_string()])
        .unwrap_or_else(|e| panic!("rcgen: {e}"));
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();

    let https_addr = spawn_https_upstream(&cert_pem, &key_pem).await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "agent-tls"
org_id = "org-alpha"
token = "tok-tls"
roles = ["api:call"]

[[pools]]
name = "https-valid"
allow_private_ip = true
ca_cert_pem = '''
{cert_pem}'''
backends = [
  {{ id = "tls-1", address = "{https_addr}", tls = true, tls_sni = "api.internal" }},
]

[[pools]]
name = "https-bad-sni"
allow_private_ip = true
ca_cert_pem = '''
{cert_pem}'''
backends = [
  {{ id = "tls-bad", address = "{https_addr}", tls = true, tls_sni = "wrong.internal" }},
]

[[routes]]
id = "secure-api"
path_prefix = "/v1/secure"
strip_prefix = true
pool = "https-valid"
[routes.credential]
credential_ref = "tls_secret"
header_name = "Authorization"
value_prefix = "Bearer "

[[routes]]
id = "bad-sni-api"
path_prefix = "/v1/bad-sni"
strip_prefix = true
pool = "https-bad-sni"

[[policies]]
org_id = "org-alpha"
required_roles = ["api:call"]
route_id = "secure-api"
methods = ["GET"]
path_prefix = "/v1/secure"

[[policies]]
org_id = "org-alpha"
required_roles = ["api:call"]
route_id = "bad-sni-api"
methods = ["GET"]
path_prefix = "/v1/bad-sni"

[[secrets]]
org_id = "org-alpha"
credential_ref = "tls_secret"
value = "tls_injected_token_777"
"#
    );

    let compiled = CompiledConfig::from_toml_str(&toml_cfg)
        .unwrap_or_else(|e| panic!("compile tls config: {e}"));
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

    // 1. Valid SNI + custom CA succeeds over TLS and injects secret.
    let ok_req = Request::builder()
        .method("GET")
        .uri("/v1/secure/models")
        .header("x-edgegate-token", "tok-tls")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (status, body) = send_tcp(gw_addr, ok_req).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("tls=true;path=/models;auth=Bearer tls_injected_token_777"));

    // 2. Mismatched SNI fails certificate verification -> 502 Bad Gateway.
    let bad_sni_req = Request::builder()
        .method("GET")
        .uri("/v1/bad-sni/models")
        .header("x-edgegate-token", "tok-tls")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (status, _) = send_tcp(gw_addr, bad_sni_req).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn zero_token_unix_domain_socket_and_atomic_hot_reload() {
    let certified = rcgen::generate_simple_self_signed(vec!["api.internal".to_string()])
        .unwrap_or_else(|e| panic!("rcgen: {e}"));
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let https_addr = spawn_https_upstream(&cert_pem, &key_pem).await;

    let uds_path = std::env::temp_dir().join(format!("edgegate-m2-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&uds_path);

    std::env::set_var("EDGEGATE_M2_ENV_SECRET", "env_secret_v1");

    let gen1_toml = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[server.unix_listeners]]
path = "{}"
workload_id = "boxlet-sandbox-1"
org_id = "org-alpha"
roles = ["repo:read"]

[[workloads]]
workload_id = "tcp-agent"
org_id = "org-alpha"
token = "tok-v1"
roles = ["repo:read"]

[[pools]]
name = "https-pool"
allow_private_ip = true
ca_cert_pem = '''
{cert_pem}'''
backends = [
  {{ id = "tls-1", address = "{https_addr}", tls = true, tls_sni = "api.internal" }},
]

[[routes]]
id = "github"
path_prefix = "/v1/github"
strip_prefix = true
pool = "https-pool"
[routes.credential]
credential_ref = "gh_secret"
header_name = "Authorization"
value_prefix = "Bearer "

[[policies]]
org_id = "org-alpha"
required_roles = ["repo:read"]
route_id = "github"
methods = ["GET"]
path_prefix = "/v1/github/repos"

[[secrets]]
org_id = "org-alpha"
credential_ref = "gh_secret"
env = "EDGEGATE_M2_ENV_SECRET"
"#,
        uds_path.display()
    );

    let compiled =
        CompiledConfig::from_toml_str(&gen1_toml).unwrap_or_else(|e| panic!("compile gen1: {e}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let gw_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let _uds_handles = proxy
        .spawn_unix_listeners()
        .unwrap_or_else(|e| panic!("spawn uds: {e}"));
    let proxy_runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = proxy_runner.serve(listener, rx).await;
    });

    // 1. Connect via Unix Domain Socket with ZERO X-EdgeGate-Token header!
    let uds_stream = UnixStream::connect(&uds_path)
        .await
        .unwrap_or_else(|e| panic!("connect uds: {e}"));
    let io = TokioIo::new(uds_stream);
    let (mut uds_sender, uds_conn) = client_http1::handshake(io)
        .await
        .unwrap_or_else(|e| panic!("uds handshake: {e}"));
    tokio::spawn(async move {
        let _ = uds_conn.await;
    });

    let zero_token_req = Request::builder()
        .method("GET")
        .uri("/v1/github/repos/boxlet")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("uds req: {e}"));
    let resp = uds_sender
        .send_request(zero_token_req)
        .await
        .unwrap_or_else(|e| panic!("uds send: {e}"));
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"))
        .to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(body_str.contains("auth=Bearer env_secret_v1"));

    // 2. Invalid reload fails safe without breaking active generation 1 snapshot.
    assert!(proxy.reload_from_toml_str("invalid = [toml").is_err());
    assert_eq!(proxy.telemetry().snapshot().config_generation, 1);
    assert_eq!(proxy.telemetry().snapshot().reload_failures_total, 1);

    // 3. Valid atomic hot reload rotates secret to v2 and increments generation to 2.
    let gen2_toml = gen1_toml.replace(
        "env = \"EDGEGATE_M2_ENV_SECRET\"",
        "value = \"rotated_secret_v2\"",
    );
    let gen = proxy
        .reload_from_toml_str(&gen2_toml)
        .unwrap_or_else(|e| panic!("valid reload: {e}"));
    assert_eq!(gen, 2);

    let after_reload_req = Request::builder()
        .method("GET")
        .uri("/v1/github/repos/boxlet")
        .header("x-edgegate-token", "tok-v1")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (status, body) = send_tcp(gw_addr, after_reload_req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("auth=Bearer rotated_secret_v2"));

    // 4. Verify /_edgegate/healthz and /_edgegate/metrics endpoints.
    let health_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/healthz")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (h_status, h_body) = send_tcp(gw_addr, health_req).await;
    assert_eq!(h_status, StatusCode::OK);
    assert!(h_body.contains("\"config_generation\":2"));

    let metrics_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("req: {e}"));
    let (m_status, m_body) = send_tcp(gw_addr, metrics_req).await;
    assert_eq!(m_status, StatusCode::OK);
    assert!(m_body.contains("\"reloads_total\":1"));
    assert!(m_body.contains("\"reload_failures_total\":1"));

    let _ = std::fs::remove_file(&uds_path);
}
