use std::convert::Infallible;
use std::io::Cursor;
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
use hyper::server::conn::http1 as server_http1;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_mtls_listener_verifies_client_certs_and_cli_connects_with_mtls() {
    // 1. Generate ephemeral CA, server cert ("localhost"), and client cert
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap_or_else(|e| panic!("ca key: {e}"));
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .unwrap_or_else(|e| panic!("ca cert: {e}"));

    let mut srv_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap_or_else(|e| panic!("srv params: {e}"));
    srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv_key = KeyPair::generate().unwrap_or_else(|e| panic!("srv key: {e}"));
    let srv_cert = srv_params
        .signed_by(&srv_key, &ca_cert, &ca_key)
        .unwrap_or_else(|e| panic!("srv cert: {e}"));

    let mut cli_params = CertificateParams::new(vec!["client.internal".to_string()])
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

    // 2. Start mock upstream returning "inbound-mtls-ok"
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
                        b"inbound-mtls-ok",
                    ))))
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    // 3. Configure EdgeGate [server.tls] with cert_pem, key_pem, and client_ca_cert_pem (INV-24)
    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
admin_token = "adm-mtls-11"

[server.tls]
cert_pem = '''{srv_cert_pem}'''
key_pem = '''{srv_key_pem}'''
client_ca_cert_pem = '''{ca_pem}'''

[[workloads]]
workload_id = "mtls-workload"
org_id = "org-enterprise"
token = "tok-mtls-inbound"

[[pools]]
name = "mtls-upstream-pool"
allow_private_ip = true
backends = [
  {{ id = "up1", address = "{up_addr}" }}
]

[[routes]]
id = "mtls-inbound-route"
path_prefix = "/v1/inbound-mtls"
strip_prefix = true
pool = "mtls-upstream-pool"

[[policies]]
org_id = "org-enterprise"
route_id = "mtls-inbound-route"
methods = ["GET"]
path_prefix = "/v1/inbound-mtls"
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
    let gw_port = gw_addr.port();
    let proxy = Arc::new(EdgeGateProxy::new(compiled));
    let runner = Arc::clone(&proxy);
    let (_tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = runner.serve(gw_listener, rx).await;
    });

    let mut root_store = RootCertStore::empty();
    let mut ca_cursor = Cursor::new(ca_pem.as_bytes());
    let parsed_ca: Vec<_> = rustls_pemfile::certs(&mut ca_cursor)
        .map(|r| r.unwrap_or_else(|e| panic!("ca cert parse: {e}")))
        .collect();
    for c in parsed_ca {
        root_store
            .add(c)
            .unwrap_or_else(|e| panic!("add ca to root: {e}"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // 4. Verify that a TLS client WITHOUT a client certificate fails the TLS handshake or connection against EdgeGate!
    let no_client_auth_cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("proto: {e}"))
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();
    let no_cert_connector = TlsConnector::from(Arc::new(no_client_auth_cfg));

    let tcp_conn = TcpStream::connect(gw_addr)
        .await
        .unwrap_or_else(|e| panic!("connect gw without cert: {e}"));
    let sni = ServerName::try_from("localhost".to_string()).unwrap_or_else(|e| panic!("sni: {e}"));
    let tls_res = no_cert_connector.connect(sni.clone(), tcp_conn).await;
    if let Ok(tls_stream) = tls_res {
        let io = TokioIo::new(tls_stream);
        if let Ok((mut sender, conn)) = client_http1::handshake(io).await {
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = Request::builder()
                .method("GET")
                .uri("https://localhost/v1/inbound-mtls/test")
                .header("host", "localhost")
                .header("x-edgegate-token", "tok-mtls-inbound")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp_res = sender.send_request(req).await;
            assert!(
                resp_res.is_err(),
                "request from client without certificate must fail against mTLS listener"
            );
        }
    } else {
        assert!(
            tls_res.is_err(),
            "TLS handshake from client without certificate must fail against mTLS listener"
        );
    }

    // 5. Verify that a TLS client WITH the valid client certificate + X-EdgeGate-Token receives 200 OK "inbound-mtls-ok"
    let mut cli_cert_reader = Cursor::new(cli_cert_pem.as_bytes());
    let cli_certs: Vec<_> = rustls_pemfile::certs(&mut cli_cert_reader)
        .map(|r| r.unwrap_or_else(|e| panic!("cli cert parse: {e}")))
        .collect();
    let mut cli_key_reader = Cursor::new(cli_key_pem.as_bytes());
    let cli_key = rustls_pemfile::private_key(&mut cli_key_reader)
        .unwrap_or_else(|e| panic!("cli key parse: {e}"))
        .unwrap_or_else(|| panic!("missing cli private key"));

    let mut with_client_auth_cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("proto: {e}"))
        .with_root_certificates(root_store)
        .with_client_auth_cert(cli_certs, cli_key)
        .unwrap_or_else(|e| panic!("client auth cert cfg: {e}"));
    with_client_auth_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let with_cert_connector = TlsConnector::from(Arc::new(with_client_auth_cfg));

    let tcp_conn = TcpStream::connect(gw_addr)
        .await
        .unwrap_or_else(|e| panic!("connect gw with cert: {e}"));
    let tls_stream = with_cert_connector
        .connect(sni, tcp_conn)
        .await
        .unwrap_or_else(|e| panic!("tls connect with client cert: {e}"));
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = client_http1::handshake(io)
        .await
        .unwrap_or_else(|e| panic!("handshake: {e}"));
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("https://localhost/v1/inbound-mtls/test")
        .header("host", "localhost")
        .header("x-edgegate-token", "tok-mtls-inbound")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender
        .send_request(req)
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("collect body: {e}"))
        .to_bytes();
    assert_eq!(body, Bytes::from_static(b"inbound-mtls-ok"));

    // 6. Invoke CLI: status --url https://localhost:<port> --ca-cert <ca> --client-cert <cert> --client-key <key>
    let temp_dir = std::env::temp_dir();
    let ca_path = temp_dir.join(format!("edgegate_m11_ca_{gw_port}.pem"));
    let cert_path = temp_dir.join(format!("edgegate_m11_cli_{gw_port}.pem"));
    let key_path = temp_dir.join(format!("edgegate_m11_cli_{gw_port}.key"));

    std::fs::write(&ca_path, &ca_pem).unwrap();
    std::fs::write(&cert_path, &cli_cert_pem).unwrap();
    std::fs::write(&key_path, &cli_key_pem).unwrap();

    let cli_output = std::process::Command::new(env!("CARGO_BIN_EXE_edgegate"))
        .args([
            "status",
            "--url",
            &format!("https://127.0.0.1:{gw_port}"),
            "--ca-cert",
            ca_path.to_str().unwrap(),
            "--client-cert",
            cert_path.to_str().unwrap(),
            "--client-key",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("run edgegate status with mTLS");

    let _ = std::fs::remove_file(&ca_path);
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(
        cli_output.status.success(),
        "edgegate status CLI with client mTLS must succeed: stderr={}",
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&cli_output.stdout);
    assert!(
        stdout.contains("\"allowed_total\":1"),
        "status stdout must contain allowed_total:1, got: {stdout}"
    );
}

#[tokio::test]
async fn outbound_aws_sigv4_signs_canonical_requests_and_strips_forged_amz_headers() {
    #[derive(Default)]
    struct CapturedAwsRequest {
        authorization: String,
        amz_date: String,
        content_sha256: String,
        security_token: Option<String>,
        uri: String,
        body: Bytes,
    }

    let captured: Arc<Mutex<Option<CapturedAwsRequest>>> = Arc::new(Mutex::new(None));
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
                        let auth = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let date = req
                            .headers()
                            .get("x-amz-date")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let sha = req
                            .headers()
                            .get("x-amz-content-sha256")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let token = req
                            .headers()
                            .get("x-amz-security-token")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        let uri = req.uri().to_string();
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .unwrap_or_else(|e| panic!("collect req body: {e}"))
                            .to_bytes();

                        *captured.lock().unwrap() = Some(CapturedAwsRequest {
                            authorization: auth,
                            amz_date: date,
                            content_sha256: sha,
                            security_token: token,
                            uri,
                            body,
                        });

                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"aws-s3-ok",
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
workload_id = "s3-agent"
org_id = "org-aws"
token = "tok-s3"

[[pools]]
name = "s3-pool"
allow_private_ip = true
backends = [
  {{ id = "s3-b1", address = "{up_addr}" }}
]

[[routes]]
id = "s3-route"
path_prefix = "/v1/s3"
strip_prefix = true
pool = "s3-pool"

[routes.aws_sigv4]
access_key_ref = "aws_ak"
secret_key_ref = "aws_sk"
region = "us-east-1"
service = "s3"

[[policies]]
org_id = "org-aws"
route_id = "s3-route"
methods = ["PUT"]
path_prefix = "/v1/s3"

[[secrets]]
org_id = "org-aws"
credential_ref = "aws_ak"
value = "AKIAIOSFODNN7EXAMPLE"

[[secrets]]
org_id = "org-aws"
credential_ref = "aws_sk"
value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
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
        .method("PUT")
        .uri("/v1/s3/my-bucket/report.json?partNumber=1&uploadId=abc")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-s3")
        .header("Authorization", "AWS4-HMAC-SHA256 forged")
        .header("x-amz-date", "19990101T000000Z")
        .header("x-amz-security-token", "forged-sts")
        .body(Full::new(Bytes::from_static(b"{\"hello\":\"aws\"}")))
        .unwrap();

    let (status, _, body) = send_http1(gw_addr, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "aws-s3-ok");

    let cap = captured
        .lock()
        .unwrap()
        .take()
        .expect("must capture upstream request");
    assert!(
        cap.security_token.is_none(),
        "forged x-amz-security-token must be stripped"
    );
    assert_ne!(
        cap.amz_date, "19990101T000000Z",
        "forged x-amz-date must be replaced with fresh timestamp"
    );
    assert_eq!(cap.uri, "/my-bucket/report.json?partNumber=1&uploadId=abc");
    assert_eq!(cap.body, Bytes::from_static(b"{\"hello\":\"aws\"}"));

    let expected = edgegate::config::compute_aws_sigv4_headers(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "s3",
        "PUT",
        "/my-bucket/report.json",
        Some("partNumber=1&uploadId=abc"),
        &up_addr.to_string(),
        b"{\"hello\":\"aws\"}",
        &cap.amz_date,
        &cap.amz_date[..8],
    );

    assert_eq!(cap.authorization, expected.authorization);
    assert_eq!(cap.content_sha256, expected.content_sha256);
}

#[tokio::test]
async fn secret_reflection_guard_blocks_credentials_smuggled_in_http2_trailers() {
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
                            .send(Ok(Frame::data(Bytes::from_static(b"innocent-body"))))
                            .await;
                        let mut trailers = HeaderMap::new();
                        trailers.insert(
                            "x-smuggled-leak",
                            HeaderValue::from_static("Bearer super_secret_cred_v11"),
                        );
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

[[workloads]]
workload_id = "trailer-agent"
org_id = "org-leak"
token = "tok-trailer"

[[pools]]
name = "trailer-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr}", http2 = true }}
]

[[routes]]
id = "trailer-route"
path_prefix = "/v1/trailer"
strip_prefix = true
pool = "trailer-pool"

[routes.credential]
credential_ref = "cred11"
header_name = "Authorization"
value_prefix = "Bearer "
block_secret_reflection = true

[[policies]]
org_id = "org-leak"
route_id = "trailer-route"
methods = ["GET"]
path_prefix = "/v1/trailer"

[[secrets]]
org_id = "org-leak"
credential_ref = "cred11"
value = "super_secret_cred_v11"
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
        .method("GET")
        .uri("/v1/trailer/leak-check")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-trailer")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let (status, _, _) = send_http1(gw_addr, req).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "reflected credential in HTTP/2 trailers must be blocked with 502 Bad Gateway"
    );
    assert_eq!(
        proxy
            .telemetry()
            .snapshot()
            .secret_reflections_blocked_total,
        1,
        "secret_reflections_blocked_total must increment when secret is leaked in trailers"
    );
}

#[tokio::test]
async fn always_counted_bulkhead_across_hot_reload_and_oversized_5xx_trips_circuit_breaker() {
    // ----------------- PART A: Always-Counted Bulkhead Across Hot Reload -----------------
    let stream_release = Arc::new(Notify::new());
    let stream_release_clone = Arc::clone(&stream_release);

    let listener_a = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind up a: {e}"));
    let up_addr_a = listener_a
        .local_addr()
        .unwrap_or_else(|e| panic!("up addr a: {e}"));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener_a.accept().await else {
                break;
            };
            let stream_release = Arc::clone(&stream_release_clone);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let stream_release = Arc::clone(&stream_release);
                    async move {
                        if req.uri().path().ends_with("/stream") {
                            let (tx, rx) =
                                tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(2);
                            tokio::spawn(async move {
                                let _ = tx
                                    .send(Ok(Frame::data(Bytes::from_static(b"stream-data-1"))))
                                    .await;
                                stream_release.notified().await;
                                let _ = tx
                                    .send(Ok(Frame::data(Bytes::from_static(b"stream-data-2"))))
                                    .await;
                            });
                            let body: BoxBody<Bytes, Infallible> = BoxBody::new(ChannelBody { rx });
                            Ok::<_, Infallible>(Response::new(body))
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

    // Start workload dyn-agent with NO max_concurrent_requests initially
    let toml_initial = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "dyn-agent"
org_id = "org-dyn"
token = "tok-dyn"

[[pools]]
name = "dyn-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr_a}" }}
]

[[routes]]
id = "dyn-route"
path_prefix = "/v1/dyn"
strip_prefix = true
pool = "dyn-pool"

[[policies]]
org_id = "org-dyn"
route_id = "dyn-route"
methods = ["GET"]
path_prefix = "/v1/dyn"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_initial).unwrap_or_else(|e| panic!("compile: {e}"));
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

    // Client 1 opens a slow streaming request from dyn-agent and holds response body open
    let stream1 = TcpStream::connect(gw_addr)
        .await
        .unwrap_or_else(|e| panic!("connect gw 1: {e}"));
    let io1 = TokioIo::new(stream1);
    let (mut sender1, conn1) = client_http1::handshake(io1)
        .await
        .unwrap_or_else(|e| panic!("handshake 1: {e}"));
    tokio::spawn(async move {
        let _ = conn1.await;
    });

    let req1 = Request::builder()
        .method("GET")
        .uri("/v1/dyn/stream")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-dyn")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp1 = sender1
        .send_request(req1)
        .await
        .unwrap_or_else(|e| panic!("send_request 1: {e}"));
    assert_eq!(resp1.status(), StatusCode::OK);

    // While client 1 is open, hot-reload config enabling max_concurrent_requests = 1 on dyn-agent
    let toml_with_limit = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "dyn-agent"
org_id = "org-dyn"
token = "tok-dyn"
max_concurrent_requests = 1

[[pools]]
name = "dyn-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr_a}" }}
]

[[routes]]
id = "dyn-route"
path_prefix = "/v1/dyn"
strip_prefix = true
pool = "dyn-pool"

[[policies]]
org_id = "org-dyn"
route_id = "dyn-route"
methods = ["GET"]
path_prefix = "/v1/dyn"
"#
    );
    let reload_res = proxy.reload_from_toml_str(&toml_with_limit);
    assert!(reload_res.is_ok(), "hot reload must succeed");

    // Client 2 sends a concurrent request -> assert 429 Too Many Requests
    let req2 = Request::builder()
        .method("GET")
        .uri("/v1/dyn/stream")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-dyn")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status2, _, _) = send_http1(gw_addr, req2).await;
    assert_eq!(
        status2,
        StatusCode::TOO_MANY_REQUESTS,
        "pre-existing stream started before bulkhead limit must be counted after hot reload"
    );

    // Drop/finish 1st response stream
    stream_release.notify_waiters();
    let _ = resp1.into_body().collect().await;

    // Verify next request returns 200 OK
    let req3 = Request::builder()
        .method("GET")
        .uri("/v1/dyn/fast")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-dyn")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status3, _, body3) = send_http1(gw_addr, req3).await;
    assert_eq!(status3, StatusCode::OK);
    assert_eq!(body3, "fast-ok");

    // ----------------- PART B: Oversized 5xx Trips Circuit Breaker -----------------
    let listener_b = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind up b: {e}"));
    let up_addr_b = listener_b
        .local_addr()
        .unwrap_or_else(|e| panic!("up addr b: {e}"));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener_b.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    // Upstream returns 503 Service Unavailable with a 64-byte error body
                    let body_64 = vec![b'E'; 64];
                    let mut resp = Response::new(Full::new(Bytes::from(body_64)));
                    *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                    Ok::<_, Infallible>(resp)
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let toml_b = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
admin_token = "adm-breaker-11"

[[workloads]]
workload_id = "breaker-agent"
org_id = "org-breaker"
token = "tok-breaker"

[[pools]]
name = "breaker-pool"
allow_private_ip = true
passive_failure_threshold = 1
passive_cooldown_ms = 60000
backends = [
  {{ id = "b1", address = "{up_addr_b}" }}
]

[[routes]]
id = "breaker-route"
path_prefix = "/v1/breaker"
strip_prefix = true
pool = "breaker-pool"
max_response_body_bytes = 16

[[policies]]
org_id = "org-breaker"
route_id = "breaker-route"
methods = ["GET"]
path_prefix = "/v1/breaker"
"#
    );

    let reload_b = proxy.reload_from_toml_str(&toml_b);
    assert!(reload_b.is_ok(), "hot reload for breaker test must succeed");

    // Request through capped route with 503 + 64 bytes -> EdgeGate returns 502 Bad Gateway
    let req_b = Request::builder()
        .method("GET")
        .uri("/v1/breaker/fail")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-breaker")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status_b, _, _) = send_http1(gw_addr, req_b).await;
    assert_eq!(
        status_b,
        StatusCode::BAD_GATEWAY,
        "oversized 503 upstream body exceeding max_response_body_bytes must return 502"
    );

    // Verify backend circuit breaker tripped to "open"
    let admin_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/admin/pools")
        .header("host", "edgegate.local")
        .header("x-edgegate-admin-token", "adm-breaker-11")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (admin_status, _, admin_body) = send_http1(gw_addr, admin_req).await;
    assert_eq!(admin_status, StatusCode::OK);
    assert!(
        admin_body.contains("\"circuit_state\":\"open\""),
        "oversized 5xx must trip circuit breaker to open: {admin_body}"
    );
}

#[tokio::test]
async fn warm_connection_pool_reuses_keepalive_socket_across_atomic_hot_reload() {
    let accepted_tcp_connections = Arc::new(AtomicUsize::new(0));
    let accepted_clone = Arc::clone(&accepted_tcp_connections);

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
            accepted_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"keepalive-ok",
                    ))))
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let toml_initial = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "pool-agent"
org_id = "org-pool"
token = "tok-pool"

[[pools]]
name = "keepalive-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr}" }}
]

[[routes]]
id = "route-1"
path_prefix = "/v1/route1"
strip_prefix = true
pool = "keepalive-pool"

[[policies]]
org_id = "org-pool"
route_id = "route-1"
methods = ["GET"]
path_prefix = "/v1/route1"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_initial).unwrap_or_else(|e| panic!("compile: {e}"));
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

    // Send request 1 through EdgeGate -> 200 OK, accepted_tcp_connections == 1
    let req1 = Request::builder()
        .method("GET")
        .uri("/v1/route1/ping")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-pool")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s1, _, b1) = send_http1(gw_addr, req1).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(b1, "keepalive-ok");
    assert_eq!(
        accepted_tcp_connections.load(Ordering::SeqCst),
        1,
        "first request should establish exactly 1 upstream TCP connection"
    );

    // Trigger proxy.reload_from_toml_str adding brand-new second route/policy while keeping pool identical
    let toml_reload = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "pool-agent"
org_id = "org-pool"
token = "tok-pool"

[[pools]]
name = "keepalive-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr}" }}
]

[[routes]]
id = "route-1"
path_prefix = "/v1/route1"
strip_prefix = true
pool = "keepalive-pool"

[[routes]]
id = "route-2"
path_prefix = "/v1/route2"
strip_prefix = true
pool = "keepalive-pool"

[[policies]]
org_id = "org-pool"
route_id = "route-1"
methods = ["GET"]
path_prefix = "/v1/route1"

[[policies]]
org_id = "org-pool"
route_id = "route-2"
methods = ["GET"]
path_prefix = "/v1/route2"
"#
    );
    let reload_res = proxy.reload_from_toml_str(&toml_reload);
    assert!(reload_res.is_ok(), "hot reload must succeed");

    // Send request 2 to the original route -> 200 OK, accepted_tcp_connections == 1
    let req2 = Request::builder()
        .method("GET")
        .uri("/v1/route1/ping")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-pool")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s2, _, b2) = send_http1(gw_addr, req2).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2, "keepalive-ok");
    assert_eq!(
        accepted_tcp_connections.load(Ordering::SeqCst),
        1,
        "warm idle HTTP/1.1 connection must be preserved across atomic ArcSwap hot reload"
    );
}

#[tokio::test]
async fn protect_observability_gates_metrics_and_replay_while_keeping_healthz_public() {
    // Configure [server] with protect_observability = true and admin_token = "adm-obs-secret"
    let toml_cfg = r#"
[server]
listen_addr = "127.0.0.1:0"
protect_observability = true
admin_token = "adm-obs-secret"
"#;

    let compiled =
        CompiledConfig::from_toml_str(toml_cfg).unwrap_or_else(|e| panic!("compile: {e}"));
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

    // 1. GET /_edgegate/healthz without token -> 200 OK
    let healthz_req = Request::builder()
        .method("GET")
        .uri("/_edgegate/healthz")
        .header("host", "edgegate.local")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s_healthz, _, b_healthz) = send_http1(gw_addr, healthz_req).await;
    assert_eq!(s_healthz, StatusCode::OK);
    assert!(b_healthz.contains("\"ok\""));

    // 2. GET /_edgegate/metrics without token -> 401 Unauthorized
    let metrics_no_tok = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics")
        .header("host", "edgegate.local")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s_m_no, _, _) = send_http1(gw_addr, metrics_no_tok).await;
    assert_eq!(
        s_m_no,
        StatusCode::UNAUTHORIZED,
        "metrics without token must return 401 when protect_observability = true"
    );

    // 3. GET /_edgegate/replay without token -> 401 Unauthorized
    let replay_no_tok = Request::builder()
        .method("GET")
        .uri("/_edgegate/replay")
        .header("host", "edgegate.local")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s_r_no, _, _) = send_http1(gw_addr, replay_no_tok).await;
    assert_eq!(
        s_r_no,
        StatusCode::UNAUTHORIZED,
        "replay without token must return 401 when protect_observability = true"
    );

    // 4. GET /_edgegate/metrics with X-EdgeGate-Admin-Token -> 200 OK
    let metrics_with_tok = Request::builder()
        .method("GET")
        .uri("/_edgegate/metrics")
        .header("host", "edgegate.local")
        .header("x-edgegate-admin-token", "adm-obs-secret")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s_m_ok, _, b_m_ok) = send_http1(gw_addr, metrics_with_tok).await;
    assert_eq!(s_m_ok, StatusCode::OK);
    assert!(b_m_ok.contains("\"allowed_total\":"));

    // 5. GET /_edgegate/replay with X-EdgeGate-Admin-Token -> 200 OK
    let replay_with_tok = Request::builder()
        .method("GET")
        .uri("/_edgegate/replay")
        .header("host", "edgegate.local")
        .header("x-edgegate-admin-token", "adm-obs-secret")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s_r_ok, _, b_r_ok) = send_http1(gw_addr, replay_with_tok).await;
    assert_eq!(s_r_ok, StatusCode::OK);
    assert!(b_r_ok.contains("\"records\":"));
}

#[tokio::test]
async fn secret_rotation_preserves_json_special_chars_and_reload_disabling_private_ip_evicts_warm_pool(
) {
    let captured_auth: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured_auth);

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
            let captured_inner = Arc::clone(&captured_clone);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let captured_deep = Arc::clone(&captured_inner);
                    async move {
                        let auth = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        *captured_deep.lock().unwrap() = auth;
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"upstream-ok",
                        ))))
                    }
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let toml_initial = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
admin_token = "adm-sec-rotate"

[[workloads]]
workload_id = "test-workload"
org_id = "org-special"
token = "tok-special"

[[pools]]
name = "special-pool"
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{up_addr}" }}
]

[[routes]]
id = "special-route"
path_prefix = "/v1/special"
strip_prefix = true
pool = "special-pool"

[routes.credential]
credential_ref = "rot_key"
header_name = "Authorization"
value_prefix = "Bearer "

[[policies]]
org_id = "org-special"
route_id = "special-route"
methods = ["GET"]
path_prefix = "/v1/special"

[[secrets]]
org_id = "org-special"
credential_ref = "rot_key"
value = "initial_secret"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_initial).unwrap_or_else(|e| panic!("compile: {e}"));
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

    // 1. Initial request establishes a warm keep-alive connection to 127.0.0.1:<port>
    let req1 = Request::builder()
        .method("GET")
        .uri("/v1/special/ping")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-special")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s1, _, b1) = send_http1(gw_addr, req1).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(b1, "upstream-ok");
    assert_eq!(
        captured_auth.lock().unwrap().as_deref(),
        Some("Bearer initial_secret")
    );

    // 2. Rotate secret via JSON POST /_edgegate/admin/secrets/rotate with value "sec_prefix\":suffix\\quote"
    let rotate_json = r#"{"org_id":"org-special","credential_ref":"rot_key","value":"sec_prefix\":suffix\\quote"}"#;
    let rotate_req = Request::builder()
        .method("POST")
        .uri("/_edgegate/admin/secrets/rotate")
        .header("host", "edgegate.local")
        .header("x-edgegate-admin-token", "adm-sec-rotate")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(rotate_json)))
        .unwrap();
    let (s_rot, _, b_rot) = send_http1(gw_addr, rotate_req).await;
    assert_eq!(
        s_rot,
        StatusCode::OK,
        "secret rotation must succeed: {b_rot}"
    );
    assert!(b_rot.contains("\"status\":\"rotated\""));

    // Verify subsequent request injects the EXACT verbatim string "Bearer sec_prefix\":suffix\\quote" upstream
    let req2 = Request::builder()
        .method("GET")
        .uri("/v1/special/ping2")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-special")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s2, _, b2) = send_http1(gw_addr, req2).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2, "upstream-ok");
    assert_eq!(
        captured_auth.lock().unwrap().as_deref(),
        Some("Bearer sec_prefix\":suffix\\quote"),
        "injected Authorization header must preserve verbatim special characters without corruption"
    );

    // 3. Reload pool from allow_private_ip = true to allow_private_ip = false
    let toml_disallow_private = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"
admin_token = "adm-sec-rotate"

[[workloads]]
workload_id = "test-workload"
org_id = "org-special"
token = "tok-special"

[[pools]]
name = "special-pool"
allow_private_ip = false
backends = [
  {{ id = "b1", address = "{up_addr}" }}
]

[[routes]]
id = "special-route"
path_prefix = "/v1/special"
strip_prefix = true
pool = "special-pool"

[routes.credential]
credential_ref = "rot_key"
header_name = "Authorization"
value_prefix = "Bearer "

[[policies]]
org_id = "org-special"
route_id = "special-route"
methods = ["GET"]
path_prefix = "/v1/special"

[[secrets]]
org_id = "org-special"
credential_ref = "rot_key"
value = "initial_secret"
"#
    );

    let reload_res = proxy.reload_from_toml_str(&toml_disallow_private);
    assert!(
        reload_res.is_ok(),
        "hot reload disabling private IP must succeed: {:?}",
        reload_res.err()
    );

    // 4. Request through the pool must evict the warm slot and reject subsequent request with 403 Forbidden (SSRF guard)
    let req3 = Request::builder()
        .method("GET")
        .uri("/v1/special/ping3")
        .header("host", "edgegate.local")
        .header("x-edgegate-token", "tok-special")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s3, _, _) = send_http1(gw_addr, req3).await;
    assert_eq!(
        s3,
        StatusCode::FORBIDDEN,
        "request after hot-reloading allow_private_ip=false must be rejected with 403 Forbidden by SSRF guard"
    );
}
