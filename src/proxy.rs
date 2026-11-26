use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{
    HeaderName, HeaderValue, ACCEPT, ACCESS_CONTROL_REQUEST_METHOD, CONTENT_TYPE, HOST, ORIGIN,
    RETRY_AFTER,
};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use tokio::net::{TcpListener, UnixListener};
use tracing::{error, info, warn};

use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::auth::{
    HeaderTokenAuthenticator, TransportBoundAuthenticator, WorkloadAuthenticator, WorkloadIdentity,
};
use crate::config::{
    sha256_digest, CompiledAwsSigV4, CompiledConfig, CompiledCorsConfig, CompiledWorkload,
};
use crate::lb::{LoadBalancer, PoolLoadBalancer};
use crate::policy::{DefaultDenyPolicyEngine, PolicyDecision, PolicyEngine};
use crate::pool::ConnectionPool;
use crate::router::{
    resolve_or_generate_traceparent, rewrite_upstream_path_and_query, sanitize_outbound_headers,
    sanitize_w3c_tracestate, validate_request_path, Router, TRACEPARENT_HEADER, TRACESTATE_HEADER,
    TRACE_ID_RESPONSE_HEADER,
};
use crate::secrets::{MockSecretProvider, SecretProvider};
use crate::telemetry::{ReplayRecord, Telemetry};
use crate::EdgeGateError;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Optional routing-key header for `ConsistentHash` load balancing (`Milestone 3`).
pub const ROUTING_KEY_HEADER: &str = "x-edgegate-routing-key";

/// Locked admin control-plane authentication header (`Milestone 7`).
pub const ADMIN_TOKEN_HEADER: &str = "x-edgegate-admin-token";

#[derive(Debug, Deserialize)]
struct RotateSecretRequest {
    org_id: String,
    credential_ref: String,
    value: String,
    #[serde(default)]
    expires_at_epoch_s: Option<u64>,
}

/// RAII handle returned by `EdgeGateProxy::register_boxlet_sandbox`.
/// Automatically stops the sandbox UDS listener and removes the socket file when dropped.
pub struct BoxletSandboxGuard {
    socket_path: PathBuf,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for BoxletSandboxGuard {
    fn drop(&mut self) {
        self.handle.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

pub struct WorkloadBulkheadGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for WorkloadBulkheadGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct InFlightGuard {
    telemetry: Arc<Telemetry>,
}

impl InFlightGuard {
    fn new(telemetry: Arc<Telemetry>) -> Self {
        telemetry.inc_in_flight();
        Self { telemetry }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.telemetry.dec_in_flight();
    }
}

pin_project_lite::pin_project! {
    pub struct GuardedResponseBody {
        #[pin]
        inner: ProxyBody,
        _in_flight: Option<InFlightGuard>,
        _bulkhead: Option<WorkloadBulkheadGuard>,
    }
}

impl hyper::body::Body for GuardedResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let res = this.inner.poll_frame(cx);
        match &res {
            std::task::Poll::Ready(None) | std::task::Poll::Ready(Some(Err(_))) => {
                *this._in_flight = None;
                *this._bulkhead = None;
            }
            _ => {}
        }
        res
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

struct BufferedBodyWithTrailers {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl hyper::body::Body for BufferedBodyWithTrailers {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if let Some(bytes) = self.data.take() {
            if !bytes.is_empty() {
                return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))));
            }
        }
        if let Some(trailers) = self.trailers.take() {
            return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::trailers(trailers))));
        }
        std::task::Poll::Ready(None)
    }
}

/// Immutable runtime snapshot stored behind `ArcSwap` for lock-free hot-path reads
/// and atomic zero-downtime config reloads.
pub struct RuntimeSnapshot {
    pub config: Arc<CompiledConfig>,
    pub auth: Arc<dyn WorkloadAuthenticator>,
    pub policy: Arc<dyn PolicyEngine>,
    pub secrets: Arc<dyn SecretProvider>,
    pub router: Router,
    pub lb: Arc<dyn LoadBalancer>,
    pub pool: Arc<ConnectionPool>,
}

impl RuntimeSnapshot {
    pub fn from_config(config: Arc<CompiledConfig>) -> Self {
        Self::from_config_reusing(config, None)
    }

    pub fn from_config_reusing(
        config: Arc<CompiledConfig>,
        prev_pool: Option<&ConnectionPool>,
    ) -> Self {
        let auth = Arc::new(HeaderTokenAuthenticator::new(config.workloads.clone()));
        let policy = Arc::new(DefaultDenyPolicyEngine::new(config.policies.clone()));
        let secrets = Arc::new(MockSecretProvider::from_compiled(config.secrets.clone()));
        let router = Router::new(config.routes.clone());
        let lb = Arc::new(PoolLoadBalancer::from_pools(&config.pools));
        let pool = Arc::new(ConnectionPool::from_pools_reusing(
            &config.pools,
            config.connect_timeout,
            config.response_timeout,
            prev_pool,
        ));
        Self {
            config,
            auth,
            policy,
            secrets,
            router,
            lb,
            pool,
        }
    }
}

/// Core EdgeGate reverse proxy server supporting HTTP/1.1 & HTTP/2, outbound TLS,
/// three-state circuit breakers, traffic shadowing, flight-recorder replay, and Boxlet UDS attachment.
pub struct EdgeGateProxy {
    runtime: Arc<ArcSwap<RuntimeSnapshot>>,
    telemetry: Arc<Telemetry>,
    bulkheads: ArcSwap<HashMap<(String, String), Arc<AtomicUsize>>>,
}

impl EdgeGateProxy {
    pub fn new(config: Arc<CompiledConfig>) -> Self {
        let replay_cap = config.replay_buffer_size;
        let snapshot = Arc::new(RuntimeSnapshot::from_config(config));
        Self {
            runtime: Arc::new(ArcSwap::new(snapshot)),
            telemetry: Arc::new(Telemetry::with_replay_capacity(replay_cap)),
            bulkheads: ArcSwap::new(Arc::new(HashMap::new())),
        }
    }

    fn get_or_create_workload_counter(&self, org_id: &str, workload_id: &str) -> Arc<AtomicUsize> {
        let key = (org_id.to_string(), workload_id.to_string());
        let snap = self.bulkheads.load();
        if let Some(c) = snap.get(&key) {
            return Arc::clone(c);
        }
        let new_counter = Arc::new(AtomicUsize::new(0));
        self.bulkheads.rcu(|current| {
            let mut next = (**current).clone();
            next.entry(key.clone())
                .or_insert_with(|| Arc::clone(&new_counter));
            Arc::new(next)
        });
        if let Some(c) = self.bulkheads.load().get(&key) {
            Arc::clone(c)
        } else {
            new_counter
        }
    }

    pub fn telemetry(&self) -> Arc<Telemetry> {
        Arc::clone(&self.telemetry)
    }

    /// Rotates a scoped credential live in-memory without a full configuration reload (`Milestone 6`).
    pub fn rotate_secret(
        &self,
        org_id: &str,
        credential_ref: &str,
        new_value: String,
        expires_at_epoch_s: Option<u64>,
    ) {
        let snap = self.runtime.load();
        snap.secrets
            .rotate_secret(org_id, credential_ref, new_value, expires_at_epoch_s);
        self.telemetry.record_secret_rotation();
    }

    /// Atomically reloads configuration from disk without dropping in-flight requests.
    pub fn reload_from_file(&self, path: &Path) -> Result<u64, EdgeGateError> {
        match CompiledConfig::from_file(path) {
            Ok(compiled) => Ok(self.swap_compiled(compiled)),
            Err(err) => {
                self.telemetry.record_reload_failure();
                warn!(error = %err, "edgegate_reload_rejected_keeping_active_snapshot");
                Err(err)
            }
        }
    }

    /// Atomically reloads configuration from a TOML string without dropping in-flight requests.
    pub fn reload_from_toml_str(&self, input: &str) -> Result<u64, EdgeGateError> {
        match CompiledConfig::from_toml_str(input) {
            Ok(compiled) => Ok(self.swap_compiled(compiled)),
            Err(err) => {
                self.telemetry.record_reload_failure();
                warn!(error = %err, "edgegate_reload_rejected_keeping_active_snapshot");
                Err(err)
            }
        }
    }

    fn swap_compiled(&self, compiled: Arc<CompiledConfig>) -> u64 {
        let prev = self.runtime.load();
        let next = Arc::new(RuntimeSnapshot::from_config_reusing(
            compiled,
            Some(&prev.pool),
        ));
        self.runtime.store(next);
        let gen = self.telemetry.record_reload_success();
        info!(
            config_generation = gen,
            "edgegate_config_reloaded_atomically"
        );
        gen
    }

    /// Spawns background active HTTP health probes for all pools configured with `health_check_path`.
    pub fn spawn_active_health_probes(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let proxy = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));
            loop {
                interval.tick().await;
                let snap = proxy.runtime.load_full();
                for (pool_name, pool_cfg) in &snap.config.pools {
                    let Some(ref hc_path) = pool_cfg.health_check_path else {
                        continue;
                    };
                    for backend in &pool_cfg.backends {
                        let ok = snap
                            .pool
                            .probe_backend_health(
                                pool_name,
                                backend,
                                pool_cfg.allow_private_ip,
                                hc_path,
                            )
                            .await;
                        snap.lb.set_active_health(pool_name, &backend.id, ok);
                    }
                }
            }
        })
    }

    /// Dynamically attaches a zero-token Boxlet sandbox Unix domain socket at runtime (`Milestone 3`).
    /// Returns a RAII `BoxletSandboxGuard` that tears down the listener and socket file on drop.
    pub fn register_boxlet_sandbox(
        self: &Arc<Self>,
        socket_path: PathBuf,
        workload: CompiledWorkload,
    ) -> Result<BoxletSandboxGuard, EdgeGateError> {
        let handle = self.spawn_single_unix_listener(&socket_path, workload)?;
        Ok(BoxletSandboxGuard {
            socket_path,
            handle,
        })
    }

    /// Binds and serves zero-token Unix domain socket listeners configured in `server.unix_listeners`.
    pub fn spawn_unix_listeners(
        self: &Arc<Self>,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, EdgeGateError> {
        let snap = self.runtime.load();
        let mut handles = Vec::with_capacity(snap.config.unix_listeners.len());

        for uds_cfg in &snap.config.unix_listeners {
            let h = self.spawn_single_unix_listener(&uds_cfg.path, uds_cfg.workload.clone())?;
            handles.push(h);
        }

        Ok(handles)
    }

    fn spawn_single_unix_listener(
        self: &Arc<Self>,
        path: &Path,
        workload: CompiledWorkload,
    ) -> Result<tokio::task::JoinHandle<()>, EdgeGateError> {
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        let listener = UnixListener::bind(path).map_err(|e| {
            EdgeGateError::Internal(format!(
                "failed to bind unix_listener '{}': {e}",
                path.display()
            ))
        })?;
        info!(
            socket_path = %path.display(),
            workload_id = %workload.workload_id,
            org_id = %workload.org_id,
            "edgegate_unix_listener_bound"
        );

        let auth = Arc::new(TransportBoundAuthenticator::new(workload));
        let proxy = Arc::clone(self);
        Ok(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                let proxy = Arc::clone(&proxy);
                let auth = Arc::clone(&auth);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let proxy = Arc::clone(&proxy);
                        let auth = Arc::clone(&auth);
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                proxy
                                    .handle_request_with_auth(req, Some(auth.as_ref()))
                                    .await,
                            )
                        }
                    });
                    let _ = AutoConnBuilder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                });
            }
        }))
    }

    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        mut shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), EdgeGateError> {
        let local_addr = listener.local_addr().map_err(|e| {
            EdgeGateError::Internal(format!("failed to read listener local_addr: {e}"))
        })?;
        info!(listen_addr = %local_addr, "edgegate_listening");

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("edgegate_shutdown_signal_received");
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, _peer) = match accept_res {
                        Ok(pair) => pair,
                        Err(err) => {
                            error!(error = %err, "edgegate_accept_error");
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);
                    let inbound_tls = self.runtime.load().config.inbound_tls.clone();
                    let proxy = Arc::clone(&self);
                    tokio::spawn(async move {
                        let service = service_fn(move |req: Request<Incoming>| {
                            let proxy = Arc::clone(&proxy);
                            async move { Ok::<_, std::convert::Infallible>(proxy.handle_request(req).await) }
                        });
                        if let Some(tls_cfg) = inbound_tls {
                            let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
                            let tls_stream = match acceptor.accept(stream).await {
                                Ok(s) => s,
                                Err(err) => {
                                    error!(error = %err, "edgegate_inbound_tls_accept_error");
                                    return;
                                }
                            };
                            let io = TokioIo::new(tls_stream);
                            if let Err(err) = AutoConnBuilder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await
                            {
                                error!(error = %err, "edgegate_connection_error");
                            }
                        } else {
                            let io = TokioIo::new(stream);
                            if let Err(err) = AutoConnBuilder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await
                            {
                                error!(error = %err, "edgegate_connection_error");
                            }
                        }
                    });
                }
            }
        }

        let drain_timeout = self.runtime.load().config.drain_timeout;
        let drain_deadline = Instant::now() + drain_timeout;
        while self.telemetry.in_flight_count() > 0 && Instant::now() < drain_deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    pub async fn bind_and_serve(
        self: Arc<Self>,
        addr: SocketAddr,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), EdgeGateError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| EdgeGateError::Internal(format!("failed to bind {addr}: {e}")))?;
        self.serve(listener, shutdown).await
    }

    pub async fn handle_request(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        self.handle_request_with_auth(req, None).await
    }

    pub async fn handle_request_with_auth(
        &self,
        req: Request<Incoming>,
        transport_auth: Option<&dyn WorkloadAuthenticator>,
    ) -> Response<ProxyBody> {
        let mut in_flight_guard = Some(InFlightGuard::new(Arc::clone(&self.telemetry)));
        let started = Instant::now();
        let path = req.uri().path();

        // Step 0: Built-in observability & flight-recorder endpoints.
        if path == "/_edgegate/healthz" {
            let gen = self.telemetry.snapshot().config_generation;
            let body = Bytes::from(format!("{{\"status\":\"ok\",\"config_generation\":{gen}}}"));
            let mut resp = Response::new(Full::new(body).map_err(|never| match never {}).boxed());
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            return resp;
        }

        if path == "/_edgegate/console" {
            if req.method() != Method::GET && req.method() != Method::HEAD {
                return json_error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            }
            let body = if req.method() == Method::HEAD {
                Bytes::new()
            } else {
                Bytes::from_static(crate::console::render_operator_console_html().as_bytes())
            };
            let mut resp = Response::new(Full::new(body).map_err(|never| match never {}).boxed());
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_static(crate::console::CONSOLE_CSP),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("no-referrer"),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("cache-control"),
                HeaderValue::from_static("no-store"),
            );
            return resp;
        }

        let snap = self.runtime.load_full();

        if path == "/_edgegate/metrics" {
            if snap.config.protect_observability {
                if let Err(err) = verify_admin_token(&snap, req.headers()) {
                    return json_error_response(err.status_code(), &err.public_message());
                }
            }
            let wants_prom_query = req
                .uri()
                .query()
                .is_some_and(|q| q.split('&').any(|kv| kv == "format=prometheus"));
            let wants_prom_accept = req
                .headers()
                .get(ACCEPT)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|a| a.contains("text/plain"));
            if wants_prom_query || wants_prom_accept {
                let body = Bytes::from(self.telemetry.to_prometheus());
                let mut resp =
                    Response::new(Full::new(body).map_err(|never| match never {}).boxed());
                *resp.status_mut() = StatusCode::OK;
                resp.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                );
                return resp;
            }
            let body = Bytes::from(self.telemetry.to_json());
            let mut resp = Response::new(Full::new(body).map_err(|never| match never {}).boxed());
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            return resp;
        }
        if path == "/_edgegate/replay" {
            if snap.config.protect_observability {
                if let Err(err) = verify_admin_token(&snap, req.headers()) {
                    return json_error_response(err.status_code(), &err.public_message());
                }
            }
            let body = Bytes::from(self.telemetry.replay_to_json());
            let mut resp = Response::new(Full::new(body).map_err(|never| match never {}).boxed());
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            return resp;
        }

        // Step 0b: Authenticated Admin Control Plane (`Milestone 7` & `Milestone 8`).
        if path == "/_edgegate/admin/audit"
            || path == "/_edgegate/admin/pools"
            || path == "/_edgegate/admin/reload"
            || path == "/_edgegate/admin/secrets/rotate"
        {
            if let Err(err) = verify_admin_token(&snap, req.headers()) {
                return json_error_response(err.status_code(), &err.public_message());
            }
            if path == "/_edgegate/admin/audit" && req.method() == Method::GET {
                let body = Bytes::from(self.telemetry.audit_to_json());
                let mut resp =
                    Response::new(Full::new(body).map_err(|never| match never {}).boxed());
                *resp.status_mut() = StatusCode::OK;
                resp.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                return resp;
            }
            if path == "/_edgegate/admin/pools" && req.method() == Method::GET {
                let body = Bytes::from(snap.lb.pools_status_json());
                let mut resp =
                    Response::new(Full::new(body).map_err(|never| match never {}).boxed());
                *resp.status_mut() = StatusCode::OK;
                resp.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                return resp;
            }
            if path == "/_edgegate/admin/reload" && req.method() == Method::POST {
                let max_body = snap.config.max_request_body_bytes;
                let Ok(collected) = Limited::new(req.into_body(), max_body).collect().await else {
                    return json_error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "admin request body exceeds limit",
                    );
                };
                let body_bytes = collected.to_bytes();
                let Ok(body_str) = std::str::from_utf8(&body_bytes) else {
                    return json_error_response(
                        StatusCode::BAD_REQUEST,
                        "admin reload body must be valid UTF-8 TOML",
                    );
                };
                match self.reload_from_toml_str(body_str) {
                    Ok(gen) => {
                        let body = Bytes::from(format!(
                            "{{\"status\":\"reloaded\",\"config_generation\":{gen}}}"
                        ));
                        let mut resp =
                            Response::new(Full::new(body).map_err(|never| match never {}).boxed());
                        *resp.status_mut() = StatusCode::OK;
                        resp.headers_mut()
                            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                        return resp;
                    }
                    Err(err) => {
                        return json_error_response(StatusCode::BAD_REQUEST, &err.to_string());
                    }
                }
            }
            if path == "/_edgegate/admin/secrets/rotate" && req.method() == Method::POST {
                let max_body = snap.config.max_request_body_bytes;
                let Ok(collected) = Limited::new(req.into_body(), max_body).collect().await else {
                    return json_error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "admin request body exceeds limit",
                    );
                };
                let body_bytes = collected.to_bytes();
                let Ok(body_str) = std::str::from_utf8(&body_bytes) else {
                    return json_error_response(
                        StatusCode::BAD_REQUEST,
                        "admin secret rotation body must be valid UTF-8",
                    );
                };
                let Ok(rot_req) = parse_rotate_secret_request(body_str) else {
                    return json_error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid secret rotation payload",
                    );
                };
                if rot_req.org_id.trim().is_empty() || rot_req.credential_ref.trim().is_empty() {
                    return json_error_response(
                        StatusCode::BAD_REQUEST,
                        "org_id and credential_ref must be non-empty",
                    );
                }
                self.rotate_secret(
                    &rot_req.org_id,
                    &rot_req.credential_ref,
                    rot_req.value,
                    rot_req.expires_at_epoch_s,
                );
                let body = Bytes::from_static(b"{\"status\":\"rotated\"}");
                let mut resp =
                    Response::new(Full::new(body).map_err(|never| match never {}).boxed());
                *resp.status_mut() = StatusCode::OK;
                resp.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                return resp;
            }
            return json_error_response(StatusCode::BAD_REQUEST, "unsupported admin method");
        }

        let req_id = self.telemetry.next_request_id();
        let req_headers = req.headers().clone();
        let (traceparent, trace_id) = resolve_or_generate_traceparent(&req_headers, req_id);

        let method = req.method().clone();
        let path = path.to_string();
        let query = req.uri().query().map(ToString::to_string);
        let host_header = req_headers
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let routing_key = req_headers
            .get(ROUTING_KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let raw_origin_header = req_headers
            .get(ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());
        let origin_header = raw_origin_header
            .as_deref()
            .map(|s| s.trim_end_matches('/').to_ascii_lowercase());

        // Step 1: Fail-closed pre-policy path validation.
        if let Err(err) = validate_request_path(&path) {
            return self.finish_error(
                req_id, &trace_id, "-", "-", "-", "-", "BLOCKED", err, started,
            );
        }

        let pre_matched_cors = snap
            .router
            .match_route(&path, host_header.as_deref())
            .and_then(|r| r.cors.clone());

        // CORS OPTIONS Preflight Short-Circuit (Before Step 2 Workload Auth, INV-27).
        if method == Method::OPTIONS
            && req_headers.contains_key(ORIGIN)
            && req_headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD)
        {
            if let Some(route) = snap.router.match_route(&path, host_header.as_deref()) {
                if let Some(ref cors) = route.cors {
                    if let Some(ref origin) = origin_header {
                        if cors.allowed_origins.contains(origin) {
                            let origin_val_str = raw_origin_header.as_deref().unwrap_or(origin);
                            if let Ok(origin_hv) = HeaderValue::from_str(origin_val_str) {
                                let latency_us = started.elapsed().as_micros() as u64;
                                self.telemetry.record_request(
                                    req_id,
                                    &trace_id,
                                    "-",
                                    "-",
                                    &route.id,
                                    "-",
                                    "ALLOWED",
                                    StatusCode::NO_CONTENT.as_u16(),
                                    latency_us,
                                );
                                let mut resp = Response::new(
                                    Full::new(Bytes::new())
                                        .map_err(|never| match never {})
                                        .boxed(),
                                );
                                *resp.status_mut() = StatusCode::NO_CONTENT;
                                resp.headers_mut().insert(
                                    HeaderName::from_static("access-control-allow-origin"),
                                    origin_hv,
                                );
                                resp.headers_mut().insert(
                                    HeaderName::from_static("access-control-allow-methods"),
                                    cors.allow_methods_value.clone(),
                                );
                                resp.headers_mut().insert(
                                    HeaderName::from_static("access-control-allow-headers"),
                                    cors.allow_headers_value.clone(),
                                );
                                resp.headers_mut().insert(
                                    HeaderName::from_static("access-control-max-age"),
                                    cors.max_age_value.clone(),
                                );
                                resp.headers_mut().insert(
                                    HeaderName::from_static("vary"),
                                    HeaderValue::from_static("Origin"),
                                );
                                if let Ok(trace_val) = HeaderValue::from_str(&trace_id) {
                                    resp.headers_mut().insert(
                                        HeaderName::from_static(TRACE_ID_RESPONSE_HEADER),
                                        trace_val,
                                    );
                                }
                                return resp;
                            }
                        }
                    }
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        "-",
                        "-",
                        &route.id,
                        "-",
                        "BLOCKED",
                        EdgeGateError::Forbidden(
                            "CORS origin not allowed by route policy".to_string(),
                        ),
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
            }
        }

        // Step 2: Authenticate workload (transport-bound UDS identity OR X-EdgeGate-Token header).
        let identity: WorkloadIdentity = match transport_auth {
            Some(ta) => match ta.authenticate(&req_headers) {
                Ok(id) => id,
                Err(err) => {
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        "-",
                        "-",
                        "-",
                        "-",
                        "BLOCKED",
                        err,
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
            },
            None => match snap.auth.authenticate(&req_headers) {
                Ok(id) => id,
                Err(err) => {
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        "-",
                        "-",
                        "-",
                        "-",
                        "BLOCKED",
                        err,
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
            },
        };

        // Step 2b: Per-workload concurrency quota / bulkhead isolation (INV-20).
        let active_counter =
            self.get_or_create_workload_counter(&identity.org_id, &identity.workload_id);
        let mut bulkhead_guard = if let Some(limit) = identity.max_concurrent_requests {
            #[allow(deprecated)]
            match active_counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                if cur < limit {
                    Some(cur + 1)
                } else {
                    None
                }
            }) {
                Ok(_) => Some(WorkloadBulkheadGuard {
                    active: active_counter,
                }),
                Err(_) => {
                    self.telemetry.record_bulkhead_rejected();
                    self.telemetry.record_replay(ReplayRecord {
                        request_id: req_id,
                        trace_id: trace_id.clone(),
                        org_id: identity.org_id.clone(),
                        workload_id: identity.workload_id.clone(),
                        method: method.as_str().to_string(),
                        path: path.clone(),
                        route: "-".to_string(),
                        upstream: "-".to_string(),
                        status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                        shadow_status: None,
                        reason: "workload_bulkhead_rejected".to_string(),
                        latency_us: started.elapsed().as_micros() as u64,
                    });
                    let mut resp = self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        "-",
                        "-",
                        "RATE_LIMITED",
                        EdgeGateError::TooManyRequests(
                            "workload concurrency quota exceeded".to_string(),
                        ),
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                    resp.headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
                    return resp;
                }
            }
        } else {
            active_counter.fetch_add(1, Ordering::AcqRel);
            Some(WorkloadBulkheadGuard {
                active: active_counter,
            })
        };

        // Step 3: Match explicit route (default-deny unmatched destination).
        let route = match snap.router.match_route(&path, host_header.as_deref()) {
            Some(r) => r.clone(),
            None => {
                return self.finish_error_with_cors(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    "-",
                    "-",
                    "BLOCKED",
                    EdgeGateError::Forbidden(format!("default-deny: no route matches '{path}'")),
                    started,
                    pre_matched_cors.as_ref(),
                    origin_header.as_deref(),
                );
            }
        };

        // CORS Actual Request Enforcement (INV-27).
        if let Some(ref cors) = route.cors {
            if let Some(ref orig) = origin_header {
                if !cors.allowed_origins.contains(orig) {
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        "-",
                        "BLOCKED",
                        EdgeGateError::Forbidden(
                            "CORS origin not allowed by route policy".to_string(),
                        ),
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
            }
        }

        // Step 4: Evaluate default-deny org_id/workload/roles/route/method/path/query/headers policy + rate limit.
        let (rule_max_body_bytes, blocked_body_substrings, allowed_jsonrpc_methods) =
            match snap.policy.evaluate_request(
                &identity,
                &route.id,
                &method,
                &path,
                query.as_deref(),
                &req_headers,
            ) {
                PolicyDecision::Allow {
                    max_body_bytes,
                    blocked_body_substrings,
                    allowed_jsonrpc_methods,
                } => (
                    max_body_bytes,
                    blocked_body_substrings,
                    allowed_jsonrpc_methods,
                ),
                PolicyDecision::Deny { reason } => {
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        "-",
                        "BLOCKED",
                        EdgeGateError::Forbidden(reason),
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
                PolicyDecision::RateLimited { reason } => {
                    self.telemetry.record_replay(ReplayRecord {
                        request_id: req_id,
                        trace_id: trace_id.clone(),
                        org_id: identity.org_id.clone(),
                        workload_id: identity.workload_id.clone(),
                        method: method.as_str().to_string(),
                        path: path.clone(),
                        route: route.id.clone(),
                        upstream: "-".to_string(),
                        status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                        shadow_status: None,
                        reason: "rate_limited".to_string(),
                        latency_us: started.elapsed().as_micros() as u64,
                    });
                    let mut resp = self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        "-",
                        "RATE_LIMITED",
                        EdgeGateError::TooManyRequests(reason),
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                    resp.headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
                    return resp;
                }
            };

        // Step 4a: Bounded request body collection BEFORE upstream selection.
        let max_body = rule_max_body_bytes.unwrap_or(snap.config.max_request_body_bytes);
        let collected = match Limited::new(req.into_body(), max_body).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return self.finish_error_with_cors(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    "-",
                    "BLOCKED",
                    EdgeGateError::PayloadTooLarge(format!(
                        "request body exceeds limit of {max_body} bytes"
                    )),
                    started,
                    pre_matched_cors.as_ref(),
                    origin_header.as_deref(),
                );
            }
        };

        // Step 4b: Egress DLP Request Payload Guard (`Milestone 8`) BEFORE upstream selection.
        if let Some(matched_pat) = blocked_body_substrings.iter().find(|pat| {
            let needle = pat.as_bytes();
            !needle.is_empty() && collected.windows(needle.len()).any(|w| w == needle)
        }) {
            let latency_us = started.elapsed().as_micros() as u64;
            self.telemetry.record_dlp_blocked();
            self.telemetry.record_replay(ReplayRecord {
                request_id: req_id,
                trace_id: trace_id.clone(),
                org_id: identity.org_id.clone(),
                workload_id: identity.workload_id.clone(),
                method: method.as_str().to_string(),
                path: path.clone(),
                route: route.id.clone(),
                upstream: "-".to_string(),
                status: StatusCode::FORBIDDEN.as_u16(),
                shadow_status: None,
                reason: "dlp_payload_blocked".to_string(),
                latency_us,
            });
            return self.finish_error_with_cors(
                req_id,
                &trace_id,
                &identity.org_id,
                &identity.workload_id,
                &route.id,
                "-",
                "BLOCKED",
                EdgeGateError::Forbidden(format!(
                    "egress DLP blocked forbidden payload pattern '{matched_pat}'"
                )),
                started,
                pre_matched_cors.as_ref(),
                origin_header.as_deref(),
            );
        }

        // Step 4c: JSON-RPC 2.0 / MCP Tool-Call Method Allowlist Guard (`Milestone 9`) BEFORE upstream selection.
        if let Some(ref allowed_methods) = allowed_jsonrpc_methods {
            let is_allowed = match serde_json::from_slice::<serde_json::Value>(&collected) {
                Ok(serde_json::Value::Object(map)) => {
                    map.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
                        && map.get("method").and_then(|v| v.as_str()).is_some_and(|m| {
                            !m.is_empty() && allowed_methods.iter().any(|am| am == m)
                        })
                }
                Ok(serde_json::Value::Array(items)) if !items.is_empty() => {
                    items.iter().all(|item| {
                        if let serde_json::Value::Object(map) = item {
                            map.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
                                && map.get("method").and_then(|v| v.as_str()).is_some_and(|m| {
                                    !m.is_empty() && allowed_methods.iter().any(|am| am == m)
                                })
                        } else {
                            false
                        }
                    })
                }
                _ => false,
            };

            if !is_allowed {
                let latency_us = started.elapsed().as_micros() as u64;
                self.telemetry.record_jsonrpc_blocked();
                self.telemetry.record_replay(ReplayRecord {
                    request_id: req_id,
                    trace_id: trace_id.clone(),
                    org_id: identity.org_id.clone(),
                    workload_id: identity.workload_id.clone(),
                    method: method.as_str().to_string(),
                    path: path.clone(),
                    route: route.id.clone(),
                    upstream: "-".to_string(),
                    status: StatusCode::FORBIDDEN.as_u16(),
                    shadow_status: None,
                    reason: "jsonrpc_method_blocked".to_string(),
                    latency_us,
                });
                return self.finish_error_with_cors(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    "-",
                    "BLOCKED",
                    EdgeGateError::Forbidden(
                        "JSON-RPC/MCP method not allowed by policy".to_string(),
                    ),
                    started,
                    pre_matched_cors.as_ref(),
                    origin_header.as_deref(),
                );
            }
        }

        // Step 5: Select healthy backend via LoadBalancer (supports ConsistentHash routing key).
        let effective_key = routing_key.as_deref().unwrap_or(&identity.workload_id);
        let mut lease = match snap.lb.select_with_key(&route.pool, Some(effective_key)) {
            Ok(l) => l,
            Err(err) => {
                self.telemetry.record_replay(ReplayRecord {
                    request_id: req_id,
                    trace_id: trace_id.clone(),
                    org_id: identity.org_id.clone(),
                    workload_id: identity.workload_id.clone(),
                    method: method.as_str().to_string(),
                    path: path.clone(),
                    route: route.id.clone(),
                    upstream: "-".to_string(),
                    status: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    shadow_status: None,
                    reason: "circuit_open_or_all_backends_unhealthy".to_string(),
                    latency_us: started.elapsed().as_micros() as u64,
                });
                return self.finish_error_with_cors(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    "-",
                    "ERROR",
                    err,
                    started,
                    pre_matched_cors.as_ref(),
                    origin_header.as_deref(),
                );
            }
        };
        let backend_id = lease.backend.id.clone();
        let backend_authority = lease.backend.authority.clone();
        let pool_name = lease.pool_name.clone();

        // Step 6: Sanitize outbound headers, propagate W3C traceparent, and inject scoped upstream credential.
        let target_cred_header = route.credential.as_ref().map(|c| &c.header_name);
        let mut outbound_headers =
            match sanitize_outbound_headers(&req_headers, &backend_authority, target_cred_header) {
                Ok(h) => h,
                Err(err) => {
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        &backend_id,
                        "ERROR",
                        err,
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
            };
        if let Ok(tp_val) = HeaderValue::from_str(&traceparent) {
            outbound_headers.insert(HeaderName::from_static(TRACEPARENT_HEADER), tp_val);
        }
        if let Some(ts_val) = sanitize_w3c_tracestate(&req_headers) {
            outbound_headers.insert(HeaderName::from_static(TRACESTATE_HEADER), ts_val);
        }

        let mut reflection_guard_secret = None;
        if let Some(ref binding) = route.credential {
            let secret = match snap
                .secrets
                .get_secret(&identity.org_id, &binding.credential_ref)
            {
                Ok(s) => s,
                Err(err) => {
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        &backend_id,
                        "BLOCKED",
                        err,
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
            };
            let injected_str = format!("{}{}", binding.value_prefix, secret.expose());
            let header_val = match HeaderValue::from_str(&injected_str) {
                Ok(v) => v,
                Err(_) => {
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        &backend_id,
                        "ERROR",
                        EdgeGateError::Internal("invalid credential header value".to_string()),
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
            };
            outbound_headers.insert(binding.header_name.clone(), header_val);
            if binding.block_secret_reflection && !secret.expose().is_empty() {
                reflection_guard_secret = Some(secret);
            }
        }

        if let Some(ref signing) = route.request_signing {
            outbound_headers.remove(&signing.signature_header);
            outbound_headers.remove(&signing.timestamp_header);
            let secret = match snap
                .secrets
                .get_secret(&identity.org_id, &signing.credential_ref)
            {
                Ok(s) => s,
                Err(err) => {
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        &backend_id,
                        "BLOCKED",
                        err,
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
            };
            let unix_s = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs(),
                Err(_) => 0,
            };
            let ts_prefix = format!("{unix_s}.");
            let signing_input = [ts_prefix.as_bytes(), collected.as_ref()].concat();
            let sig_hex =
                crate::config::hmac_sha256_hex(secret.expose().as_bytes(), &signing_input);
            let sig_val = format!("sha256={sig_hex}");
            if let Ok(ts_val) = HeaderValue::from_str(&unix_s.to_string()) {
                outbound_headers.insert(signing.timestamp_header.clone(), ts_val);
            }
            if let Ok(sig_val_header) = HeaderValue::from_str(&sig_val) {
                outbound_headers.insert(signing.signature_header.clone(), sig_val_header);
            }
            self.telemetry.record_signed_request();
        }

        let upstream_pq = rewrite_upstream_path_and_query(&path, query.as_deref(), &route);
        let upstream_uri = match Uri::builder().path_and_query(upstream_pq.as_str()).build() {
            Ok(u) => u,
            Err(err) => {
                return self.finish_error_with_cors(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    &backend_id,
                    "ERROR",
                    EdgeGateError::BadRequest(format!("invalid rewritten URI: {err}")),
                    started,
                    pre_matched_cors.as_ref(),
                    origin_header.as_deref(),
                );
            }
        };

        if let Some(ref sigv4) = route.aws_sigv4 {
            outbound_headers.remove(http::header::AUTHORIZATION);
            let amz_keys: Vec<HeaderName> = outbound_headers
                .keys()
                .filter(|k| k.as_str().starts_with("x-amz-"))
                .cloned()
                .collect();
            for k in amz_keys {
                outbound_headers.remove(&k);
            }

            if let Err(err) = apply_aws_sigv4_headers(
                &snap,
                &identity.org_id,
                sigv4,
                method.as_str(),
                &upstream_pq,
                &backend_authority,
                &collected,
                &mut outbound_headers,
            ) {
                return self.finish_error_with_cors(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    &backend_id,
                    "BLOCKED",
                    err,
                    started,
                    pre_matched_cors.as_ref(),
                    origin_header.as_deref(),
                );
            }
            self.telemetry.record_signed_request();
        }

        // Step 7: Forward through bounded pool (NO 3xx auto-follow; controlled retries only for idempotent methods).
        let max_retries = if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
            snap.config
                .pools
                .get(&route.pool)
                .map_or(0, |p| p.max_idempotent_retries)
        } else {
            0
        };

        let mut backend_id = backend_id;
        let mut attempt = 0u32;
        let send_res = loop {
            let mut outbound_req = match Request::builder()
                .method(method.clone())
                .uri(upstream_uri.clone())
                .body(Full::new(collected.clone()))
            {
                Ok(r) => r,
                Err(err) => {
                    return self.finish_error_with_cors(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        &backend_id,
                        "ERROR",
                        EdgeGateError::Internal(format!("failed to build upstream request: {err}")),
                        started,
                        pre_matched_cors.as_ref(),
                        origin_header.as_deref(),
                    );
                }
            };
            *outbound_req.headers_mut() = outbound_headers.clone();

            lease.settle_probe();
            match snap
                .pool
                .send_with_timeout(lease, outbound_req, route.response_timeout)
                .await
            {
                Ok(resp) => break Ok(resp),
                Err(EdgeGateError::BadGateway(msg)) if attempt < max_retries => {
                    snap.lb.record_failure(&pool_name, &backend_id);
                    self.telemetry.record_retry();
                    let Ok(next_lease) = snap.lb.select_with_key(&route.pool, Some(effective_key))
                    else {
                        break Err(EdgeGateError::BadGateway(msg));
                    };
                    attempt += 1;
                    backend_id = next_lease.backend.id.clone();
                    if let Ok(host_val) = HeaderValue::from_str(&next_lease.backend.authority) {
                        outbound_headers.insert(HOST, host_val);
                    }
                    if let Some(ref sigv4) = route.aws_sigv4 {
                        if let Err(secret_err) = apply_aws_sigv4_headers(
                            &snap,
                            &identity.org_id,
                            sigv4,
                            method.as_str(),
                            &upstream_pq,
                            &next_lease.backend.authority,
                            &collected,
                            &mut outbound_headers,
                        ) {
                            return self.finish_error_with_cors(
                                req_id,
                                &trace_id,
                                &identity.org_id,
                                &identity.workload_id,
                                &route.id,
                                &backend_id,
                                "BLOCKED",
                                secret_err,
                                started,
                                pre_matched_cors.as_ref(),
                                origin_header.as_deref(),
                            );
                        }
                    }
                    lease = next_lease;
                }
                Err(err) => break Err(err),
            }
        };

        match send_res {
            Ok(resp) => {
                // Step 7a: Response Credential Reflection Guard (`Milestone 5`) & Max Response Body Bytes (`Milestone 9`).
                if let Some(ref secret) = reflection_guard_secret {
                    let needle = secret.expose().as_bytes();
                    let header_reflected = resp.headers().values().any(|v| {
                        v.as_bytes()
                            .windows(needle.len())
                            .any(|window| window == needle)
                    });
                    if header_reflected {
                        let latency_us = started.elapsed().as_micros() as u64;
                        self.telemetry.record_secret_reflection_blocked();
                        self.telemetry.record_replay(ReplayRecord {
                            request_id: req_id,
                            trace_id: trace_id.clone(),
                            org_id: identity.org_id.clone(),
                            workload_id: identity.workload_id.clone(),
                            method: method.as_str().to_string(),
                            path: path.clone(),
                            route: route.id.clone(),
                            upstream: backend_id.clone(),
                            status: StatusCode::BAD_GATEWAY.as_u16(),
                            shadow_status: None,
                            reason: "credential_reflection_blocked".to_string(),
                            latency_us,
                        });
                        return self.finish_error_with_cors(
                            req_id,
                            &trace_id,
                            &identity.org_id,
                            &identity.workload_id,
                            &route.id,
                            &backend_id,
                            "ERROR",
                            EdgeGateError::BadGateway(
                                "upstream credential reflection blocked".to_string(),
                            ),
                            started,
                            pre_matched_cors.as_ref(),
                            origin_header.as_deref(),
                        );
                    }
                }

                let is_buffered =
                    route.max_response_body_bytes.is_some() || reflection_guard_secret.is_some();
                let mapped = if is_buffered {
                    let (parts, incoming_body) = resp.into_parts();
                    let (body_bytes, trailers) = if let Some(limit) = route.max_response_body_bytes
                    {
                        match Limited::new(incoming_body, limit).collect().await {
                            Ok(collected_body) => {
                                let trailers = collected_body.trailers().cloned();
                                let body_bytes = collected_body.to_bytes();
                                (body_bytes, trailers)
                            }
                            Err(box_err) => {
                                let latency_us = started.elapsed().as_micros() as u64;
                                let is_limit_exceeded = box_err
                                    .downcast_ref::<http_body_util::LengthLimitError>()
                                    .is_some();
                                if is_limit_exceeded {
                                    if parts.status.is_server_error() {
                                        snap.lb.record_failure(&pool_name, &backend_id);
                                    } else {
                                        snap.lb.record_success(&pool_name, &backend_id, latency_us);
                                    }
                                    self.telemetry.record_replay(ReplayRecord {
                                        request_id: req_id,
                                        trace_id: trace_id.clone(),
                                        org_id: identity.org_id.clone(),
                                        workload_id: identity.workload_id.clone(),
                                        method: method.as_str().to_string(),
                                        path: path.clone(),
                                        route: route.id.clone(),
                                        upstream: backend_id.clone(),
                                        status: StatusCode::BAD_GATEWAY.as_u16(),
                                        shadow_status: None,
                                        reason: "response_body_too_large".to_string(),
                                        latency_us,
                                    });
                                    return self.finish_error_with_cors(
                                        req_id,
                                        &trace_id,
                                        &identity.org_id,
                                        &identity.workload_id,
                                        &route.id,
                                        &backend_id,
                                        "ERROR",
                                        EdgeGateError::BadGateway(
                                            "upstream response body exceeds max_response_body_bytes"
                                                .to_string(),
                                        ),
                                        started,
                                        pre_matched_cors.as_ref(),
                                        origin_header.as_deref(),
                                    );
                                } else {
                                    snap.lb.record_failure(&pool_name, &backend_id);
                                    self.telemetry.record_replay(ReplayRecord {
                                        request_id: req_id,
                                        trace_id: trace_id.clone(),
                                        org_id: identity.org_id.clone(),
                                        workload_id: identity.workload_id.clone(),
                                        method: method.as_str().to_string(),
                                        path: path.clone(),
                                        route: route.id.clone(),
                                        upstream: backend_id.clone(),
                                        status: StatusCode::BAD_GATEWAY.as_u16(),
                                        shadow_status: None,
                                        reason: "upstream_transport_or_timeout".to_string(),
                                        latency_us,
                                    });
                                    return self.finish_error_with_cors(
                                        req_id,
                                        &trace_id,
                                        &identity.org_id,
                                        &identity.workload_id,
                                        &route.id,
                                        &backend_id,
                                        "ERROR",
                                        EdgeGateError::BadGateway(format!(
                                            "failed to read upstream response body: {box_err}"
                                        )),
                                        started,
                                        pre_matched_cors.as_ref(),
                                        origin_header.as_deref(),
                                    );
                                }
                            }
                        }
                    } else {
                        match incoming_body.collect().await {
                            Ok(collected_body) => {
                                let trailers = collected_body.trailers().cloned();
                                let body_bytes = collected_body.to_bytes();
                                (body_bytes, trailers)
                            }
                            Err(err) => {
                                let latency_us = started.elapsed().as_micros() as u64;
                                snap.lb.record_failure(&pool_name, &backend_id);
                                self.telemetry.record_replay(ReplayRecord {
                                    request_id: req_id,
                                    trace_id: trace_id.clone(),
                                    org_id: identity.org_id.clone(),
                                    workload_id: identity.workload_id.clone(),
                                    method: method.as_str().to_string(),
                                    path: path.clone(),
                                    route: route.id.clone(),
                                    upstream: backend_id.clone(),
                                    status: StatusCode::BAD_GATEWAY.as_u16(),
                                    shadow_status: None,
                                    reason: "upstream_transport_or_timeout".to_string(),
                                    latency_us,
                                });
                                return self.finish_error_with_cors(
                                    req_id,
                                    &trace_id,
                                    &identity.org_id,
                                    &identity.workload_id,
                                    &route.id,
                                    &backend_id,
                                    "ERROR",
                                    EdgeGateError::BadGateway(format!(
                                        "failed to read upstream response body: {err}"
                                    )),
                                    started,
                                    pre_matched_cors.as_ref(),
                                    origin_header.as_deref(),
                                );
                            }
                        }
                    };

                    if let Some(ref secret) = reflection_guard_secret {
                        let needle = secret.expose().as_bytes();
                        let body_reflected = body_bytes
                            .windows(needle.len())
                            .any(|window| window == needle);
                        let trailer_reflected = trailers.as_ref().is_some_and(|tr_map| {
                            tr_map
                                .values()
                                .any(|v| v.as_bytes().windows(needle.len()).any(|w| w == needle))
                        });
                        if body_reflected || trailer_reflected {
                            let latency_us = started.elapsed().as_micros() as u64;
                            self.telemetry.record_secret_reflection_blocked();
                            self.telemetry.record_replay(ReplayRecord {
                                request_id: req_id,
                                trace_id: trace_id.clone(),
                                org_id: identity.org_id.clone(),
                                workload_id: identity.workload_id.clone(),
                                method: method.as_str().to_string(),
                                path: path.clone(),
                                route: route.id.clone(),
                                upstream: backend_id.clone(),
                                status: StatusCode::BAD_GATEWAY.as_u16(),
                                shadow_status: None,
                                reason: "credential_reflection_blocked".to_string(),
                                latency_us,
                            });
                            return self.finish_error_with_cors(
                                req_id,
                                &trace_id,
                                &identity.org_id,
                                &identity.workload_id,
                                &route.id,
                                &backend_id,
                                "ERROR",
                                EdgeGateError::BadGateway(
                                    "upstream credential reflection blocked".to_string(),
                                ),
                                started,
                                pre_matched_cors.as_ref(),
                                origin_header.as_deref(),
                            );
                        }
                    }
                    Response::from_parts(
                        parts,
                        BufferedBodyWithTrailers {
                            data: Some(body_bytes),
                            trailers,
                        }
                        .boxed(),
                    )
                } else {
                    resp.map(|b| b.boxed())
                };

                let status = mapped.status();
                let latency_us = started.elapsed().as_micros() as u64;
                if status.is_server_error() {
                    snap.lb.record_failure(&pool_name, &backend_id);
                    self.telemetry.record_replay(ReplayRecord {
                        request_id: req_id,
                        trace_id: trace_id.clone(),
                        org_id: identity.org_id.clone(),
                        workload_id: identity.workload_id.clone(),
                        method: method.as_str().to_string(),
                        path: path.clone(),
                        route: route.id.clone(),
                        upstream: backend_id.clone(),
                        status: status.as_u16(),
                        shadow_status: None,
                        reason: "upstream_5xx".to_string(),
                        latency_us,
                    });
                } else {
                    snap.lb.record_success(&pool_name, &backend_id, latency_us);
                }

                // Step 7b: Non-blocking asynchronous traffic shadowing (`Milestone 3`).
                if let Some(ref shadow_pool_name) = route.shadow_pool {
                    self.spawn_shadow_dispatch(
                        Arc::clone(&snap),
                        req_id,
                        trace_id.clone(),
                        identity.org_id.clone(),
                        identity.workload_id.clone(),
                        method.clone(),
                        path.clone(),
                        route.id.clone(),
                        shadow_pool_name.clone(),
                        upstream_uri,
                        upstream_pq.clone(),
                        route.aws_sigv4.clone(),
                        outbound_headers,
                        collected,
                        status.as_u16(),
                    );
                }

                self.telemetry.record_request(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    &backend_id,
                    "ALLOWED",
                    status.as_u16(),
                    latency_us,
                );
                let (mut parts, body) = mapped.into_parts();
                for hdr_name in &route.strip_response_headers {
                    parts.headers.remove(hdr_name);
                }
                for (hdr_name, hdr_val) in &route.inject_response_headers {
                    parts.headers.insert(hdr_name.clone(), hdr_val.clone());
                }
                if let Ok(trace_val) = HeaderValue::from_str(&trace_id) {
                    parts
                        .headers
                        .insert(HeaderName::from_static(TRACE_ID_RESPONSE_HEADER), trace_val);
                }
                if let Some(ref cors) = route.cors {
                    attach_cors_headers(&mut parts.headers, cors, origin_header.as_deref());
                }
                let body = if !route.strip_response_headers.is_empty() {
                    let strip_headers = route.strip_response_headers.clone();
                    body.map_frame(move |mut frame| {
                        if let Some(trailers) = frame.trailers_mut() {
                            for hdr in &strip_headers {
                                trailers.remove(hdr);
                            }
                        }
                        frame
                    })
                    .boxed()
                } else {
                    body
                };
                let body = GuardedResponseBody {
                    inner: body,
                    _in_flight: in_flight_guard.take(),
                    _bulkhead: bulkhead_guard.take(),
                }
                .boxed();
                Response::from_parts(parts, body)
            }
            Err(err) => {
                let latency_us = started.elapsed().as_micros() as u64;
                match err {
                    EdgeGateError::BadGateway(_) | EdgeGateError::GatewayTimeout(_) => {
                        snap.lb.record_failure(&pool_name, &backend_id);
                        self.telemetry.record_replay(ReplayRecord {
                            request_id: req_id,
                            trace_id: trace_id.clone(),
                            org_id: identity.org_id.clone(),
                            workload_id: identity.workload_id.clone(),
                            method: method.as_str().to_string(),
                            path: path.clone(),
                            route: route.id.clone(),
                            upstream: backend_id.clone(),
                            status: err.status_code().as_u16(),
                            shadow_status: None,
                            reason: "upstream_transport_or_timeout".to_string(),
                            latency_us,
                        });
                    }
                    _ => {}
                }
                let decision = if matches!(err, EdgeGateError::Forbidden(_)) {
                    "BLOCKED"
                } else {
                    "ERROR"
                };
                self.finish_error_with_cors(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    &backend_id,
                    decision,
                    err,
                    started,
                    route.cors.as_ref(),
                    origin_header.as_deref(),
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_shadow_dispatch(
        &self,
        snap: Arc<RuntimeSnapshot>,
        req_id: u64,
        trace_id: String,
        org_id: String,
        workload_id: String,
        method: Method,
        path: String,
        route_id: String,
        shadow_pool_name: String,
        upstream_uri: Uri,
        upstream_pq: String,
        aws_sigv4: Option<CompiledAwsSigV4>,
        mut headers: HeaderMap,
        body_bytes: Bytes,
        primary_status: u16,
    ) {
        let telemetry = Arc::clone(&self.telemetry);
        tokio::spawn(async move {
            let started = Instant::now();
            let Ok(mut shadow_lease) = snap.lb.select(&shadow_pool_name) else {
                telemetry.record_shadow_outcome(false);
                return;
            };
            let shadow_backend_id = shadow_lease.backend.id.clone();
            if let Ok(host_val) = HeaderValue::from_str(&shadow_lease.backend.authority) {
                headers.insert(HOST, host_val);
            }
            if let Some(ref sigv4) = aws_sigv4 {
                if apply_aws_sigv4_headers(
                    &snap,
                    &org_id,
                    sigv4,
                    method.as_str(),
                    &upstream_pq,
                    &shadow_lease.backend.authority,
                    &body_bytes,
                    &mut headers,
                )
                .is_err()
                {
                    return;
                }
            }
            let Ok(mut shadow_req) = Request::builder()
                .method(method.clone())
                .uri(upstream_uri)
                .body(Full::new(body_bytes))
            else {
                return;
            };
            *shadow_req.headers_mut() = headers;

            shadow_lease.settle_probe();
            match snap.pool.send(shadow_lease, shadow_req).await {
                Ok(shadow_resp) => {
                    let shadow_code = shadow_resp.status().as_u16();
                    let _ = shadow_resp.into_body().collect().await;
                    let matched = shadow_code == primary_status;
                    telemetry.record_shadow_outcome(matched);
                    if !matched {
                        telemetry.record_replay(ReplayRecord {
                            request_id: req_id,
                            trace_id,
                            org_id,
                            workload_id,
                            method: method.as_str().to_string(),
                            path,
                            route: route_id,
                            upstream: shadow_backend_id,
                            status: primary_status,
                            shadow_status: Some(shadow_code),
                            reason: "shadow_status_mismatch".to_string(),
                            latency_us: started.elapsed().as_micros() as u64,
                        });
                    }
                }
                Err(_) => {
                    telemetry.record_shadow_outcome(false);
                    telemetry.record_replay(ReplayRecord {
                        request_id: req_id,
                        trace_id,
                        org_id,
                        workload_id,
                        method: method.as_str().to_string(),
                        path,
                        route: route_id,
                        upstream: shadow_backend_id,
                        status: primary_status,
                        shadow_status: Some(502),
                        reason: "shadow_transport_error".to_string(),
                        latency_us: started.elapsed().as_micros() as u64,
                    });
                }
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_error(
        &self,
        request_id: u64,
        trace_id: &str,
        org_id: &str,
        workload_id: &str,
        route: &str,
        upstream: &str,
        decision: &str,
        err: EdgeGateError,
        started: Instant,
    ) -> Response<ProxyBody> {
        self.finish_error_with_cors(
            request_id,
            trace_id,
            org_id,
            workload_id,
            route,
            upstream,
            decision,
            err,
            started,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_error_with_cors(
        &self,
        request_id: u64,
        trace_id: &str,
        org_id: &str,
        workload_id: &str,
        route: &str,
        upstream: &str,
        decision: &str,
        err: EdgeGateError,
        started: Instant,
        cors: Option<&CompiledCorsConfig>,
        origin_header: Option<&str>,
    ) -> Response<ProxyBody> {
        let status = err.status_code();
        let latency_us = started.elapsed().as_micros() as u64;
        self.telemetry.record_request(
            request_id,
            trace_id,
            org_id,
            workload_id,
            route,
            upstream,
            decision,
            status.as_u16(),
            latency_us,
        );
        let mut resp = json_error_response(status, &err.public_message());
        if let Ok(trace_val) = HeaderValue::from_str(trace_id) {
            resp.headers_mut()
                .insert(HeaderName::from_static(TRACE_ID_RESPONSE_HEADER), trace_val);
        }
        if let Some(cors) = cors {
            attach_cors_headers(resp.headers_mut(), cors, origin_header);
        }
        resp
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_aws_sigv4_headers(
    snap: &RuntimeSnapshot,
    org_id: &str,
    sigv4: &CompiledAwsSigV4,
    method_str: &str,
    upstream_pq: &str,
    authority: &str,
    payload: &[u8],
    headers: &mut HeaderMap,
) -> Result<(), EdgeGateError> {
    let access_key = snap.secrets.get_secret(org_id, &sigv4.access_key_ref)?;
    let secret_key = snap.secrets.get_secret(org_id, &sigv4.secret_key_ref)?;

    let unix_s = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };
    let (amz_date, date_stamp) = crate::config::format_amz_timestamps(unix_s);
    let (canon_path, canon_query) = match upstream_pq.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (upstream_pq, None),
    };

    let sig_headers = crate::config::compute_aws_sigv4_headers(
        access_key.expose(),
        secret_key.expose(),
        &sigv4.region,
        &sigv4.service,
        method_str,
        canon_path,
        canon_query,
        authority,
        payload,
        &amz_date,
        &date_stamp,
    );

    if let Ok(val) = HeaderValue::from_str(&sig_headers.amz_date) {
        headers.insert(HeaderName::from_static("x-amz-date"), val);
    }
    if let Ok(val) = HeaderValue::from_str(&sig_headers.content_sha256) {
        headers.insert(HeaderName::from_static("x-amz-content-sha256"), val);
    }
    if let Ok(val) = HeaderValue::from_str(&sig_headers.authorization) {
        headers.insert(http::header::AUTHORIZATION, val);
    }

    Ok(())
}

fn attach_cors_headers(
    headers: &mut HeaderMap,
    cors: &CompiledCorsConfig,
    origin_header: Option<&str>,
) {
    let has_origin_vary = headers
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|tok| tok.trim().eq_ignore_ascii_case("origin") || tok.trim() == "*");
    if !has_origin_vary {
        headers.append(http::header::VARY, HeaderValue::from_static("Origin"));
    }

    if let Some(orig) = origin_header {
        if cors.allowed_origins.contains(orig) {
            if let Ok(val) = HeaderValue::from_str(orig) {
                headers.insert(HeaderName::from_static("access-control-allow-origin"), val);
                if let Some(ref exp) = cors.expose_headers_value {
                    headers.insert(
                        HeaderName::from_static("access-control-expose-headers"),
                        exp.clone(),
                    );
                }
            }
        }
    }
}

fn verify_admin_token(snap: &RuntimeSnapshot, headers: &HeaderMap) -> Result<(), EdgeGateError> {
    let expected = snap.config.admin_token_digest.ok_or_else(|| {
        EdgeGateError::Unauthorized("admin control plane token not configured".to_string())
    })?;
    let header_val = headers
        .get(ADMIN_TOKEN_HEADER)
        .ok_or_else(|| EdgeGateError::Unauthorized("missing X-EdgeGate-Admin-Token".to_string()))?;
    let raw_token = header_val
        .to_str()
        .map_err(|_| EdgeGateError::Unauthorized("non-ASCII X-EdgeGate-Admin-Token".to_string()))?
        .trim();
    if raw_token.is_empty() {
        return Err(EdgeGateError::Unauthorized(
            "empty X-EdgeGate-Admin-Token".to_string(),
        ));
    }
    let candidate = sha256_digest(raw_token.as_bytes());
    if bool::from(expected.ct_eq(&candidate)) {
        Ok(())
    } else {
        Err(EdgeGateError::Unauthorized(
            "invalid X-EdgeGate-Admin-Token".to_string(),
        ))
    }
}

fn parse_rotate_secret_request(body_str: &str) -> Result<RotateSecretRequest, String> {
    if let Ok(req) = serde_json::from_str::<RotateSecretRequest>(body_str) {
        return Ok(req);
    }
    toml::from_str::<RotateSecretRequest>(body_str).map_err(|e| e.to_string())
}

fn json_error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let escaped = message.replace('\\', "\\\\").replace('"', "\\\"");
    let body = Bytes::from(format!(
        "{{\"error\":\"{escaped}\",\"status\":{}}}",
        status.as_u16()
    ));
    let mut resp = Response::new(Full::new(body).map_err(|never| match never {}).boxed());
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}
