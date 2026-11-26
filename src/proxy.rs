use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE, HOST, RETRY_AFTER};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use tokio::net::{TcpListener, UnixListener};
use tracing::{error, info, warn};

use crate::auth::{
    HeaderTokenAuthenticator, TransportBoundAuthenticator, WorkloadAuthenticator, WorkloadIdentity,
};
use crate::config::{CompiledConfig, CompiledWorkload};
use crate::lb::{LoadBalancer, PoolLoadBalancer};
use crate::policy::{DefaultDenyPolicyEngine, PolicyDecision, PolicyEngine};
use crate::pool::ConnectionPool;
use crate::router::{
    resolve_or_generate_traceparent, rewrite_upstream_path_and_query, sanitize_outbound_headers,
    validate_request_path, Router, TRACEPARENT_HEADER, TRACE_ID_RESPONSE_HEADER,
};
use crate::secrets::{MockSecretProvider, SecretProvider};
use crate::telemetry::{ReplayRecord, Telemetry};
use crate::EdgeGateError;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Optional routing-key header for `ConsistentHash` load balancing (`Milestone 3`).
pub const ROUTING_KEY_HEADER: &str = "x-edgegate-routing-key";

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

struct InFlightGuard<'a> {
    telemetry: &'a Telemetry,
}

impl<'a> InFlightGuard<'a> {
    fn new(telemetry: &'a Telemetry) -> Self {
        telemetry.inc_in_flight();
        Self { telemetry }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.telemetry.dec_in_flight();
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
        let auth = Arc::new(HeaderTokenAuthenticator::new(config.workloads.clone()));
        let policy = Arc::new(DefaultDenyPolicyEngine::new(config.policies.clone()));
        let secrets = Arc::new(MockSecretProvider::from_map(config.secrets.clone()));
        let router = Router::new(config.routes.clone());
        let lb = Arc::new(PoolLoadBalancer::from_pools(&config.pools));
        let pool = Arc::new(ConnectionPool::from_pools(
            &config.pools,
            config.connect_timeout,
            config.response_timeout,
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
}

impl EdgeGateProxy {
    pub fn new(config: Arc<CompiledConfig>) -> Self {
        let replay_cap = config.replay_buffer_size;
        let snapshot = Arc::new(RuntimeSnapshot::from_config(config));
        Self {
            runtime: Arc::new(ArcSwap::new(snapshot)),
            telemetry: Arc::new(Telemetry::with_replay_capacity(replay_cap)),
        }
    }

    pub fn telemetry(&self) -> Arc<Telemetry> {
        Arc::clone(&self.telemetry)
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
        let next = Arc::new(RuntimeSnapshot::from_config(compiled));
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
        let _in_flight_guard = InFlightGuard::new(&self.telemetry);
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
        if path == "/_edgegate/metrics" {
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
            let body = Bytes::from(self.telemetry.replay_to_json());
            let mut resp = Response::new(Full::new(body).map_err(|never| match never {}).boxed());
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            return resp;
        }

        let req_id = self.telemetry.next_request_id();
        let (traceparent, trace_id) = resolve_or_generate_traceparent(req.headers(), req_id);
        let snap = self.runtime.load_full();

        let method = req.method().clone();
        let path = path.to_string();
        let query = req.uri().query().map(ToString::to_string);
        let host_header = req
            .headers()
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let routing_key = req
            .headers()
            .get(ROUTING_KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        // Step 1: Fail-closed pre-policy path validation.
        if let Err(err) = validate_request_path(&path) {
            return self.finish_error(
                req_id, &trace_id, "-", "-", "-", "-", "BLOCKED", err, started,
            );
        }

        // Step 2: Authenticate workload (transport-bound UDS identity OR X-EdgeGate-Token header).
        let identity: WorkloadIdentity = match transport_auth {
            Some(ta) => match ta.authenticate(req.headers()) {
                Ok(id) => id,
                Err(err) => {
                    return self.finish_error(
                        req_id, &trace_id, "-", "-", "-", "-", "BLOCKED", err, started,
                    );
                }
            },
            None => match snap.auth.authenticate(req.headers()) {
                Ok(id) => id,
                Err(err) => {
                    return self.finish_error(
                        req_id, &trace_id, "-", "-", "-", "-", "BLOCKED", err, started,
                    );
                }
            },
        };

        // Step 3: Match explicit route (default-deny unmatched destination).
        let route = match snap.router.match_route(&path, host_header.as_deref()) {
            Some(r) => r.clone(),
            None => {
                return self.finish_error(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    "-",
                    "-",
                    "BLOCKED",
                    EdgeGateError::Forbidden(format!("default-deny: no route matches '{path}'")),
                    started,
                );
            }
        };

        // Step 4: Evaluate default-deny org_id/workload/roles/route/method/path policy + rate limit.
        match snap.policy.evaluate(&identity, &route.id, &method, &path) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny { reason } => {
                return self.finish_error(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    "-",
                    "BLOCKED",
                    EdgeGateError::Forbidden(reason),
                    started,
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
                let mut resp = self.finish_error(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    "-",
                    "RATE_LIMITED",
                    EdgeGateError::TooManyRequests(reason),
                    started,
                );
                resp.headers_mut()
                    .insert(RETRY_AFTER, HeaderValue::from_static("1"));
                return resp;
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
                return self.finish_error(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    "-",
                    "ERROR",
                    err,
                    started,
                );
            }
        };
        let backend_id = lease.backend.id.clone();
        let backend_authority = lease.backend.authority.clone();
        let pool_name = lease.pool_name.clone();

        // Step 6: Sanitize outbound headers, propagate W3C traceparent, and inject scoped upstream credential.
        let target_cred_header = route.credential.as_ref().map(|c| &c.header_name);
        let mut outbound_headers = match sanitize_outbound_headers(
            req.headers(),
            &backend_authority,
            target_cred_header,
        ) {
            Ok(h) => h,
            Err(err) => {
                return self.finish_error(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    &backend_id,
                    "ERROR",
                    err,
                    started,
                );
            }
        };
        if let Ok(tp_val) = HeaderValue::from_str(&traceparent) {
            outbound_headers.insert(HeaderName::from_static(TRACEPARENT_HEADER), tp_val);
        }

        let mut reflection_guard_secret = None;
        if let Some(ref binding) = route.credential {
            let secret = match snap
                .secrets
                .get_secret(&identity.org_id, &binding.credential_ref)
            {
                Ok(s) => s,
                Err(err) => {
                    return self.finish_error(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        &backend_id,
                        "BLOCKED",
                        err,
                        started,
                    );
                }
            };
            let injected_str = format!("{}{}", binding.value_prefix, secret.expose());
            let header_val = match HeaderValue::from_str(&injected_str) {
                Ok(v) => v,
                Err(_) => {
                    return self.finish_error(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        &backend_id,
                        "ERROR",
                        EdgeGateError::Internal("invalid credential header value".to_string()),
                        started,
                    );
                }
            };
            outbound_headers.insert(binding.header_name.clone(), header_val);
            if binding.block_secret_reflection && !secret.expose().is_empty() {
                reflection_guard_secret = Some(secret);
            }
        }

        let max_body = snap.config.max_request_body_bytes;
        let collected = match Limited::new(req.into_body(), max_body).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return self.finish_error(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    &backend_id,
                    "BLOCKED",
                    EdgeGateError::PayloadTooLarge(format!(
                        "request body exceeds limit of {max_body} bytes"
                    )),
                    started,
                );
            }
        };

        let upstream_pq = rewrite_upstream_path_and_query(&path, query.as_deref(), &route);
        let upstream_uri = match Uri::builder().path_and_query(upstream_pq.as_str()).build() {
            Ok(u) => u,
            Err(err) => {
                return self.finish_error(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    &backend_id,
                    "ERROR",
                    EdgeGateError::BadRequest(format!("invalid rewritten URI: {err}")),
                    started,
                );
            }
        };

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
                    return self.finish_error(
                        req_id,
                        &trace_id,
                        &identity.org_id,
                        &identity.workload_id,
                        &route.id,
                        &backend_id,
                        "ERROR",
                        EdgeGateError::Internal(format!("failed to build upstream request: {err}")),
                        started,
                    );
                }
            };
            *outbound_req.headers_mut() = outbound_headers.clone();

            lease.settle_probe();
            match snap.pool.send(lease, outbound_req).await {
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
                    lease = next_lease;
                }
                Err(err) => break Err(err),
            }
        };

        match send_res {
            Ok(resp) => {
                // Step 7a: Response Credential Reflection Guard (`Milestone 5`).
                let mapped = if let Some(ref secret) = reflection_guard_secret {
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
                        return self.finish_error(
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
                        );
                    }

                    let (parts, incoming_body) = resp.into_parts();
                    let body_bytes = match incoming_body.collect().await {
                        Ok(c) => c.to_bytes(),
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
                            return self.finish_error(
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
                            );
                        }
                    };
                    let body_reflected = body_bytes
                        .windows(needle.len())
                        .any(|window| window == needle);
                    if body_reflected {
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
                        return self.finish_error(
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
                        );
                    }
                    Response::from_parts(
                        parts,
                        Full::new(body_bytes)
                            .map_err(|never| match never {})
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
                let mut mapped = mapped;
                if let Ok(trace_val) = HeaderValue::from_str(&trace_id) {
                    mapped
                        .headers_mut()
                        .insert(HeaderName::from_static(TRACE_ID_RESPONSE_HEADER), trace_val);
                }
                mapped
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
                self.finish_error(
                    req_id,
                    &trace_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    &backend_id,
                    decision,
                    err,
                    started,
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
        resp
    }
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
