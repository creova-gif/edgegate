use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{HeaderValue, CONTENT_TYPE, HOST};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, UnixListener};
use tracing::{error, info, warn};

use crate::auth::{
    HeaderTokenAuthenticator, TransportBoundAuthenticator, WorkloadAuthenticator, WorkloadIdentity,
};
use crate::config::CompiledConfig;
use crate::lb::{LoadBalancer, PoolLoadBalancer};
use crate::policy::{DefaultDenyPolicyEngine, PolicyDecision, PolicyEngine};
use crate::pool::ConnectionPool;
use crate::router::{
    rewrite_upstream_path_and_query, sanitize_outbound_headers, validate_request_path, Router,
};
use crate::secrets::{MockSecretProvider, SecretProvider};
use crate::telemetry::Telemetry;
use crate::EdgeGateError;

// EdgeGate Milestone 1 + 2 linear L7 security & proxy pipeline:
//
//   HTTP/1.1 Request (hyper v1 over TCP or zero-token Unix domain socket)
//     0. Built-in /_edgegate/healthz & /_edgegate/metrics probes
//     1. validate_request_path()            ──► 400 (dot-segments, \, %00, //)
//     2. resolve WorkloadIdentity           ──► 401 (UDS transport identity OR X-EdgeGate-Token)
//     3. router.match_route(path, host)     ──► 403 (default-deny unmatched destination)
//     4. policy.evaluate(id, route, m, p)   ──► 403 (default-deny org_id / roles / method / prefix)
//     5. lb.select(&route.pool)             ──► 503 (all backends unhealthy or in failure cooldown)
//     6. sanitize_outbound_headers() + inject SecretProvider scoped credential
//     7. pool.send(lease, outbound_req)     ──► 503 pool full (NO LB ejection)
//                                           ──► 502/504/5xx (record passive LB failure)
//                                           ──► 3xx returned verbatim (NEVER auto-followed)
//     8. telemetry.record_request()         ──► structured JSON audit log (zero secrets)

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Immutable runtime snapshot stored behind `ArcSwap` for lock-free hot-path reads
/// and atomic zero-downtime config reloads (`Milestone 2`).
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

/// Core EdgeGate reverse proxy server.
pub struct EdgeGateProxy {
    runtime: Arc<ArcSwap<RuntimeSnapshot>>,
    telemetry: Arc<Telemetry>,
}

impl EdgeGateProxy {
    pub fn new(config: Arc<CompiledConfig>) -> Self {
        let snapshot = Arc::new(RuntimeSnapshot::from_config(config));
        Self {
            runtime: Arc::new(ArcSwap::new(snapshot)),
            telemetry: Arc::new(Telemetry::new()),
        }
    }

    pub fn telemetry(&self) -> Arc<Telemetry> {
        Arc::clone(&self.telemetry)
    }

    /// Atomically reloads configuration from disk without dropping in-flight requests.
    /// Fails safe: if parsing or validation fails, the existing snapshot stays active.
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

    /// Binds and serves zero-token Unix domain socket listeners configured in `server.unix_listeners`.
    pub fn spawn_unix_listeners(
        self: &Arc<Self>,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, EdgeGateError> {
        let snap = self.runtime.load();
        let mut handles = Vec::with_capacity(snap.config.unix_listeners.len());

        for uds_cfg in &snap.config.unix_listeners {
            if uds_cfg.path.exists() {
                let _ = std::fs::remove_file(&uds_cfg.path);
            }
            let listener = UnixListener::bind(&uds_cfg.path).map_err(|e| {
                EdgeGateError::Internal(format!(
                    "failed to bind unix_listener '{}': {e}",
                    uds_cfg.path.display()
                ))
            })?;
            info!(
                socket_path = %uds_cfg.path.display(),
                workload_id = %uds_cfg.workload.workload_id,
                org_id = %uds_cfg.workload.org_id,
                "edgegate_unix_listener_bound"
            );

            let auth = Arc::new(TransportBoundAuthenticator::new(uds_cfg.workload.clone()));
            let proxy = Arc::clone(self);
            handles.push(tokio::spawn(async move {
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
                        let _ = http1::Builder::new()
                            .keep_alive(true)
                            .serve_connection(io, service)
                            .await;
                    });
                }
            }));
        }

        Ok(handles)
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
                    let io = TokioIo::new(stream);
                    let proxy = Arc::clone(&self);
                    tokio::spawn(async move {
                        let service = service_fn(move |req: Request<Incoming>| {
                            let proxy = Arc::clone(&proxy);
                            async move { Ok::<_, std::convert::Infallible>(proxy.handle_request(req).await) }
                        });
                        if let Err(err) = http1::Builder::new()
                            .keep_alive(true)
                            .serve_connection(io, service)
                            .await
                        {
                            error!(error = %err, "edgegate_connection_error");
                        }
                    });
                }
            }
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
        let started = Instant::now();
        let path = req.uri().path();

        // Step 0: Built-in observability endpoints.
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
            let body = Bytes::from(self.telemetry.to_json());
            let mut resp = Response::new(Full::new(body).map_err(|never| match never {}).boxed());
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            return resp;
        }

        let req_id = self.telemetry.next_request_id();
        let snap = self.runtime.load();

        let method = req.method().clone();
        let path = path.to_string();
        let query = req.uri().query().map(ToString::to_string);
        let host_header = req
            .headers()
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        // Step 1: Fail-closed pre-policy path validation.
        if let Err(err) = validate_request_path(&path) {
            return self.finish_error(req_id, "-", "-", "-", "-", "BLOCKED", err, started);
        }

        // Step 2: Authenticate workload (transport-bound UDS identity OR X-EdgeGate-Token header).
        let identity: WorkloadIdentity = match transport_auth {
            Some(ta) => match ta.authenticate(req.headers()) {
                Ok(id) => id,
                Err(err) => {
                    return self.finish_error(req_id, "-", "-", "-", "-", "BLOCKED", err, started);
                }
            },
            None => match snap.auth.authenticate(req.headers()) {
                Ok(id) => id,
                Err(err) => {
                    return self.finish_error(req_id, "-", "-", "-", "-", "BLOCKED", err, started);
                }
            },
        };

        // Step 3: Match explicit route (default-deny unmatched destination).
        let route = match snap.router.match_route(&path, host_header.as_deref()) {
            Some(r) => r.clone(),
            None => {
                return self.finish_error(
                    req_id,
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

        // Step 4: Evaluate default-deny org_id/workload/roles/route/method/path policy.
        if let PolicyDecision::Deny { reason } =
            snap.policy.evaluate(&identity, &route.id, &method, &path)
        {
            return self.finish_error(
                req_id,
                &identity.org_id,
                &identity.workload_id,
                &route.id,
                "-",
                "BLOCKED",
                EdgeGateError::Forbidden(reason),
                started,
            );
        }

        // Step 5: Select healthy backend via LoadBalancer.
        let lease = match snap.lb.select(&route.pool) {
            Ok(l) => l,
            Err(err) => {
                return self.finish_error(
                    req_id,
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

        // Step 6: Sanitize outbound headers and inject scoped upstream credential.
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

        if let Some(ref binding) = route.credential {
            let secret = match snap
                .secrets
                .get_secret(&identity.org_id, &binding.credential_ref)
            {
                Ok(s) => s,
                Err(err) => {
                    return self.finish_error(
                        req_id,
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
        }

        let max_body = snap.config.max_request_body_bytes;
        let collected = match Limited::new(req.into_body(), max_body).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return self.finish_error(
                    req_id,
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

        let mut outbound_req = match Request::builder()
            .method(method)
            .uri(upstream_uri)
            .body(Full::new(collected))
        {
            Ok(r) => r,
            Err(err) => {
                return self.finish_error(
                    req_id,
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
        *outbound_req.headers_mut() = outbound_headers;

        // Step 7: Forward through bounded single-flight pool (NO 3xx auto-follow, NO auto-retry).
        match snap.pool.send(lease, outbound_req).await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() {
                    snap.lb.record_failure(&pool_name, &backend_id);
                } else {
                    snap.lb.record_success(&pool_name, &backend_id);
                }
                let latency_us = started.elapsed().as_micros() as u64;
                self.telemetry.record_request(
                    req_id,
                    &identity.org_id,
                    &identity.workload_id,
                    &route.id,
                    &backend_id,
                    "ALLOWED",
                    status.as_u16(),
                    latency_us,
                );
                resp.map(|b| b.boxed())
            }
            Err(err) => {
                match err {
                    EdgeGateError::BadGateway(_) | EdgeGateError::GatewayTimeout(_) => {
                        snap.lb.record_failure(&pool_name, &backend_id);
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
    fn finish_error(
        &self,
        request_id: u64,
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
            org_id,
            workload_id,
            route,
            upstream,
            decision,
            status.as_u16(),
            latency_us,
        );
        json_error_response(status, &err.public_message())
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
