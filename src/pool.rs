use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::CONNECTION;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::CompiledPool;
use crate::lb::BackendLease;
use crate::EdgeGateError;

// Single-flight HTTP/1.1 connection pool lifecycle:
//
//   acquire Semaphore permit (bounded; try_acquire -> 503 local backpressure, NO LB ejection)
//        │
//        ▼
//   pop idle SendRequest (discard expired idle_ttl or sender.is_closed())
//        ├── hit  ──► poll_ready()
//        └── miss ──► lookup_host -> validate EVERY IPv4/IPv6/::ffff: IP -> TcpStream::connect(validated_addr)
//                                  -> hyper http1::handshake -> spawn conn driver
//        │
//        ▼
//   sender.send_request(req) (with response_timeout; NO auto-retry, NO 3xx auto-follow)
//        │
//        ▼
//   wrap Incoming body in PooledBody { inner, state: Some(PoolReturnState) }
//        ├── poll_frame sees None (EOF) + !Connection:close + sender.is_ready()
//        │        ──► push SendRequest back to idle VecDeque; drop permit & LB lease
//        └── error / client drop / partial drain / Connection:close
//                 ──► Drop discards SendRequest (closes socket) & releases permit + LB lease

#[derive(Debug)]
struct IdleConn {
    sender: SendRequest<Full<Bytes>>,
    returned_at: Instant,
}

#[derive(Debug)]
struct UpstreamSlot {
    semaphore: Arc<Semaphore>,
    idle: Arc<Mutex<VecDeque<IdleConn>>>,
    idle_ttl: Duration,
}

impl UpstreamSlot {
    fn new(max_conns: usize, idle_ttl: Duration) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_conns)),
            idle: Arc::new(Mutex::new(VecDeque::new())),
            idle_ttl,
        }
    }

    fn pop_fresh_idle(&self) -> Option<SendRequest<Full<Bytes>>> {
        let now = Instant::now();
        let mut guard = match self.idle.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        while let Some(conn) = guard.pop_front() {
            if now.saturating_duration_since(conn.returned_at) > self.idle_ttl {
                continue;
            }
            if conn.sender.is_closed() {
                continue;
            }
            return Some(conn.sender);
        }
        None
    }
}

struct PoolReturnState {
    sender: SendRequest<Full<Bytes>>,
    idle_queue: Arc<Mutex<VecDeque<IdleConn>>>,
    connection_close: bool,
    _permit: OwnedSemaphorePermit,
    _lb_lease: BackendLease,
}

pin_project! {
    /// Streams an upstream `hyper::body::Incoming` response while holding the single-flight
    /// `SendRequest`, pool semaphore permit, and LB `BackendLease`.
    /// Returns the `SendRequest` to the idle queue ONLY after full EOF drain.
    pub struct PooledBody {
        #[pin]
        inner: Incoming,
        state: Option<PoolReturnState>,
    }
}

impl PooledBody {
    fn try_return_clean(&mut self) {
        if let Some(state) = self.state.take() {
            if !state.connection_close && !state.sender.is_closed() && state.sender.is_ready() {
                let mut guard = match state.idle_queue.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                guard.push_back(IdleConn {
                    sender: state.sender,
                    returned_at: Instant::now(),
                });
            }
            // `_permit` and `_lb_lease` drop here, releasing pool capacity and LB in-flight count.
        }
    }

    fn discard_dirty(&mut self) {
        // Dropping `state` drops `sender` (closing the TCP socket) and releases permit + LB lease.
        self.state = None;
    }
}

impl Body for PooledBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                // Full EOF reached cleanly.
                if let Some(state) = this.state.take() {
                    if !state.connection_close
                        && !state.sender.is_closed()
                        && state.sender.is_ready()
                    {
                        let mut guard = match state.idle_queue.lock() {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        guard.push_back(IdleConn {
                            sender: state.sender,
                            returned_at: Instant::now(),
                        });
                    }
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(err))) => {
                *this.state = None;
                Poll::Ready(Some(Err(err)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Bounded per-upstream HTTP/1.1 connection pool with resolve-validate-connect SSRF protection.
#[derive(Debug)]
pub struct ConnectionPool {
    slots: HashMap<(String, String), UpstreamSlot>,
    connect_timeout: Duration,
    response_timeout: Duration,
}

impl ConnectionPool {
    pub fn from_pools(
        compiled: &HashMap<String, CompiledPool>,
        connect_timeout: Duration,
        response_timeout: Duration,
    ) -> Self {
        let mut slots = HashMap::new();
        for (pool_name, pool) in compiled {
            for backend in &pool.backends {
                slots.insert(
                    (pool_name.clone(), backend.id.clone()),
                    UpstreamSlot::new(pool.max_connections_per_upstream, pool.idle_ttl),
                );
            }
        }
        Self {
            slots,
            connect_timeout,
            response_timeout,
        }
    }

    /// Sends one HTTP/1.1 request to the leased backend.
    /// - Returns `EdgeGateError::PoolExhausted` (`503`, must NOT trigger passive LB ejection) when bounded capacity is full.
    /// - Returns `EdgeGateError::BadGateway` (`502`) on SSRF block or connect/transport error.
    /// - Returns `EdgeGateError::GatewayTimeout` (`504`) on connect or response-header timeout.
    pub async fn send(
        &self,
        lease: BackendLease,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<PooledBody>, EdgeGateError> {
        let key = (lease.pool_name.clone(), lease.backend.id.clone());
        let slot = self.slots.get(&key).ok_or_else(|| {
            EdgeGateError::BadGateway(format!(
                "no connection slot for pool '{}' backend '{}'",
                lease.pool_name, lease.backend.id
            ))
        })?;

        let permit = slot.semaphore.clone().try_acquire_owned().map_err(|_| {
            EdgeGateError::PoolExhausted(format!(
                "connection pool exhausted for pool '{}' backend '{}'",
                lease.pool_name, lease.backend.id
            ))
        })?;

        let mut sender = match slot.pop_fresh_idle() {
            Some(idle_sender) => idle_sender,
            None => {
                self.dial_validated(
                    &lease.backend.host,
                    lease.backend.port,
                    lease.allow_private_ip,
                )
                .await?
            }
        };

        // Ensure single-flight SendRequest is ready before dispatching.
        if tokio::time::timeout(self.connect_timeout, sender.ready())
            .await
            .map_err(|_| {
                EdgeGateError::GatewayTimeout("upstream connection readiness timeout".to_string())
            })?
            .is_err()
        {
            // Idle socket closed right before use: dial one fresh validated connection
            // (no bytes were written to the wire yet).
            sender = self
                .dial_validated(
                    &lease.backend.host,
                    lease.backend.port,
                    lease.allow_private_ip,
                )
                .await?;
            tokio::time::timeout(self.connect_timeout, sender.ready())
                .await
                .map_err(|_| {
                    EdgeGateError::GatewayTimeout(
                        "fresh upstream connection readiness timeout".to_string(),
                    )
                })?
                .map_err(|e| {
                    EdgeGateError::BadGateway(format!("upstream connection not ready: {e}"))
                })?;
        }

        let response = tokio::time::timeout(self.response_timeout, sender.send_request(request))
            .await
            .map_err(|_| EdgeGateError::GatewayTimeout("upstream response timeout".to_string()))?
            .map_err(|e| EdgeGateError::BadGateway(format!("upstream transport error: {e}")))?;

        let connection_close = response
            .headers()
            .get_all(CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| {
                v.split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("close"))
            });

        let (parts, incoming) = response.into_parts();
        let mut pooled_body = PooledBody {
            inner: incoming,
            state: Some(PoolReturnState {
                sender,
                idle_queue: Arc::clone(&slot.idle),
                connection_close,
                _permit: permit,
                _lb_lease: lease,
            }),
        };

        // If the response has an empty body already at EOF, return the connection immediately.
        if pooled_body.inner.is_end_stream() {
            if connection_close {
                pooled_body.discard_dirty();
            } else {
                pooled_body.try_return_clean();
            }
        }

        Ok(Response::from_parts(parts, pooled_body))
    }

    async fn dial_validated(
        &self,
        host: &str,
        port: u16,
        allow_private_ip: bool,
    ) -> Result<SendRequest<Full<Bytes>>, EdgeGateError> {
        let validated_addr = resolve_and_validate_addr(host, port, allow_private_ip).await?;
        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect(validated_addr))
            .await
            .map_err(|_| EdgeGateError::GatewayTimeout("upstream TCP connect timeout".to_string()))?
            .map_err(|e| EdgeGateError::BadGateway(format!("upstream TCP connect failed: {e}")))?;

        let _ = stream.set_nodelay(true);
        let io = TokioIo::new(stream);
        let (sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| EdgeGateError::BadGateway(format!("HTTP/1.1 handshake failed: {e}")))?;

        tokio::spawn(async move {
            let _ = conn.await;
        });

        Ok(sender)
    }
}

/// Resolve-validate-connect SSRF guard:
/// Resolves `host:port`, checks EVERY resolved IPv4, IPv6, and unwrapped IPv4-mapped IPv6
/// address against the SSRF blocklist unless `allow_private_ip` is explicitly `true`,
/// and returns the validated `SocketAddr` to dial directly (preventing DNS-rebinding TOCTOU).
pub async fn resolve_and_validate_addr(
    host: &str,
    port: u16,
    allow_private_ip: bool,
) -> Result<SocketAddr, EdgeGateError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_private_ip && is_blocked_ip(ip) {
            return Err(EdgeGateError::Forbidden(format!(
                "SSRF guard blocked upstream IP '{ip}'"
            )));
        }
        return Ok(SocketAddr::new(ip, port));
    }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| EdgeGateError::BadGateway(format!("DNS resolution failed for '{host}': {e}")))?
        .collect();

    if addrs.is_empty() {
        return Err(EdgeGateError::BadGateway(format!(
            "DNS resolution returned zero addresses for '{host}'"
        )));
    }

    if !allow_private_ip {
        for addr in &addrs {
            if is_blocked_ip(addr.ip()) {
                return Err(EdgeGateError::Forbidden(format!(
                    "SSRF guard blocked resolved IP '{}' for host '{host}'",
                    addr.ip()
                )));
            }
        }
    }

    Ok(addrs[0])
}

/// Returns `true` if `ip` belongs to loopback, private RFC1918, link-local/cloud metadata,
/// CGNAT, unspecified, broadcast, IPv6 ULA/link-local, or IPv4-mapped IPv6 targeting any of those.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn is_blocked_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 169 && o[1] == 254) // 169.254.0.0/16 cloud metadata / link-local
}

fn is_blocked_ipv6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_blocked_ipv4(mapped);
    }
    let segs = v6.segments();
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || (segs[0] & 0xfe00) == 0xfc00 // fc00::/7 Unique Local
        || (segs[0] & 0xffc0) == 0xfe80 // fe80::/10 Link-Local
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_ipv4_ipv6_and_ipv4_mapped_metadata_and_private_ranges() {
        let blocked = [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.10",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ];
        for s in blocked {
            let ip: IpAddr = s.parse().unwrap_or_else(|e| panic!("parse {s}: {e}"));
            assert!(is_blocked_ip(ip), "expected SSRF guard to block {s}");
        }

        let allowed = [
            "93.184.216.34",
            "1.1.1.1",
            "2606:2800:220:1:248:1893:25c8:1946",
        ];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap_or_else(|e| panic!("parse {s}: {e}"));
            assert!(!is_blocked_ip(ip), "expected SSRF guard to allow {s}");
        }
    }
}
