use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use edgegate::config::CompiledConfig;
use edgegate::proxy::EdgeGateProxy;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

async fn spawn_fast_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind backend: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("backend addr: {e}"));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = server_http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

async fn run_load(
    target: std::net::SocketAddr,
    workers: usize,
    requests_per_worker: usize,
    with_token: bool,
) -> (f64, u64, u64, u64) {
    let started = Instant::now();
    let mut handles = Vec::with_capacity(workers);

    for _ in 0..workers {
        handles.push(tokio::spawn(async move {
            let stream = TcpStream::connect(target)
                .await
                .unwrap_or_else(|e| panic!("connect: {e}"));
            let _ = stream.set_nodelay(true);
            let io = TokioIo::new(stream);
            let (mut sender, conn) = client_http1::handshake(io)
                .await
                .unwrap_or_else(|e| panic!("handshake: {e}"));
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let mut latencies_us = Vec::with_capacity(requests_per_worker);
            for _ in 0..requests_per_worker {
                let mut builder = Request::builder().method("GET").uri("/v1/bench/ping");
                if with_token {
                    builder = builder.header("x-edgegate-token", "bench-token");
                }
                let req = builder
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|e| panic!("req: {e}"));
                let t0 = Instant::now();
                let resp = sender
                    .send_request(req)
                    .await
                    .unwrap_or_else(|e| panic!("send: {e}"));
                let _ = resp
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_else(|e| panic!("body: {e}"));
                latencies_us.push(t0.elapsed().as_micros() as u64);
            }
            latencies_us
        }));
    }

    let mut all = Vec::with_capacity(workers * requests_per_worker);
    for h in handles {
        let mut part = h.await.unwrap_or_else(|e| panic!("worker join: {e}"));
        all.append(&mut part);
    }
    let elapsed = started.elapsed().as_secs_f64();
    all.sort_unstable();
    let n = all.len();
    let p50 = all[n / 2];
    let p95 = all[(n * 95) / 100];
    let p99 = all[(n * 99) / 100];
    let rps = (n as f64) / elapsed;
    (rps, p50, p95, p99)
}

#[tokio::main]
async fn main() {
    let b1 = spawn_fast_backend().await;
    let b2 = spawn_fast_backend().await;

    let toml_cfg = format!(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[[workloads]]
workload_id = "bench-agent"
org_id = "org-bench"
token = "bench-token"

[[pools]]
name = "bench-pool"
strategy = "round_robin"
max_connections_per_upstream = 128
allow_private_ip = true
backends = [
  {{ id = "b1", address = "{b1}" }},
  {{ id = "b2", address = "{b2}" }},
]

[[routes]]
id = "bench"
path_prefix = "/v1/bench"
strip_prefix = true
pool = "bench-pool"
[routes.credential]
credential_ref = "bench_key"
header_name = "Authorization"
value_prefix = "Bearer "

[[policies]]
org_id = "org-bench"
route_id = "bench"
methods = ["GET"]
path_prefix = "/v1/bench"

[[secrets]]
org_id = "org-bench"
credential_ref = "bench_key"
value = "bench_secret_value"
"#
    );

    let compiled =
        CompiledConfig::from_toml_str(&toml_cfg).unwrap_or_else(|e| panic!("config: {e}"));
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

    let workers = 32;
    let reqs_per_worker = 500; // 16,000 total requests

    let (direct_rps, d_p50, d_p95, d_p99) = run_load(b1, workers, reqs_per_worker, false).await;
    let (proxy_rps, p_p50, p_p95, p_p99) = run_load(gw_addr, workers, reqs_per_worker, true).await;

    println!("=== EdgeGate Local Reproducible Benchmark ({workers} workers x {reqs_per_worker} reqs) ===");
    println!(
        "Direct backend : {direct_rps:>10.1} req/s | p50={d_p50}us p95={d_p95}us p99={d_p99}us"
    );
    println!(
        "Via EdgeGate   : {proxy_rps:>10.1} req/s | p50={p_p50}us p95={p_p95}us p99={p_p99}us"
    );
    println!(
        "Added p95 overhead: {}us ({:.3}ms)",
        p_p95.saturating_sub(d_p95),
        (p_p95.saturating_sub(d_p95)) as f64 / 1000.0
    );
}
