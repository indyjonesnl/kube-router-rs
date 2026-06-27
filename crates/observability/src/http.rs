//! Minimal HTTP/1.1 server for the `/healthz` and `/metrics` endpoints.
//!
//! Dependency-light (std/tokio only) responder: it reads the request line,
//! routes by path, and writes a `Connection: close` response. Sufficient for the
//! liveness probe and Prometheus scrape surfaces the Go upstream exposes.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::health::HealthState;
use crate::metrics::Metrics;

/// A simple HTTP response.
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Content-Type header value.
    pub content_type: &'static str,
    /// Body.
    pub body: String,
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Extract the request path from a raw request, if parseable.
pub fn parse_path(req: &str) -> Option<&str> {
    let line = req.lines().next()?;
    let mut parts = line.split_whitespace();
    let _method = parts.next()?;
    parts.next()
}

/// Bind a TCP listener for the server.
pub async fn bind(addr: &str) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

async fn handle_conn<H>(mut stream: TcpStream, handler: Arc<H>)
where
    H: Fn(&str) -> Response + Send + Sync + 'static,
{
    let mut buf = [0u8; 2048];
    let n = match stream.read(&mut buf).await {
        Ok(n) => n,
        Err(_) => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = parse_path(&req).unwrap_or("/");
    let resp = handler(path);
    let out = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        resp.status,
        reason(resp.status),
        resp.content_type,
        resp.body.len(),
        resp.body
    );
    let _ = stream.write_all(out.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Run an accept loop on `listener`, dispatching each connection to `handler`.
/// Runs until the task is cancelled (e.g. on shutdown).
pub async fn serve<H>(listener: TcpListener, handler: H)
where
    H: Fn(&str) -> Response + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    while let Ok((stream, _)) = listener.accept().await {
        let h = handler.clone();
        tokio::spawn(handle_conn(stream, h));
    }
}

/// Build the `/healthz` handler over shared health state.
pub fn health_handler(
    state: Arc<Mutex<HealthState>>,
) -> impl Fn(&str) -> Response + Send + Sync + 'static {
    move |path: &str| {
        if path.starts_with("/healthz") {
            let (status, body) = state.lock().unwrap().healthz_response(Instant::now());
            Response {
                status,
                content_type: "text/plain",
                body: body.to_string(),
            }
        } else {
            Response {
                status: 404,
                content_type: "text/plain",
                body: "not found".to_string(),
            }
        }
    }
}

/// Build the metrics handler serving `metrics_path`.
pub fn metrics_handler(
    metrics: Arc<Metrics>,
    metrics_path: String,
) -> impl Fn(&str) -> Response + Send + Sync + 'static {
    move |path: &str| {
        if path == metrics_path {
            Response {
                status: 200,
                content_type: "text/plain; version=0.0.4",
                body: metrics.gather(),
            }
        } else {
            Response {
                status: 404,
                content_type: "text/plain",
                body: "not found".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::health::Component;

    async fn get(addr: &str, path: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn parses_request_path() {
        assert_eq!(parse_path("GET /healthz HTTP/1.1\r\n"), Some("/healthz"));
        assert_eq!(parse_path("GET /metrics HTTP/1.1"), Some("/metrics"));
        assert_eq!(parse_path(""), None);
    }

    #[tokio::test]
    async fn healthz_serves_200_when_healthy() {
        let state = Arc::new(Mutex::new(HealthState::new()));
        state.lock().unwrap().register(
            Component::NetworkRoutes,
            Duration::from_secs(60),
            Instant::now(),
        );
        let listener = bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(serve(listener, health_handler(state)));

        let resp = get(&addr, "/healthz").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("OK"));
    }

    #[tokio::test]
    async fn metrics_serves_build_info() {
        let metrics = Arc::new(Metrics::new("0.1.0-test"));
        let listener = bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(serve(
            listener,
            metrics_handler(metrics, "/metrics".to_string()),
        ));

        let resp = get(&addr, "/metrics").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("kube_router_build_info"));

        let nf = get(&addr, "/wrong").await;
        assert!(nf.starts_with("HTTP/1.1 404"));
    }
}
