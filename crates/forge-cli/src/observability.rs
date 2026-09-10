//! Opt-in observability for the gateway process.
//!
//! A tiny HTTP/1.1 listener (no extra web framework) serves:
//! - `GET /health` — liveness JSON (`status`, `version`, live manifest counts)
//! - `GET /metrics` — Prometheus text (when the `metrics` feature is on)
//!
//! Disabled unless `observability.listen` or `FORGE_OBSERVABILITY_LISTEN` is set.
//! Binding is intentional: this is a side channel, not the MCP transport.

#[cfg(feature = "metrics")]
use std::sync::Arc;

use anyhow::{Context, Result};
use forge_manifest::LiveManifest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Shared process snapshot for `/health`.
#[derive(Clone)]
pub struct HealthState {
    /// Live capability manifest (lock-free reads).
    pub manifest: LiveManifest,
}

/// Decision for a single HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: &'static str,
    /// Content-Type header value.
    pub content_type: &'static str,
    /// Response body.
    pub body: String,
}

impl HttpResponse {
    fn new(
        status: u16,
        reason: &'static str,
        content_type: &'static str,
        body: impl Into<String>,
    ) -> Self {
        Self {
            status,
            reason,
            content_type,
            body: body.into(),
        }
    }
}

/// Parse the request line from a raw HTTP request buffer.
pub fn request_line(buf: &str) -> Option<(&str, &str)> {
    let line = buf.lines().next()?.trim_end_matches('\r');
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

/// Build the HTTP response for a parsed method + path.
pub fn handle_request(
    method: &str,
    path: &str,
    health: &HealthState,
    metrics_body: Option<&str>,
) -> HttpResponse {
    let path_only = path.split('?').next().unwrap_or(path);

    if method != "GET" && method != "HEAD" {
        return HttpResponse::new(
            405,
            "Method Not Allowed",
            "text/plain",
            "method not allowed\n",
        );
    }

    match path_only {
        "/health" | "/ready" => {
            let snapshot = health.manifest.current();
            let body = serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "servers": snapshot.total_servers(),
                "tools": snapshot.total_tools(),
            })
            .to_string();
            HttpResponse::new(200, "OK", "application/json", body)
        }
        "/metrics" => match metrics_body {
            Some(body) => HttpResponse::new(
                200,
                "OK",
                "text/plain; version=0.0.4; charset=utf-8",
                body.to_string(),
            ),
            None => HttpResponse::new(404, "Not Found", "text/plain", "metrics feature disabled\n"),
        },
        _ => HttpResponse::new(404, "Not Found", "text/plain", "not found\n"),
    }
}

/// Bind `listen` and serve `/health` + `/metrics` until the task is aborted.
pub async fn serve(
    listen: std::net::SocketAddr,
    health: HealthState,
    #[cfg(feature = "metrics")] registry: Arc<prometheus_client::registry::Registry>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind observability listener on {listen}"))?;
    tracing::info!(%listen, "observability HTTP listening (/health, /metrics)");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let health = health.clone();
                #[cfg(feature = "metrics")]
                let registry = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(
                        stream,
                        health,
                        #[cfg(feature = "metrics")]
                        registry,
                    )
                    .await
                    {
                        tracing::debug!(error = %e, "observability HTTP connection error");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "observability accept failed");
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    health: HealthState,
    #[cfg(feature = "metrics")] registry: Arc<prometheus_client::registry::Registry>,
) -> Result<()> {
    let mut buf = vec![0u8; 2048];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf[..n]);
    let (method, path) = match request_line(&request) {
        Some(pair) => pair,
        None => {
            write_response(
                &mut stream,
                &HttpResponse::new(400, "Bad Request", "text/plain", "bad request\n"),
            )
            .await?;
            return Ok(());
        }
    };

    #[cfg(feature = "metrics")]
    let metrics_owned = {
        let mut encoded = String::new();
        match prometheus_client::encoding::text::encode(&mut encoded, registry.as_ref()) {
            Ok(()) => Some(encoded),
            Err(_) => None,
        }
    };
    #[cfg(feature = "metrics")]
    let metrics_body = metrics_owned.as_deref();
    #[cfg(not(feature = "metrics"))]
    let metrics_body = None::<&str>;

    let response = handle_request(method, path, &health, metrics_body);
    write_response(&mut stream, &response).await
}

async fn write_response(stream: &mut TcpStream, response: &HttpResponse) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(response.body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Resolve the observability bind address: env wins, then config.
pub fn resolve_listen(config_listen: Option<&str>) -> Option<std::net::SocketAddr> {
    let raw = std::env::var("FORGE_OBSERVABILITY_LISTEN")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| config_listen.map(str::to_string))?;
    match raw.parse() {
        Ok(addr) => Some(addr),
        Err(e) => {
            tracing::warn!(listen = %raw, error = %e, "invalid observability listen address");
            None
        }
    }
}

/// Resolve log format: CLI / env / config, default text.
pub fn resolve_log_format(cli_format: Option<&str>, config_format: Option<&str>) -> LogFormat {
    if let Some(raw) = cli_format {
        return LogFormat::parse(raw);
    }
    if let Ok(raw) = std::env::var("FORGE_LOG_FORMAT") {
        if !raw.is_empty() {
            return LogFormat::parse(&raw);
        }
    }
    if let Some(raw) = config_format {
        return LogFormat::parse(raw);
    }
    LogFormat::Text
}

/// Tracing output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable `tracing-subscriber` default.
    Text,
    /// Newline-delimited JSON (one event per line).
    Json,
}

impl LogFormat {
    fn parse(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_manifest::Manifest;

    fn health() -> HealthState {
        HealthState {
            manifest: LiveManifest::new(Manifest::new()),
        }
    }

    #[test]
    fn obs_http_01_parses_request_line() {
        let req = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(request_line(req), Some(("GET", "/health")));
    }

    #[test]
    fn obs_http_02_health_ok() {
        let resp = handle_request("GET", "/health", &health(), None);
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"status\":\"ok\""));
        assert!(resp.body.contains("\"version\""));
        assert!(resp.body.contains("\"servers\":0"));
    }

    #[test]
    fn obs_http_03_ready_alias() {
        let resp = handle_request("GET", "/ready", &health(), None);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn obs_http_04_metrics_when_present() {
        let resp = handle_request("GET", "/metrics", &health(), Some("# TYPE x counter\n"));
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("# TYPE"));
    }

    #[test]
    fn obs_http_05_metrics_missing() {
        let resp = handle_request("GET", "/metrics", &health(), None);
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn obs_http_06_unknown_is_404() {
        let resp = handle_request("GET", "/nope", &health(), None);
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn obs_http_07_post_rejected() {
        let resp = handle_request("POST", "/health", &health(), None);
        assert_eq!(resp.status, 405);
    }

    #[test]
    fn obs_http_08_log_format_parse() {
        assert_eq!(resolve_log_format(Some("json"), None), LogFormat::Json);
        assert_eq!(
            resolve_log_format(Some("text"), Some("json")),
            LogFormat::Text
        );
        assert_eq!(resolve_log_format(None, Some("json")), LogFormat::Json);
        assert_eq!(resolve_log_format(None, None), LogFormat::Text);
    }

    #[test]
    fn obs_http_09_listen_from_config() {
        temp_env::with_var_unset("FORGE_OBSERVABILITY_LISTEN", || {
            let addr = resolve_listen(Some("127.0.0.1:9090")).unwrap();
            assert_eq!(addr.port(), 9090);
        });
    }
}
