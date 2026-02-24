#![warn(missing_docs)]

//! # forge-client
//!
//! MCP client connections to downstream servers for the Forgemax Code Mode Gateway.
//!
//! Provides [`McpClient`] for connecting to individual MCP servers over stdio
//! or HTTP transports, and [`RouterDispatcher`] for routing tool calls to the
//! correct downstream server.

pub mod circuit_breaker;
pub mod router;
pub mod timeout;

use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::{Context, Result};
use forge_sandbox::ToolDispatcher;
use rmcp::model::{CallToolRequestParams, CallToolResult, Content, RawContent};
use rmcp::service::RunningService;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{ConfigureCommandExt, StreamableHttpClientTransport, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use serde_json::Value;
use tokio::process::Command;

pub use circuit_breaker::{CircuitBreakerConfig, CircuitBreakerDispatcher};
pub use router::RouterDispatcher;
pub use timeout::TimeoutDispatcher;

/// Configuration for connecting to a downstream MCP server.
#[derive(Debug, Clone)]
pub enum TransportConfig {
    /// Connect via stdio to a child process.
    Stdio {
        /// Command to execute.
        command: String,
        /// Arguments to the command.
        args: Vec<String>,
    },
    /// Connect via HTTP (Streamable HTTP / SSE).
    Http {
        /// URL of the MCP server endpoint.
        url: String,
        /// Optional HTTP headers (e.g., Authorization).
        headers: HashMap<String, String>,
    },
}

/// A client connection to a single downstream MCP server.
///
/// Wraps an rmcp client session and implements [`ToolDispatcher`] for routing
/// tool calls from the sandbox.
pub struct McpClient {
    name: String,
    inner: ClientInner,
}

enum ClientInner {
    Stdio(RunningService<RoleClient, ()>),
    Http(RunningService<RoleClient, ()>),
}

impl ClientInner {
    fn peer(&self) -> &rmcp::Peer<RoleClient> {
        match self {
            ClientInner::Stdio(s) => s,
            ClientInner::Http(s) => s,
        }
    }
}

/// Information about a tool discovered from a downstream server.
#[derive(Debug, Clone)]
pub struct ToolInfo {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: Option<String>,
    /// JSON Schema for the tool's input parameters.
    pub input_schema: Value,
}

impl McpClient {
    /// Connect to a downstream MCP server over stdio (child process).
    ///
    /// Spawns the given command as a child process and communicates via stdin/stdout.
    pub async fn connect_stdio(
        name: impl Into<String>,
        command: &str,
        args: &[&str],
    ) -> Result<Self> {
        let name = name.into();
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        tracing::info!(
            server = %name,
            command = %command,
            args = ?args_owned,
            "connecting to downstream MCP server (stdio)"
        );

        let transport = TokioChildProcess::new(Command::new(command).configure(|cmd| {
            for arg in &args_owned {
                cmd.arg(arg);
            }
        }))
        .with_context(|| {
            format!(
                "failed to spawn stdio transport for server '{}' (command: {})",
                name, command
            )
        })?;

        let service: RunningService<RoleClient, ()> = ()
            .serve(transport)
            .await
            .with_context(|| format!("MCP handshake failed for server '{}'", name))?;

        tracing::info!(server = %name, "connected to downstream MCP server (stdio)");

        Ok(Self {
            name,
            inner: ClientInner::Stdio(service),
        })
    }

    /// Connect to a downstream MCP server over HTTP (Streamable HTTP / SSE).
    pub async fn connect_http(
        name: impl Into<String>,
        url: &str,
        headers: Option<HashMap<String, String>>,
    ) -> Result<Self> {
        let name = name.into();

        if url.starts_with("http://") {
            tracing::warn!(
                server = %name,
                url = %url,
                "connecting over plain HTTP — consider using HTTPS for production"
            );
        }

        tracing::info!(
            server = %name,
            url = %url,
            "connecting to downstream MCP server (HTTP)"
        );

        let mut config = StreamableHttpClientTransportConfig::with_uri(url);

        // Strip sensitive headers on plain HTTP to prevent credential leakage
        let headers = headers.map(|mut h| {
            sanitize_headers_for_transport(url, &mut h);
            h
        });

        if let Some(hdrs) = &headers {
            for (key, value) in hdrs {
                if key.to_lowercase() == "authorization" {
                    tracing::debug!(server = %name, header = %key, "setting auth header (redacted)");
                } else {
                    tracing::debug!(server = %name, header = %key, value = %value, "setting header");
                }
            }

            let mut header_map = HashMap::new();
            for (key, value) in hdrs {
                let header_name = http::HeaderName::from_bytes(key.as_bytes())
                    .with_context(|| format!("invalid header name: {key}"))?;
                let header_value = http::HeaderValue::from_str(value)
                    .with_context(|| format!("invalid header value for {key}"))?;
                header_map.insert(header_name, header_value);
            }
            config = config.custom_headers(header_map);
        }

        let transport = StreamableHttpClientTransport::from_config(config);
        let service: RunningService<RoleClient, ()> = ()
            .serve(transport)
            .await
            .with_context(|| format!("MCP handshake failed for server '{}' (HTTP)", name))?;

        tracing::info!(server = %name, "connected to downstream MCP server (HTTP)");

        Ok(Self {
            name,
            inner: ClientInner::Http(service),
        })
    }

    /// Connect using a [`TransportConfig`].
    pub async fn connect(name: impl Into<String>, config: &TransportConfig) -> Result<Self> {
        let name = name.into();
        match config {
            TransportConfig::Stdio { command, args } => {
                let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                Self::connect_stdio(name, command, &arg_refs).await
            }
            TransportConfig::Http { url, headers } => {
                let hdrs = if headers.is_empty() {
                    None
                } else {
                    Some(headers.clone())
                };
                Self::connect_http(name, url, hdrs).await
            }
        }
    }

    /// List all tools available on this server.
    pub async fn list_tools(&self) -> Result<Vec<ToolInfo>> {
        let tools = self
            .inner
            .peer()
            .list_all_tools()
            .await
            .with_context(|| format!("failed to list tools for server '{}'", self.name))?;

        Ok(tools
            .into_iter()
            .map(|t| ToolInfo {
                name: t.name.to_string(),
                description: t.description.map(|d: Cow<'_, str>| d.to_string()),
                input_schema: serde_json::to_value(&*t.input_schema)
                    .unwrap_or(Value::Object(Default::default())),
            })
            .collect())
    }

    /// Get the server name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gracefully disconnect from the server.
    pub async fn disconnect(self) -> Result<()> {
        tracing::info!(server = %self.name, "disconnecting from downstream MCP server");
        match self.inner {
            ClientInner::Stdio(s) => {
                let _ = s.cancel().await;
            }
            ClientInner::Http(s) => {
                let _ = s.cancel().await;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for McpClient {
    async fn call_tool(&self, _server: &str, tool: &str, args: Value) -> Result<Value> {
        let arguments = args.as_object().cloned().or_else(|| {
            if args.is_null() {
                Some(serde_json::Map::new())
            } else {
                None
            }
        });

        let result: CallToolResult = self
            .inner
            .peer()
            .call_tool(CallToolRequestParams {
                meta: None,
                name: Cow::Owned(tool.to_string()),
                arguments,
                task: None,
            })
            .await
            .with_context(|| {
                format!("tool call failed: server='{}', tool='{}'", self.name, tool)
            })?;

        call_tool_result_to_value(result)
    }
}

/// Convert an MCP CallToolResult to a JSON Value.
fn call_tool_result_to_value(result: CallToolResult) -> Result<Value> {
    if let Some(structured) = result.structured_content {
        return Ok(structured);
    }

    if result.is_error == Some(true) {
        let error_text = result
            .content
            .iter()
            .filter_map(|c| match &c.raw {
                RawContent::Text(t) => Some(t.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        return Err(anyhow::anyhow!("tool returned error: {}", error_text));
    }

    if result.content.len() == 1 {
        content_to_value(&result.content[0])
    } else if result.content.is_empty() {
        Ok(Value::Null)
    } else {
        let values: Vec<Value> = result
            .content
            .iter()
            .filter_map(|c| content_to_value(c).ok())
            .collect();
        Ok(Value::Array(values))
    }
}

/// Maximum size in bytes for binary content (images, audio) before truncation.
const MAX_BINARY_CONTENT_SIZE: usize = 1_048_576; // 1 MB

/// Maximum size in bytes for text content before truncation.
/// Prevents OOM from enormous text responses from compromised downstream servers.
const MAX_TEXT_CONTENT_SIZE: usize = 10_485_760; // 10 MB

/// Convert a single Content item to a JSON Value.
///
/// Binary content (images, audio) larger than [`MAX_BINARY_CONTENT_SIZE`] is
/// replaced with truncation metadata to prevent OOM on large base64 payloads.
fn content_to_value(content: &Content) -> Result<Value> {
    match &content.raw {
        RawContent::Text(t) => {
            if t.text.len() > MAX_TEXT_CONTENT_SIZE {
                Ok(serde_json::json!({
                    "type": "text",
                    "truncated": true,
                    "original_size": t.text.len(),
                    "preview": &t.text[..1024.min(t.text.len())],
                }))
            } else {
                serde_json::from_str(&t.text).or_else(|_| Ok(Value::String(t.text.clone())))
            }
        }
        RawContent::Image(img) => {
            if img.data.len() > MAX_BINARY_CONTENT_SIZE {
                Ok(serde_json::json!({
                    "type": "image",
                    "truncated": true,
                    "original_size": img.data.len(),
                    "mime_type": img.mime_type,
                }))
            } else {
                Ok(serde_json::json!({
                    "type": "image",
                    "data": img.data,
                    "mime_type": img.mime_type,
                }))
            }
        }
        RawContent::Resource(r) => Ok(serde_json::json!({
            "type": "resource",
            "resource": serde_json::to_value(&r.resource).unwrap_or(Value::Null),
        })),
        RawContent::Audio(a) => {
            if a.data.len() > MAX_BINARY_CONTENT_SIZE {
                Ok(serde_json::json!({
                    "type": "audio",
                    "truncated": true,
                    "original_size": a.data.len(),
                    "mime_type": a.mime_type,
                }))
            } else {
                Ok(serde_json::json!({
                    "type": "audio",
                    "data": a.data,
                    "mime_type": a.mime_type,
                }))
            }
        }
        _ => Ok(serde_json::json!({"type": "unknown"})),
    }
}

/// Sensitive header name substrings (lowercase). Any header whose lowercased name
/// contains one of these is stripped on plain HTTP connections.
const SENSITIVE_HEADER_PATTERNS: &[&str] = &[
    "authorization",
    "cookie",
    "token",
    "secret",
    "key",
    "credential",
    "password",
    "auth",
];

/// Returns true if the header name matches a sensitive pattern.
fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_lowercase();
    SENSITIVE_HEADER_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

/// Strip sensitive headers from HTTP connections over plain HTTP.
///
/// Strips any header whose name contains "auth", "token", "secret", "key",
/// "cookie", "credential", or "password" (case-insensitive) to prevent
/// accidental credential leakage over unencrypted transports.
fn sanitize_headers_for_transport(url: &str, headers: &mut HashMap<String, String>) {
    if url.starts_with("http://") {
        let removed: Vec<String> = headers
            .keys()
            .filter(|k| is_sensitive_header(k))
            .cloned()
            .collect();
        for key in &removed {
            headers.remove(key);
        }
        if !removed.is_empty() {
            tracing::warn!(
                url = %url,
                removed_headers = ?removed,
                "stripped sensitive headers from plain HTTP connection — use HTTPS to send credentials"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{Content, RawContent};

    #[test]
    fn content_to_value_text_string() {
        let content = Content::text("hello");
        let val = content_to_value(&content).unwrap();
        assert_eq!(val, Value::String("hello".into()));
    }

    #[test]
    fn content_to_value_text_json() {
        let content = Content::text(r#"{"k":"v"}"#);
        let val = content_to_value(&content).unwrap();
        assert_eq!(val, serde_json::json!({"k": "v"}));
    }

    #[test]
    fn content_to_value_small_image_preserved() {
        let small_data = "a".repeat(1024); // 1KB
        let content = Content::image(small_data.clone(), "image/png");
        let val = content_to_value(&content).unwrap();
        assert_eq!(val["type"], "image");
        assert_eq!(val["data"], small_data);
        assert!(val.get("truncated").is_none());
    }

    #[test]
    fn content_to_value_oversized_image_truncated() {
        let large_data = "a".repeat(2 * 1024 * 1024); // 2MB
        let content = Content::image(large_data, "image/png");
        let val = content_to_value(&content).unwrap();
        assert_eq!(val["type"], "image");
        assert_eq!(val["truncated"], true);
        assert!(val.get("data").is_none());
        assert!(val["original_size"].as_u64().unwrap() > MAX_BINARY_CONTENT_SIZE as u64);
    }

    #[test]
    fn content_to_value_oversized_audio_truncated() {
        let large_data = "a".repeat(2 * 1024 * 1024); // 2MB
        let content = Content {
            raw: RawContent::Audio(rmcp::model::RawAudioContent {
                data: large_data,
                mime_type: "audio/wav".into(),
            }),
            annotations: None,
        };
        let val = content_to_value(&content).unwrap();
        assert_eq!(val["type"], "audio");
        assert_eq!(val["truncated"], true);
        assert!(val.get("data").is_none());
    }

    #[test]
    fn content_to_value_oversized_text_truncated() {
        let large_text = "x".repeat(11 * 1024 * 1024); // 11MB
        let content = Content::text(large_text);
        let val = content_to_value(&content).unwrap();
        assert_eq!(val["type"], "text");
        assert_eq!(val["truncated"], true);
        assert!(val["original_size"].as_u64().unwrap() > MAX_TEXT_CONTENT_SIZE as u64);
        assert!(val["preview"].as_str().unwrap().len() <= 1024);
    }

    #[test]
    fn content_to_value_normal_text_not_truncated() {
        let normal_text = "x".repeat(1024); // 1KB — well under limit
        let content = Content::text(normal_text.clone());
        let val = content_to_value(&content).unwrap();
        assert_eq!(val, Value::String(normal_text));
    }

    #[test]
    fn sanitize_headers_strips_auth_on_http() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".into(), "Bearer secret".into());
        headers.insert("Content-Type".into(), "application/json".into());
        sanitize_headers_for_transport("http://example.com/mcp", &mut headers);
        assert!(!headers.contains_key("Authorization"));
        assert!(headers.contains_key("Content-Type"));
    }

    #[test]
    fn sanitize_headers_strips_api_key_on_http() {
        let mut headers = HashMap::new();
        headers.insert("X-Api-Key".into(), "sk-123".into());
        headers.insert("Content-Type".into(), "application/json".into());
        sanitize_headers_for_transport("http://example.com/mcp", &mut headers);
        assert!(!headers.contains_key("X-Api-Key"));
        assert!(headers.contains_key("Content-Type"));
    }

    #[test]
    fn sanitize_headers_strips_cookie_on_http() {
        let mut headers = HashMap::new();
        headers.insert("Cookie".into(), "session=abc123".into());
        sanitize_headers_for_transport("http://example.com/mcp", &mut headers);
        assert!(!headers.contains_key("Cookie"));
    }

    #[test]
    fn sanitize_headers_strips_custom_token_on_http() {
        let mut headers = HashMap::new();
        headers.insert("X-Auth-Token".into(), "tok_secret".into());
        headers.insert("X-Secret-Key".into(), "s3cr3t".into());
        headers.insert("X-Custom-Credential".into(), "cred".into());
        headers.insert("X-Password".into(), "pass".into());
        headers.insert("Accept".into(), "application/json".into());
        sanitize_headers_for_transport("http://example.com/mcp", &mut headers);
        assert!(!headers.contains_key("X-Auth-Token"));
        assert!(!headers.contains_key("X-Secret-Key"));
        assert!(!headers.contains_key("X-Custom-Credential"));
        assert!(!headers.contains_key("X-Password"));
        assert!(headers.contains_key("Accept"));
    }

    #[test]
    fn sanitize_headers_preserves_all_on_https() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".into(), "Bearer secret".into());
        headers.insert("X-Api-Key".into(), "sk-123".into());
        headers.insert("Cookie".into(), "session=abc".into());
        sanitize_headers_for_transport("https://example.com/mcp", &mut headers);
        assert!(headers.contains_key("Authorization"));
        assert!(headers.contains_key("X-Api-Key"));
        assert!(headers.contains_key("Cookie"));
    }

    #[test]
    fn is_sensitive_header_matches() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("x-api-key"));
        assert!(is_sensitive_header("Cookie"));
        assert!(is_sensitive_header("X-Auth-Token"));
        assert!(is_sensitive_header("X-Secret-Key"));
        assert!(is_sensitive_header("X-Custom-Credential"));
        assert!(is_sensitive_header("X-Password"));
        assert!(!is_sensitive_header("Content-Type"));
        assert!(!is_sensitive_header("Accept"));
        assert!(!is_sensitive_header("User-Agent"));
    }
}
