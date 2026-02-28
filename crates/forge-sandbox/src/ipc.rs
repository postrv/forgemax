//! IPC protocol for parent ↔ worker communication.
//!
//! Uses length-delimited JSON messages: 4-byte big-endian length prefix + JSON payload.
//! All messages are typed via [`ParentMessage`] and [`ChildMessage`] enums.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Error classification for structured error preservation across IPC.
///
/// When errors cross the process boundary via `ExecutionComplete`, the typed
/// `SandboxError` variants are converted to strings. This enum preserves the
/// error kind so the parent can reconstruct the correct `SandboxError` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorKind {
    /// V8 execution timed out (CPU watchdog or async event loop).
    Timeout,
    /// V8 heap memory limit was exceeded.
    HeapLimit,
    /// A JavaScript error was thrown.
    JsError,
    /// Generic execution failure.
    Execution,
}

/// Messages sent from the parent process to the worker child.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ParentMessage {
    /// Initial message: execute this code in the sandbox.
    Execute {
        /// The JavaScript async arrow function to execute.
        code: String,
        /// Optional capability manifest (for search mode — not used in child process execute).
        manifest: Option<Value>,
        /// Worker configuration.
        config: WorkerConfig,
    },
    /// Response to a tool call request from the child.
    ToolCallResult {
        /// Matches the request_id from ChildMessage::ToolCallRequest.
        request_id: u64,
        /// The tool call result, or an error message.
        result: Result<Value, String>,
    },
    /// Response to a resource read request from the child.
    ResourceReadResult {
        /// Matches the request_id from ChildMessage::ResourceReadRequest.
        request_id: u64,
        /// The resource content, or an error message.
        result: Result<Value, String>,
    },
    /// Reset the worker for a new execution (pool mode).
    ///
    /// The worker drops its current JsRuntime and creates a fresh one.
    /// It responds with [`ChildMessage::ResetComplete`].
    Reset {
        /// New worker configuration for the next execution.
        config: WorkerConfig,
    },
    /// Response to a stash operation from the child.
    StashResult {
        /// Matches the request_id from the stash request.
        request_id: u64,
        /// The stash operation result, or an error message.
        result: Result<Value, String>,
    },
}

/// Messages sent from the worker child to the parent process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ChildMessage {
    /// Request the parent to dispatch a tool call.
    ToolCallRequest {
        /// Unique ID for correlating request ↔ response.
        request_id: u64,
        /// Target server name.
        server: String,
        /// Tool identifier.
        tool: String,
        /// Tool arguments.
        args: Value,
    },
    /// Request the parent to read a resource.
    ResourceReadRequest {
        /// Unique ID for correlating request ↔ response.
        request_id: u64,
        /// Target server name.
        server: String,
        /// Resource URI.
        uri: String,
    },
    /// Request the parent to put a value in the stash.
    StashPut {
        /// Unique ID for correlating request ↔ response.
        request_id: u64,
        /// Stash key.
        key: String,
        /// Value to store.
        value: Value,
        /// TTL in seconds (None = use default).
        ttl_secs: Option<u32>,
        /// Stash group for isolation (v0.3.1+). Absent in v0.3.0 workers → None.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<String>,
    },
    /// Request the parent to get a value from the stash.
    StashGet {
        /// Unique ID for correlating request ↔ response.
        request_id: u64,
        /// Stash key.
        key: String,
        /// Stash group for isolation (v0.3.1+). Absent in v0.3.0 workers → None.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<String>,
    },
    /// Request the parent to delete a value from the stash.
    StashDelete {
        /// Unique ID for correlating request ↔ response.
        request_id: u64,
        /// Stash key.
        key: String,
        /// Stash group for isolation (v0.3.1+). Absent in v0.3.0 workers → None.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<String>,
    },
    /// Request the parent to list stash keys.
    StashKeys {
        /// Unique ID for correlating request ↔ response.
        request_id: u64,
        /// Stash group for isolation (v0.3.1+). Absent in v0.3.0 workers → None.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<String>,
    },
    /// Worker has been reset and is ready for a new execution.
    ResetComplete,
    /// The execution has finished.
    ExecutionComplete {
        /// The result value, or an error message.
        result: Result<Value, String>,
        /// Classification of the error for typed reconstruction on the parent side.
        /// Present only when `result` is `Err`. Defaults to `JsError` if absent
        /// (backward compatibility with workers that don't send this field).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_kind: Option<ErrorKind>,
        /// Structured timeout value in milliseconds (v0.3.1+).
        /// Present only when `error_kind` is `Timeout`. Replaces fragile string parsing.
        /// Absent in v0.3.0 workers → None.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
    /// A log message from the worker.
    Log {
        /// The log message text.
        message: String,
    },
}

/// Configuration passed to the worker process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Maximum execution time.
    pub timeout_ms: u64,
    /// V8 heap limit in bytes.
    pub max_heap_size: usize,
    /// Maximum tool calls per execution.
    pub max_tool_calls: usize,
    /// Maximum size of tool call arguments in bytes.
    pub max_tool_call_args_size: usize,
    /// Maximum size of the JSON result in bytes.
    pub max_output_size: usize,
    /// Maximum size of LLM-generated code in bytes.
    pub max_code_size: usize,
    /// Maximum IPC message size in bytes. Defaults to [`DEFAULT_MAX_IPC_MESSAGE_SIZE`].
    #[serde(default = "default_max_ipc_message_size")]
    pub max_ipc_message_size: usize,
    /// Maximum resource content size in bytes.
    #[serde(default = "default_max_resource_size")]
    pub max_resource_size: usize,
    /// Maximum concurrent calls in forge.parallel().
    #[serde(default = "default_max_parallel")]
    pub max_parallel: usize,
    /// Known tools for structured error fuzzy matching (v0.3.1+).
    /// Each entry is `(server_name, tool_name)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_tools: Option<Vec<(String, String)>>,
    /// Known server names for structured error detection (v0.3.1+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_servers: Option<std::collections::HashSet<String>>,
}

fn default_max_ipc_message_size() -> usize {
    DEFAULT_MAX_IPC_MESSAGE_SIZE
}

fn default_max_resource_size() -> usize {
    64 * 1024 * 1024 // 64 MB
}

fn default_max_parallel() -> usize {
    8
}

impl From<&crate::SandboxConfig> for WorkerConfig {
    fn from(config: &crate::SandboxConfig) -> Self {
        Self {
            timeout_ms: config.timeout.as_millis() as u64,
            max_heap_size: config.max_heap_size,
            max_tool_calls: config.max_tool_calls,
            max_tool_call_args_size: config.max_tool_call_args_size,
            max_output_size: config.max_output_size,
            max_code_size: config.max_code_size,
            max_ipc_message_size: config.max_ipc_message_size,
            max_resource_size: config.max_resource_size,
            max_parallel: config.max_parallel,
            known_tools: None,
            known_servers: None,
        }
    }
}

impl WorkerConfig {
    /// Convert back to a SandboxConfig for use in the worker.
    pub fn to_sandbox_config(&self) -> crate::SandboxConfig {
        crate::SandboxConfig {
            timeout: Duration::from_millis(self.timeout_ms),
            max_code_size: self.max_code_size,
            max_output_size: self.max_output_size,
            max_heap_size: self.max_heap_size,
            max_concurrent: 1, // worker handles one execution
            max_tool_calls: self.max_tool_calls,
            max_tool_call_args_size: self.max_tool_call_args_size,
            execution_mode: crate::executor::ExecutionMode::InProcess, // worker always runs in-process
            max_resource_size: self.max_resource_size,
            max_parallel: self.max_parallel,
            max_ipc_message_size: self.max_ipc_message_size,
        }
    }
}

/// Write a length-delimited JSON message to an async writer.
///
/// Format: 4-byte big-endian length prefix followed by the JSON payload bytes.
pub async fn write_message<T: Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &T,
) -> Result<(), std::io::Error> {
    let payload = serde_json::to_vec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "IPC payload too large: {} bytes (max {} bytes)",
                payload.len(),
                u32::MAX
            ),
        )
    })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Write a raw JSON byte payload as a length-delimited IPC message.
///
/// This bypasses serialization entirely — useful for forwarding large
/// tool/resource results without deserializing and re-serializing.
pub async fn write_raw_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "raw IPC payload too large: {} bytes (max {} bytes)",
                payload.len(),
                u32::MAX
            ),
        )
    })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a raw JSON byte payload from an IPC message without deserializing.
///
/// Returns the raw bytes as an owned `Box<RawValue>` which can be forwarded
/// without parsing. Returns `None` on EOF.
pub async fn read_raw_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_size: usize,
) -> Result<Option<Box<RawValue>>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(len_buf) as usize;

    if len > max_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "raw IPC message too large: {} bytes (limit: {} bytes)",
                len, max_size
            ),
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;

    let raw: Box<RawValue> = serde_json::from_slice(&payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(raw))
}

/// Default maximum IPC message size: 8 MB.
///
/// Reduced from 64 MB to prevent single messages from causing memory pressure.
/// Configurable via `sandbox.max_ipc_message_size_mb` in config.
pub const DEFAULT_MAX_IPC_MESSAGE_SIZE: usize = 8 * 1024 * 1024;

/// Read a length-delimited JSON message from an async reader.
///
/// Returns `None` if the reader has reached EOF (clean shutdown).
/// Uses [`DEFAULT_MAX_IPC_MESSAGE_SIZE`] as the size limit.
pub async fn read_message<T: for<'de> Deserialize<'de>, R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<T>, std::io::Error> {
    read_message_with_limit(reader, DEFAULT_MAX_IPC_MESSAGE_SIZE).await
}

/// Read a length-delimited JSON message with a configurable size limit.
///
/// Returns `None` if the reader has reached EOF (clean shutdown).
/// The `max_size` parameter controls the maximum allowed message size in bytes.
pub async fn read_message_with_limit<T: for<'de> Deserialize<'de>, R: AsyncRead + Unpin>(
    reader: &mut R,
    max_size: usize,
) -> Result<Option<T>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(len_buf) as usize;

    // Reject messages exceeding the configured limit
    if len > max_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "IPC message too large: {} bytes (limit: {} bytes)",
                len, max_size
            ),
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;

    let msg: T = serde_json::from_slice(&payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn roundtrip_parent_execute_message() {
        let msg = ParentMessage::Execute {
            code: "async () => { return 42; }".into(),
            manifest: Some(serde_json::json!({"servers": []})),
            config: WorkerConfig {
                timeout_ms: 5000,
                max_heap_size: 64 * 1024 * 1024,
                max_tool_calls: 50,
                max_tool_call_args_size: 1024 * 1024,
                max_output_size: 1024 * 1024,
                max_code_size: 64 * 1024,
                max_ipc_message_size: DEFAULT_MAX_IPC_MESSAGE_SIZE,
                max_resource_size: 64 * 1024 * 1024,
                max_parallel: 8,
                known_tools: None,
                known_servers: None,
            },
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ParentMessage::Execute {
                code,
                manifest,
                config,
            } => {
                assert_eq!(code, "async () => { return 42; }");
                assert!(manifest.is_some());
                assert_eq!(config.timeout_ms, 5000);
            }
            other => panic!("expected Execute, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn roundtrip_parent_tool_result() {
        let msg = ParentMessage::ToolCallResult {
            request_id: 42,
            result: Ok(serde_json::json!({"status": "ok"})),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ParentMessage::ToolCallResult { request_id, result } => {
                assert_eq!(request_id, 42);
                assert!(result.is_ok());
            }
            other => panic!("expected ToolCallResult, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn roundtrip_parent_tool_result_error() {
        let msg = ParentMessage::ToolCallResult {
            request_id: 7,
            result: Err("connection refused".into()),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ParentMessage::ToolCallResult { request_id, result } => {
                assert_eq!(request_id, 7);
                assert_eq!(result.unwrap_err(), "connection refused");
            }
            other => panic!("expected ToolCallResult, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn roundtrip_child_tool_request() {
        let msg = ChildMessage::ToolCallRequest {
            request_id: 1,
            server: "narsil".into(),
            tool: "ast.parse".into(),
            args: serde_json::json!({"file": "test.rs"}),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ToolCallRequest {
                request_id,
                server,
                tool,
                args,
            } => {
                assert_eq!(request_id, 1);
                assert_eq!(server, "narsil");
                assert_eq!(tool, "ast.parse");
                assert_eq!(args["file"], "test.rs");
            }
            other => panic!("expected ToolCallRequest, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn roundtrip_child_execution_complete() {
        let msg = ChildMessage::ExecutionComplete {
            result: Ok(serde_json::json!([1, 2, 3])),
            error_kind: None,
            timeout_ms: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete {
                result, error_kind, ..
            } => {
                assert_eq!(result.unwrap(), serde_json::json!([1, 2, 3]));
                assert_eq!(error_kind, None);
            }
            other => panic!("expected ExecutionComplete, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn roundtrip_child_log() {
        let msg = ChildMessage::Log {
            message: "processing step 3".into(),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::Log { message } => {
                assert_eq!(message, "processing step 3");
            }
            other => panic!("expected Log, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn multiple_messages_in_stream() {
        let msg1 = ChildMessage::Log {
            message: "first".into(),
        };
        let msg2 = ChildMessage::ToolCallRequest {
            request_id: 1,
            server: "s".into(),
            tool: "t".into(),
            args: serde_json::json!({}),
        };
        let msg3 = ChildMessage::ExecutionComplete {
            result: Ok(serde_json::json!("done")),
            error_kind: None,
            timeout_ms: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg1).await.unwrap();
        write_message(&mut buf, &msg2).await.unwrap();
        write_message(&mut buf, &msg3).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let d1: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        let d2: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        let d3: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        assert!(matches!(d1, ChildMessage::Log { .. }));
        assert!(matches!(d2, ChildMessage::ToolCallRequest { .. }));
        assert!(matches!(d3, ChildMessage::ExecutionComplete { .. }));

        // EOF after all messages
        let d4: Option<ChildMessage> = read_message(&mut cursor).await.unwrap();
        assert!(d4.is_none());
    }

    #[tokio::test]
    async fn execution_complete_error_roundtrip() {
        let msg = ChildMessage::ExecutionComplete {
            result: Err("failed to create tokio runtime: resource unavailable".into()),
            error_kind: Some(ErrorKind::Execution),
            timeout_ms: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete {
                result, error_kind, ..
            } => {
                let err = result.unwrap_err();
                assert!(
                    err.contains("tokio runtime"),
                    "expected runtime error: {err}"
                );
                assert_eq!(error_kind, Some(ErrorKind::Execution));
            }
            other => panic!("expected ExecutionComplete, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn eof_returns_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result: Option<ParentMessage> = read_message(&mut cursor).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn u32_try_from_overflow() {
        // Validates that the conversion logic correctly rejects sizes > u32::MAX
        let overflow_size = u32::MAX as usize + 1;
        assert!(u32::try_from(overflow_size).is_err());
    }

    #[tokio::test]
    async fn write_message_normal_size_succeeds() {
        // Regression guard: normal-sized messages still work after the try_from change
        let msg = ChildMessage::Log {
            message: "a".repeat(1024),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();
        assert!(buf.len() > 1024);
    }

    #[tokio::test]
    async fn large_message_roundtrip() {
        // A large payload (~1MB of data)
        let large_data = "x".repeat(1_000_000);
        let msg = ChildMessage::ExecutionComplete {
            result: Ok(serde_json::json!(large_data)),
            error_kind: None,
            timeout_ms: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete { result, .. } => {
                assert_eq!(result.unwrap().as_str().unwrap().len(), 1_000_000);
            }
            other => panic!("expected ExecutionComplete, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn worker_config_roundtrip_from_sandbox_config() {
        let sandbox = crate::SandboxConfig::default();
        let worker = WorkerConfig::from(&sandbox);
        let back = worker.to_sandbox_config();

        assert_eq!(sandbox.timeout, back.timeout);
        assert_eq!(sandbox.max_heap_size, back.max_heap_size);
        assert_eq!(sandbox.max_tool_calls, back.max_tool_calls);
        assert_eq!(sandbox.max_output_size, back.max_output_size);
        assert_eq!(worker.max_ipc_message_size, DEFAULT_MAX_IPC_MESSAGE_SIZE);
        assert_eq!(worker.max_ipc_message_size, 8 * 1024 * 1024); // 8 MB default
    }

    #[tokio::test]
    async fn read_message_with_limit_rejects_oversized() {
        let msg = ChildMessage::Log {
            message: "x".repeat(1024),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        // Set limit smaller than the message payload
        let mut cursor = Cursor::new(buf);
        let result: Result<Option<ChildMessage>, _> =
            read_message_with_limit(&mut cursor, 64).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("too large"), "error: {err_msg}");
    }

    #[tokio::test]
    async fn read_message_with_limit_accepts_within_limit() {
        let msg = ChildMessage::Log {
            message: "hello".into(),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let result: Option<ChildMessage> =
            read_message_with_limit(&mut cursor, 1024).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn worker_config_ipc_limit_serde_default() {
        // Deserializing JSON without max_ipc_message_size should use the default
        let json = r#"{
            "timeout_ms": 5000,
            "max_heap_size": 67108864,
            "max_tool_calls": 50,
            "max_tool_call_args_size": 1048576,
            "max_output_size": 1048576,
            "max_code_size": 65536
        }"#;
        let config: WorkerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_ipc_message_size, DEFAULT_MAX_IPC_MESSAGE_SIZE);
    }

    // --- IPC-01: ResourceReadRequest round-trip ---
    #[tokio::test]
    async fn ipc_01_resource_read_request_roundtrip() {
        let msg = ChildMessage::ResourceReadRequest {
            request_id: 10,
            server: "postgres".into(),
            uri: "file:///logs/app.log".into(),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ResourceReadRequest {
                request_id,
                server,
                uri,
            } => {
                assert_eq!(request_id, 10);
                assert_eq!(server, "postgres");
                assert_eq!(uri, "file:///logs/app.log");
            }
            other => panic!("expected ResourceReadRequest, got: {:?}", other),
        }
    }

    // --- IPC-02: ResourceReadResult (success) round-trip ---
    #[tokio::test]
    async fn ipc_02_resource_read_result_success_roundtrip() {
        let msg = ParentMessage::ResourceReadResult {
            request_id: 11,
            result: Ok(serde_json::json!({"content": "log data here"})),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ParentMessage::ResourceReadResult { request_id, result } => {
                assert_eq!(request_id, 11);
                let val = result.unwrap();
                assert_eq!(val["content"], "log data here");
            }
            other => panic!("expected ResourceReadResult, got: {:?}", other),
        }
    }

    // --- IPC-03: ResourceReadResult (error) round-trip ---
    #[tokio::test]
    async fn ipc_03_resource_read_result_error_roundtrip() {
        let msg = ParentMessage::ResourceReadResult {
            request_id: 12,
            result: Err("resource not found".into()),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ParentMessage::ResourceReadResult { request_id, result } => {
                assert_eq!(request_id, 12);
                assert_eq!(result.unwrap_err(), "resource not found");
            }
            other => panic!("expected ResourceReadResult, got: {:?}", other),
        }
    }

    // --- IPC-04: StashPut round-trip ---
    #[tokio::test]
    async fn ipc_04_stash_put_roundtrip() {
        let msg = ChildMessage::StashPut {
            request_id: 20,
            key: "my-key".into(),
            value: serde_json::json!({"data": 42}),
            ttl_secs: Some(60),
            group: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::StashPut {
                request_id,
                key,
                value,
                ttl_secs,
                group,
            } => {
                assert_eq!(request_id, 20);
                assert_eq!(key, "my-key");
                assert_eq!(value["data"], 42);
                assert_eq!(ttl_secs, Some(60));
                assert_eq!(group, None);
            }
            other => panic!("expected StashPut, got: {:?}", other),
        }
    }

    // --- IPC-05: StashGet round-trip ---
    #[tokio::test]
    async fn ipc_05_stash_get_roundtrip() {
        let msg = ChildMessage::StashGet {
            request_id: 21,
            key: "lookup-key".into(),
            group: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::StashGet {
                request_id,
                key,
                group,
            } => {
                assert_eq!(request_id, 21);
                assert_eq!(key, "lookup-key");
                assert_eq!(group, None);
            }
            other => panic!("expected StashGet, got: {:?}", other),
        }
    }

    // --- IPC-06: StashDelete round-trip ---
    #[tokio::test]
    async fn ipc_06_stash_delete_roundtrip() {
        let msg = ChildMessage::StashDelete {
            request_id: 22,
            key: "delete-me".into(),
            group: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::StashDelete {
                request_id,
                key,
                group,
            } => {
                assert_eq!(request_id, 22);
                assert_eq!(key, "delete-me");
                assert_eq!(group, None);
            }
            other => panic!("expected StashDelete, got: {:?}", other),
        }
    }

    // --- IPC-07: StashKeys round-trip ---
    #[tokio::test]
    async fn ipc_07_stash_keys_roundtrip() {
        let msg = ChildMessage::StashKeys {
            request_id: 23,
            group: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::StashKeys { request_id, group } => {
                assert_eq!(request_id, 23);
                assert_eq!(group, None);
            }
            other => panic!("expected StashKeys, got: {:?}", other),
        }
    }

    // --- IPC-08: StashResult round-trip ---
    #[tokio::test]
    async fn ipc_08_stash_result_roundtrip() {
        let msg = ParentMessage::StashResult {
            request_id: 24,
            result: Ok(serde_json::json!({"ok": true})),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ParentMessage::StashResult { request_id, result } => {
                assert_eq!(request_id, 24);
                assert_eq!(result.unwrap(), serde_json::json!({"ok": true}));
            }
            other => panic!("expected StashResult, got: {:?}", other),
        }
    }

    // --- IPC-09: Mixed message interleaving (tool + resource + stash in single stream) ---
    #[tokio::test]
    async fn ipc_09_mixed_message_interleaving() {
        let msg1 = ChildMessage::ToolCallRequest {
            request_id: 1,
            server: "s".into(),
            tool: "t".into(),
            args: serde_json::json!({}),
        };
        let msg2 = ChildMessage::ResourceReadRequest {
            request_id: 2,
            server: "pg".into(),
            uri: "file:///data".into(),
        };
        let msg3 = ChildMessage::StashPut {
            request_id: 3,
            key: "k".into(),
            value: serde_json::json!("v"),
            ttl_secs: None,
            group: None,
        };
        let msg4 = ChildMessage::StashGet {
            request_id: 4,
            key: "k".into(),
            group: None,
        };
        let msg5 = ChildMessage::ExecutionComplete {
            result: Ok(serde_json::json!("done")),
            error_kind: None,
            timeout_ms: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg1).await.unwrap();
        write_message(&mut buf, &msg2).await.unwrap();
        write_message(&mut buf, &msg3).await.unwrap();
        write_message(&mut buf, &msg4).await.unwrap();
        write_message(&mut buf, &msg5).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let d1: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        let d2: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        let d3: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        let d4: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        let d5: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        assert!(matches!(d1, ChildMessage::ToolCallRequest { .. }));
        assert!(matches!(d2, ChildMessage::ResourceReadRequest { .. }));
        assert!(matches!(d3, ChildMessage::StashPut { .. }));
        assert!(matches!(d4, ChildMessage::StashGet { .. }));
        assert!(matches!(d5, ChildMessage::ExecutionComplete { .. }));

        // EOF after all messages
        let d6: Option<ChildMessage> = read_message(&mut cursor).await.unwrap();
        assert!(d6.is_none());
    }

    // --- IPC-P01: Reset round-trip ---
    #[tokio::test]
    async fn ipc_p01_reset_roundtrip() {
        let msg = ParentMessage::Reset {
            config: WorkerConfig {
                timeout_ms: 3000,
                max_heap_size: 32 * 1024 * 1024,
                max_tool_calls: 25,
                max_tool_call_args_size: 512 * 1024,
                max_output_size: 512 * 1024,
                max_code_size: 32 * 1024,
                max_ipc_message_size: DEFAULT_MAX_IPC_MESSAGE_SIZE,
                max_resource_size: 32 * 1024 * 1024,
                max_parallel: 4,
                known_tools: None,
                known_servers: None,
            },
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ParentMessage::Reset { config } => {
                assert_eq!(config.timeout_ms, 3000);
                assert_eq!(config.max_tool_calls, 25);
            }
            other => panic!("expected Reset, got: {:?}", other),
        }
    }

    // --- IPC-P02: ResetComplete round-trip ---
    #[tokio::test]
    async fn ipc_p02_reset_complete_roundtrip() {
        let msg = ChildMessage::ResetComplete;

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        assert!(matches!(decoded, ChildMessage::ResetComplete));
    }

    // --- IPC-P03: Reset + Execute interleaving in single stream ---
    #[tokio::test]
    async fn ipc_p03_reset_execute_interleaving() {
        let reset = ParentMessage::Reset {
            config: WorkerConfig {
                timeout_ms: 5000,
                max_heap_size: 64 * 1024 * 1024,
                max_tool_calls: 50,
                max_tool_call_args_size: 1024 * 1024,
                max_output_size: 1024 * 1024,
                max_code_size: 64 * 1024,
                max_ipc_message_size: DEFAULT_MAX_IPC_MESSAGE_SIZE,
                max_resource_size: 64 * 1024 * 1024,
                max_parallel: 8,
                known_tools: None,
                known_servers: None,
            },
        };
        let execute = ParentMessage::Execute {
            code: "async () => 42".into(),
            manifest: None,
            config: WorkerConfig {
                timeout_ms: 5000,
                max_heap_size: 64 * 1024 * 1024,
                max_tool_calls: 50,
                max_tool_call_args_size: 1024 * 1024,
                max_output_size: 1024 * 1024,
                max_code_size: 64 * 1024,
                max_ipc_message_size: DEFAULT_MAX_IPC_MESSAGE_SIZE,
                max_resource_size: 64 * 1024 * 1024,
                max_parallel: 8,
                known_tools: None,
                known_servers: None,
            },
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &reset).await.unwrap();
        write_message(&mut buf, &execute).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let d1: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();
        let d2: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();

        assert!(matches!(d1, ParentMessage::Reset { .. }));
        assert!(matches!(d2, ParentMessage::Execute { .. }));
    }

    // --- IPC-10: Oversized stash message rejected by read_message_with_limit ---
    #[tokio::test]
    async fn ipc_10_oversized_stash_message_rejected() {
        let msg = ChildMessage::StashPut {
            request_id: 100,
            key: "k".into(),
            value: serde_json::json!("x".repeat(2048)),
            ttl_secs: Some(60),
            group: None,
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        // Set limit smaller than the message payload
        let mut cursor = Cursor::new(buf);
        let result: Result<Option<ChildMessage>, _> =
            read_message_with_limit(&mut cursor, 64).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too large"),
            "error should mention 'too large': {err_msg}"
        );
    }

    // --- IPC-O01: ErrorKind timeout round-trip ---
    #[tokio::test]
    async fn ipc_o01_error_kind_timeout_roundtrip() {
        let msg = ChildMessage::ExecutionComplete {
            result: Err("execution timed out after 500ms".into()),
            error_kind: Some(ErrorKind::Timeout),
            timeout_ms: Some(500),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete {
                result,
                error_kind,
                timeout_ms,
            } => {
                assert!(result.is_err());
                assert_eq!(error_kind, Some(ErrorKind::Timeout));
                assert_eq!(timeout_ms, Some(500));
            }
            other => panic!("expected ExecutionComplete, got: {:?}", other),
        }
    }

    // --- IPC-O02: ErrorKind heap_limit round-trip ---
    #[tokio::test]
    async fn ipc_o02_error_kind_heap_limit_roundtrip() {
        let msg = ChildMessage::ExecutionComplete {
            result: Err("V8 heap limit exceeded".into()),
            error_kind: Some(ErrorKind::HeapLimit),
            timeout_ms: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete {
                result, error_kind, ..
            } => {
                assert!(result.is_err());
                assert_eq!(error_kind, Some(ErrorKind::HeapLimit));
            }
            other => panic!("expected ExecutionComplete, got: {:?}", other),
        }
    }

    // --- IPC-O03: ErrorKind absent defaults to None (backward compatibility) ---
    #[tokio::test]
    async fn ipc_o03_error_kind_backward_compat() {
        // Simulate a message from an older worker that doesn't include error_kind.
        // The JSON doesn't have the error_kind field at all.
        let json = r#"{"type":"ExecutionComplete","result":{"Err":"some old error"}}"#;
        let mut buf = Vec::new();
        let payload = json.as_bytes();
        let len = payload.len() as u32;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(payload);

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete {
                result,
                error_kind,
                timeout_ms,
            } => {
                assert!(result.is_err());
                assert_eq!(
                    error_kind, None,
                    "missing error_kind should default to None"
                );
                assert_eq!(
                    timeout_ms, None,
                    "missing timeout_ms should default to None"
                );
            }
            other => panic!("expected ExecutionComplete, got: {:?}", other),
        }
    }

    // --- IPC-O04: ErrorKind js_error round-trip ---
    #[tokio::test]
    async fn ipc_o04_error_kind_js_error_roundtrip() {
        let msg = ChildMessage::ExecutionComplete {
            result: Err("ReferenceError: x is not defined".into()),
            error_kind: Some(ErrorKind::JsError),
            timeout_ms: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete {
                result, error_kind, ..
            } => {
                assert_eq!(result.unwrap_err(), "ReferenceError: x is not defined");
                assert_eq!(error_kind, Some(ErrorKind::JsError));
            }
            other => panic!("expected ExecutionComplete, got: {:?}", other),
        }
    }

    // --- IPC-O05: Success result has no error_kind in serialized JSON ---
    #[tokio::test]
    async fn ipc_o05_success_omits_error_kind() {
        let msg = ChildMessage::ExecutionComplete {
            result: Ok(serde_json::json!(42)),
            error_kind: None,
            timeout_ms: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        // error_kind: None should be skipped thanks to skip_serializing_if
        assert!(
            !json.contains("error_kind"),
            "success messages should not contain error_kind field: {json}"
        );
        assert!(
            !json.contains("timeout_ms"),
            "success messages should not contain timeout_ms field: {json}"
        );
    }

    // --- H1: Stash Group Isolation Tests ---

    #[tokio::test]
    async fn ipc_h1_01_stash_put_with_group_roundtrip() {
        let msg = ChildMessage::StashPut {
            request_id: 50,
            key: "grouped-key".into(),
            value: serde_json::json!({"data": "secret"}),
            ttl_secs: Some(120),
            group: Some("analytics".into()),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::StashPut {
                request_id,
                key,
                group,
                ..
            } => {
                assert_eq!(request_id, 50);
                assert_eq!(key, "grouped-key");
                assert_eq!(group, Some("analytics".into()));
            }
            other => panic!("expected StashPut, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipc_h1_02_stash_get_with_group_roundtrip() {
        let msg = ChildMessage::StashGet {
            request_id: 51,
            key: "grouped-key".into(),
            group: Some("analytics".into()),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::StashGet {
                request_id,
                key,
                group,
            } => {
                assert_eq!(request_id, 51);
                assert_eq!(key, "grouped-key");
                assert_eq!(group, Some("analytics".into()));
            }
            other => panic!("expected StashGet, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipc_h1_03_stash_delete_with_group_roundtrip() {
        let msg = ChildMessage::StashDelete {
            request_id: 52,
            key: "grouped-key".into(),
            group: Some("analytics".into()),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::StashDelete {
                request_id,
                key,
                group,
            } => {
                assert_eq!(request_id, 52);
                assert_eq!(key, "grouped-key");
                assert_eq!(group, Some("analytics".into()));
            }
            other => panic!("expected StashDelete, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipc_h1_04_stash_keys_with_group_roundtrip() {
        let msg = ChildMessage::StashKeys {
            request_id: 53,
            group: Some("analytics".into()),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::StashKeys { request_id, group } => {
                assert_eq!(request_id, 53);
                assert_eq!(group, Some("analytics".into()));
            }
            other => panic!("expected StashKeys, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipc_h1_05_stash_put_without_group_backward_compat() {
        // group: None → field absent in JSON
        let msg = ChildMessage::StashPut {
            request_id: 54,
            key: "no-group-key".into(),
            value: serde_json::json!("val"),
            ttl_secs: None,
            group: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(
            !json.contains("\"group\""),
            "group:None should be absent in serialized JSON: {json}"
        );

        // Still deserializes correctly
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        match decoded {
            ChildMessage::StashPut { group, .. } => {
                assert_eq!(group, None);
            }
            other => panic!("expected StashPut, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipc_h1_06_old_message_without_group_field_deserializes() {
        // Simulate a v0.3.0 worker message that lacks the group field entirely
        let json = r#"{"type":"StashPut","request_id":60,"key":"old-key","value":"old-val","ttl_secs":30}"#;
        let mut buf = Vec::new();
        let payload = json.as_bytes();
        let len = payload.len() as u32;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(payload);

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::StashPut {
                request_id,
                key,
                group,
                ..
            } => {
                assert_eq!(request_id, 60);
                assert_eq!(key, "old-key");
                assert_eq!(
                    group, None,
                    "missing group field from v0.3.0 worker should deserialize as None"
                );
            }
            other => panic!("expected StashPut, got: {:?}", other),
        }

        // Also test StashGet, StashDelete, StashKeys backward compat
        let json_get = r#"{"type":"StashGet","request_id":61,"key":"old-key"}"#;
        let mut buf = Vec::new();
        let payload = json_get.as_bytes();
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        match decoded {
            ChildMessage::StashGet { group, .. } => assert_eq!(group, None),
            other => panic!("expected StashGet, got: {:?}", other),
        }

        let json_del = r#"{"type":"StashDelete","request_id":62,"key":"old-key"}"#;
        let mut buf = Vec::new();
        let payload = json_del.as_bytes();
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        match decoded {
            ChildMessage::StashDelete { group, .. } => assert_eq!(group, None),
            other => panic!("expected StashDelete, got: {:?}", other),
        }

        let json_keys = r#"{"type":"StashKeys","request_id":63}"#;
        let mut buf = Vec::new();
        let payload = json_keys.as_bytes();
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        match decoded {
            ChildMessage::StashKeys { group, .. } => assert_eq!(group, None),
            other => panic!("expected StashKeys, got: {:?}", other),
        }
    }

    // --- Phase 2: Structured Timeout + RawValue Tests ---

    #[tokio::test]
    async fn ipc_t01_exec_complete_timeout_with_timeout_ms_roundtrip() {
        let msg = ChildMessage::ExecutionComplete {
            result: Err("execution timed out after 5000ms".into()),
            error_kind: Some(ErrorKind::Timeout),
            timeout_ms: Some(5000),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete {
                result,
                error_kind,
                timeout_ms,
            } => {
                assert!(result.is_err());
                assert_eq!(error_kind, Some(ErrorKind::Timeout));
                assert_eq!(timeout_ms, Some(5000));
            }
            other => panic!("expected ExecutionComplete, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipc_t02_timeout_ms_absent_backward_compat() {
        // Simulate an old v0.3.0 worker that doesn't include timeout_ms
        let json = r#"{"type":"ExecutionComplete","result":{"Err":"timed out after 3000ms"},"error_kind":"timeout"}"#;
        let mut buf = Vec::new();
        let payload = json.as_bytes();
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete {
                error_kind,
                timeout_ms,
                ..
            } => {
                assert_eq!(error_kind, Some(ErrorKind::Timeout));
                assert_eq!(
                    timeout_ms, None,
                    "missing timeout_ms should default to None"
                );
            }
            other => panic!("expected ExecutionComplete, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipc_t03_timeout_ms_serialization_omitted_when_none() {
        let msg = ChildMessage::ExecutionComplete {
            result: Err("some error".into()),
            error_kind: Some(ErrorKind::JsError),
            timeout_ms: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(
            !json.contains("timeout_ms"),
            "timeout_ms:None should be omitted: {json}"
        );
    }

    #[tokio::test]
    async fn ipc_t04_timeout_ms_present_when_some() {
        let msg = ChildMessage::ExecutionComplete {
            result: Err("timed out".into()),
            error_kind: Some(ErrorKind::Timeout),
            timeout_ms: Some(10000),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(
            json.contains("\"timeout_ms\":10000"),
            "timeout_ms should be present: {json}"
        );
    }

    // --- RawValue passthrough tests ---

    #[tokio::test]
    async fn ipc_rv01_write_raw_message_roundtrip() {
        let payload = br#"{"type":"StashResult","request_id":1,"result":{"Ok":{"data":42}}}"#;

        let mut buf = Vec::new();
        write_raw_message(&mut buf, payload).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let raw = read_raw_message(&mut cursor, DEFAULT_MAX_IPC_MESSAGE_SIZE)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(raw.get(), std::str::from_utf8(payload).unwrap());
    }

    #[tokio::test]
    async fn ipc_rv02_read_raw_message_preserves_bytes() {
        // Write a regular message, then read it raw
        let msg = ChildMessage::Log {
            message: "test raw".into(),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let raw = read_raw_message(&mut cursor, DEFAULT_MAX_IPC_MESSAGE_SIZE)
            .await
            .unwrap()
            .unwrap();

        // The raw value should be valid JSON
        let parsed: ChildMessage = serde_json::from_str(raw.get()).unwrap();
        assert!(matches!(parsed, ChildMessage::Log { .. }));
    }

    #[tokio::test]
    async fn ipc_rv03_raw_message_size_limit_enforced() {
        let large_payload = format!(r#"{{"data":"{}"}}"#, "x".repeat(1024));
        let mut buf = Vec::new();
        write_raw_message(&mut buf, large_payload.as_bytes())
            .await
            .unwrap();

        let mut cursor = Cursor::new(buf);
        let result = read_raw_message(&mut cursor, 64).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too large"), "error: {err}");
    }

    #[tokio::test]
    async fn ipc_rv04_large_payload_stays_raw() {
        // 1MB payload — read as raw without full Value parse
        let large = format!(r#"{{"big":"{}"}}"#, "x".repeat(1_000_000));
        let mut buf = Vec::new();
        write_raw_message(&mut buf, large.as_bytes()).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let raw = read_raw_message(&mut cursor, 2 * 1024 * 1024)
            .await
            .unwrap()
            .unwrap();

        // Should preserve the raw JSON string without parsing into Value
        assert!(raw.get().len() > 1_000_000);
        // Can still be parsed if needed
        let val: Value = serde_json::from_str(raw.get()).unwrap();
        assert_eq!(val["big"].as_str().unwrap().len(), 1_000_000);
    }

    #[tokio::test]
    async fn ipc_rv05_rawvalue_backward_compat_with_value() {
        // Write as regular message (Value), read as raw
        let msg = ParentMessage::ToolCallResult {
            request_id: 99,
            result: Ok(serde_json::json!({"status": "ok", "count": 42})),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf.clone());
        let raw = read_raw_message(&mut cursor, DEFAULT_MAX_IPC_MESSAGE_SIZE)
            .await
            .unwrap()
            .unwrap();

        // Parse the raw back as ParentMessage
        let parsed: ParentMessage = serde_json::from_str(raw.get()).unwrap();
        match parsed {
            ParentMessage::ToolCallResult { request_id, result } => {
                assert_eq!(request_id, 99);
                assert!(result.is_ok());
            }
            other => panic!("expected ToolCallResult, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipc_rv06_raw_eof_returns_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result = read_raw_message(&mut cursor, DEFAULT_MAX_IPC_MESSAGE_SIZE)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn ipc_rv07_mixed_raw_and_value_messages() {
        let mut buf = Vec::new();

        // Write a typed message
        let msg1 = ChildMessage::Log {
            message: "first".into(),
        };
        write_message(&mut buf, &msg1).await.unwrap();

        // Write a raw message
        let raw_payload = br#"{"type":"Log","message":"raw second"}"#;
        write_raw_message(&mut buf, raw_payload).await.unwrap();

        // Read both: first typed, second raw
        let mut cursor = Cursor::new(buf);
        let d1: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();
        assert!(matches!(d1, ChildMessage::Log { .. }));

        let d2 = read_raw_message(&mut cursor, DEFAULT_MAX_IPC_MESSAGE_SIZE)
            .await
            .unwrap()
            .unwrap();
        let parsed: ChildMessage = serde_json::from_str(d2.get()).unwrap();
        assert!(matches!(parsed, ChildMessage::Log { .. }));
    }
}
