//! IPC protocol for parent ↔ worker communication.
//!
//! Uses length-delimited JSON messages: 4-byte big-endian length prefix + JSON payload.
//! All messages are typed via [`ParentMessage`] and [`ChildMessage`] enums.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Messages sent from the parent process to the worker child.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
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
}

/// Messages sent from the worker child to the parent process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
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
    /// The execution has finished.
    ExecutionComplete {
        /// The result value, or an error message.
        result: Result<Value, String>,
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
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-delimited JSON message from an async reader.
///
/// Returns `None` if the reader has reached EOF (clean shutdown).
pub async fn read_message<T: for<'de> Deserialize<'de>, R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<T>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check: reject messages larger than 64 MB
    if len > 64 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("IPC message too large: {} bytes", len),
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
            },
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ParentMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ParentMessage::Execute { code, manifest, config } => {
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
            ChildMessage::ToolCallRequest { request_id, server, tool, args } => {
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
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete { result } => {
                assert_eq!(result.unwrap(), serde_json::json!([1, 2, 3]));
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
        let msg1 = ChildMessage::Log { message: "first".into() };
        let msg2 = ChildMessage::ToolCallRequest {
            request_id: 1,
            server: "s".into(),
            tool: "t".into(),
            args: serde_json::json!({}),
        };
        let msg3 = ChildMessage::ExecutionComplete {
            result: Ok(serde_json::json!("done")),
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
    async fn eof_returns_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result: Option<ParentMessage> = read_message(&mut cursor).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn large_message_roundtrip() {
        // A large payload (~1MB of data)
        let large_data = "x".repeat(1_000_000);
        let msg = ChildMessage::ExecutionComplete {
            result: Ok(serde_json::json!(large_data)),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChildMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            ChildMessage::ExecutionComplete { result } => {
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
    }
}
