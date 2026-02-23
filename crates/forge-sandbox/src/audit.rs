//! Audit logging for sandbox executions.
//!
//! Every sandbox execution emits an [`AuditEntry`] containing:
//! - Execution ID (UUID)
//! - SHA-256 hash of the code (never raw code in logs)
//! - A preview of the first 500 chars of code
//! - Tool calls made (with hashed args, not raw)
//! - Duration and outcome
//!
//! The [`AuditLogger`] trait allows pluggable backends.
//! [`JsonLinesAuditLogger`] writes newline-delimited JSON to any `AsyncWrite`.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Maximum length of the code preview in audit entries.
const CODE_PREVIEW_MAX: usize = 500;

/// A complete audit record for a single sandbox execution.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// Unique execution identifier.
    pub execution_id: String,
    /// ISO-8601 timestamp of when execution started.
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hash of the submitted code.
    pub code_hash: String,
    /// First N characters of the code (for human review).
    pub code_preview: String,
    /// Whether this was a search or execute call.
    pub operation: AuditOperation,
    /// Tool calls made during execution.
    pub tool_calls: Vec<ToolCallAudit>,
    /// Total execution duration in milliseconds.
    pub duration_ms: u64,
    /// Size of the result in bytes.
    pub result_size_bytes: usize,
    /// Final outcome.
    pub outcome: AuditOutcome,
}

/// The type of sandbox operation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    /// A manifest search operation.
    Search,
    /// A code execution operation with tool access.
    Execute,
}

/// Audit record for a single tool call within an execution.
#[derive(Debug, Clone, Serialize)]
pub struct ToolCallAudit {
    /// Target server name.
    pub server: String,
    /// Tool identifier.
    pub tool: String,
    /// SHA-256 hash of the serialized arguments (args never stored raw).
    pub args_hash: String,
    /// Duration of this tool call in milliseconds.
    pub duration_ms: u64,
    /// Whether the tool call succeeded.
    pub success: bool,
}

/// The outcome of a sandbox execution.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Execution completed successfully.
    Success,
    /// Execution failed with an error.
    Error {
        /// The error message.
        message: String,
    },
    /// Execution was terminated due to timeout.
    Timeout,
}

/// Trait for audit log backends.
#[async_trait::async_trait]
pub trait AuditLogger: Send + Sync {
    /// Write an audit entry.
    async fn log(&self, entry: &AuditEntry);
}

/// Writes audit entries as newline-delimited JSON to an `AsyncWrite` sink.
pub struct JsonLinesAuditLogger<W: AsyncWrite + Unpin + Send> {
    writer: Mutex<W>,
}

impl<W: AsyncWrite + Unpin + Send> JsonLinesAuditLogger<W> {
    /// Create a new JSON lines audit logger writing to the given sink.
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

#[async_trait::async_trait]
impl<W: AsyncWrite + Unpin + Send + 'static> AuditLogger for JsonLinesAuditLogger<W> {
    async fn log(&self, entry: &AuditEntry) {
        let mut line = match serde_json::to_string(entry) {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize audit entry");
                return;
            }
        };
        line.push('\n');

        let mut writer = self.writer.lock().await;
        if let Err(e) = writer.write_all(line.as_bytes()).await {
            tracing::warn!(error = %e, "failed to write audit entry");
        }
        let _ = writer.flush().await;
    }
}

/// Compute the SHA-256 hash of a string, returned as a hex string.
pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

/// Encode bytes as a hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Create a code preview (first N bytes, with ellipsis if truncated).
///
/// Truncates at a valid UTF-8 char boundary to avoid panics on multibyte characters.
pub fn code_preview(code: &str) -> String {
    if code.len() <= CODE_PREVIEW_MAX {
        code.to_string()
    } else {
        let mut end = CODE_PREVIEW_MAX;
        while !code.is_char_boundary(end) {
            end -= 1;
        }
        let mut preview = code[..end].to_string();
        preview.push_str("...");
        preview
    }
}

/// Builder for constructing audit entries during execution.
pub struct AuditEntryBuilder {
    execution_id: String,
    timestamp: DateTime<Utc>,
    code_hash: String,
    code_preview: String,
    operation: AuditOperation,
    tool_calls: Vec<ToolCallAudit>,
    start: Instant,
}

impl AuditEntryBuilder {
    /// Start building an audit entry for an execution.
    pub fn new(code: &str, operation: AuditOperation) -> Self {
        Self {
            execution_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            code_hash: sha256_hex(code),
            code_preview: code_preview(code),
            operation,
            tool_calls: Vec::new(),
            start: Instant::now(),
        }
    }

    /// Record a tool call.
    pub fn record_tool_call(&mut self, audit: ToolCallAudit) {
        self.tool_calls.push(audit);
    }

    /// Finalize the audit entry with the execution result.
    pub fn finish(self, result: &Result<serde_json::Value, crate::SandboxError>) -> AuditEntry {
        let duration_ms = self.start.elapsed().as_millis() as u64;
        let (result_size_bytes, outcome) = match result {
            Ok(value) => {
                let size = serde_json::to_string(value).map(|s| s.len()).unwrap_or(0);
                (size, AuditOutcome::Success)
            }
            Err(crate::SandboxError::Timeout { .. }) => (0, AuditOutcome::Timeout),
            Err(e) => (
                0,
                AuditOutcome::Error {
                    message: e.to_string(),
                },
            ),
        };

        AuditEntry {
            execution_id: self.execution_id,
            timestamp: self.timestamp,
            code_hash: self.code_hash,
            code_preview: self.code_preview,
            operation: self.operation,
            tool_calls: self.tool_calls,
            duration_ms,
            result_size_bytes,
            outcome,
        }
    }
}

/// A no-op audit logger for when auditing is not needed.
pub struct NoopAuditLogger;

#[async_trait::async_trait]
impl AuditLogger for NoopAuditLogger {
    async fn log(&self, _entry: &AuditEntry) {}
}

/// An audit-logging wrapper around a [`ToolDispatcher`] that records tool call metrics.
pub struct AuditingDispatcher {
    inner: Arc<dyn crate::ToolDispatcher>,
    audit_tx: tokio::sync::mpsc::UnboundedSender<ToolCallAudit>,
}

impl AuditingDispatcher {
    /// Wrap a dispatcher with audit recording.
    pub fn new(
        inner: Arc<dyn crate::ToolDispatcher>,
        audit_tx: tokio::sync::mpsc::UnboundedSender<ToolCallAudit>,
    ) -> Self {
        Self { inner, audit_tx }
    }
}

#[async_trait::async_trait]
impl crate::ToolDispatcher for AuditingDispatcher {
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, anyhow::Error> {
        let args_hash = sha256_hex(&serde_json::to_string(&args).unwrap_or_default());
        let start = Instant::now();

        let result = self.inner.call_tool(server, tool, args).await;

        let audit = ToolCallAudit {
            server: server.to_string(),
            tool: tool.to_string(),
            args_hash,
            duration_ms: start.elapsed().as_millis() as u64,
            success: result.is_ok(),
        };
        let _ = self.audit_tx.send(audit);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_produces_correct_hash() {
        // Known SHA-256 of "hello"
        let hash = sha256_hex("hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn code_preview_short_code_unchanged() {
        let code = "async () => { return 42; }";
        assert_eq!(code_preview(code), code);
    }

    #[test]
    fn code_preview_long_code_truncated() {
        let code = "x".repeat(1000);
        let preview = code_preview(&code);
        assert_eq!(preview.len(), 503); // 500 + "..."
        assert!(preview.ends_with("..."));
    }

    #[test]
    fn code_preview_multibyte_emoji_boundary() {
        // 499 ASCII bytes + U+1F600 (4 bytes) = 503 total, crosses the 500 boundary
        let mut code = "a".repeat(499);
        code.push('\u{1F600}'); // 😀 — 4 bytes
        code.push_str(&"b".repeat(100));
        let preview = code_preview(&code);
        assert!(preview.ends_with("..."));
        // Should truncate before the emoji since byte 500 is mid-char
        assert!(preview.starts_with(&"a".repeat(499)));
    }

    #[test]
    fn code_preview_all_emoji() {
        // 200 × U+1F600 (4 bytes each) = 800 bytes
        let code: String = std::iter::repeat('\u{1F600}').take(200).collect();
        let preview = code_preview(&code);
        assert!(preview.ends_with("..."));
        // Verify valid UTF-8 (would panic on invalid)
        let _ = preview.chars().count();
    }

    #[test]
    fn code_preview_exact_500_ascii() {
        let code = "a".repeat(500);
        let preview = code_preview(&code);
        assert_eq!(preview, code); // no truncation, no "..."
    }

    #[test]
    fn code_preview_cjk_boundary() {
        // CJK chars are 3 bytes each: 167 × 3 = 501 bytes, crosses 500
        let code: String = std::iter::repeat('\u{4E00}').take(200).collect(); // 600 bytes
        let preview = code_preview(&code);
        assert!(preview.ends_with("..."));
        // Verify valid UTF-8
        let _ = preview.chars().count();
    }

    #[test]
    fn audit_entry_builder_success() {
        let code = "async () => { return 1; }";
        let builder = AuditEntryBuilder::new(code, AuditOperation::Execute);
        let result: Result<serde_json::Value, crate::SandboxError> = Ok(serde_json::json!(1));
        let entry = builder.finish(&result);

        assert!(!entry.execution_id.is_empty());
        assert_eq!(entry.code_preview, code);
        assert!(matches!(entry.outcome, AuditOutcome::Success));
        assert_eq!(entry.result_size_bytes, 1); // "1" = 1 byte
    }

    #[test]
    fn audit_entry_builder_error() {
        let code = "async () => { throw new Error('test'); }";
        let builder = AuditEntryBuilder::new(code, AuditOperation::Search);
        let result: Result<serde_json::Value, crate::SandboxError> =
            Err(crate::SandboxError::JsError {
                message: "test error".into(),
            });
        let entry = builder.finish(&result);

        assert!(matches!(entry.outcome, AuditOutcome::Error { .. }));
        if let AuditOutcome::Error { message } = &entry.outcome {
            assert!(message.contains("test error"));
        }
    }

    #[test]
    fn audit_entry_builder_timeout() {
        let code = "async () => { while(true) {} }";
        let builder = AuditEntryBuilder::new(code, AuditOperation::Execute);
        let result: Result<serde_json::Value, crate::SandboxError> =
            Err(crate::SandboxError::Timeout { timeout_ms: 5000 });
        let entry = builder.finish(&result);

        assert!(matches!(entry.outcome, AuditOutcome::Timeout));
    }

    #[tokio::test]
    async fn json_lines_logger_writes_valid_json() {
        let buf: Vec<u8> = Vec::new();
        let logger = JsonLinesAuditLogger::new(buf);

        let entry = AuditEntry {
            execution_id: "test-id".into(),
            timestamp: Utc::now(),
            code_hash: "abc123".into(),
            code_preview: "async () => {}".into(),
            operation: AuditOperation::Execute,
            tool_calls: vec![],
            duration_ms: 42,
            result_size_bytes: 10,
            outcome: AuditOutcome::Success,
        };

        logger.log(&entry).await;

        let writer = logger.writer.lock().await;
        let output = String::from_utf8(writer.clone()).unwrap();
        assert!(output.ends_with('\n'));

        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(parsed["execution_id"], "test-id");
        assert_eq!(parsed["duration_ms"], 42);
        assert_eq!(parsed["outcome"], "success");
    }

    #[tokio::test]
    async fn json_lines_logger_with_tool_calls() {
        let buf: Vec<u8> = Vec::new();
        let logger = JsonLinesAuditLogger::new(buf);

        let entry = AuditEntry {
            execution_id: "test-id-2".into(),
            timestamp: Utc::now(),
            code_hash: "def456".into(),
            code_preview: "async () => { await forge.callTool(...); }".into(),
            operation: AuditOperation::Execute,
            tool_calls: vec![
                ToolCallAudit {
                    server: "narsil".into(),
                    tool: "ast.parse".into(),
                    args_hash: "hash1".into(),
                    duration_ms: 10,
                    success: true,
                },
                ToolCallAudit {
                    server: "github".into(),
                    tool: "issues.list".into(),
                    args_hash: "hash2".into(),
                    duration_ms: 25,
                    success: false,
                },
            ],
            duration_ms: 100,
            result_size_bytes: 500,
            outcome: AuditOutcome::Success,
        };

        logger.log(&entry).await;

        let writer = logger.writer.lock().await;
        let output = String::from_utf8(writer.clone()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        let calls = parsed["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["server"], "narsil");
        assert_eq!(calls[1]["success"], false);
    }

    #[test]
    fn audit_entry_serializes_no_raw_credentials() {
        let entry = AuditEntry {
            execution_id: "id".into(),
            timestamp: Utc::now(),
            code_hash: "hash".into(),
            code_preview: "preview".into(),
            operation: AuditOperation::Execute,
            tool_calls: vec![ToolCallAudit {
                server: "s".into(),
                tool: "t".into(),
                args_hash: "args_are_hashed".into(),
                duration_ms: 1,
                success: true,
            }],
            duration_ms: 1,
            result_size_bytes: 0,
            outcome: AuditOutcome::Success,
        };

        let json = serde_json::to_string(&entry).unwrap();
        // Verify that the JSON contains "args_hash" field, not "args"
        assert!(json.contains("args_hash"));
        assert!(!json.contains("\"args\""));
    }
}
