//! Error types for the Forge sandbox.

use thiserror::Error;

/// Errors that can occur during sandbox execution.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Code failed validation checks.
    #[error("code validation failed: {reason}")]
    ValidationFailed {
        /// What went wrong.
        reason: String,
    },

    /// Code exceeds the configured maximum size.
    #[error("code exceeds maximum size of {max} bytes (got {actual})")]
    CodeTooLarge {
        /// Maximum allowed size.
        max: usize,
        /// Actual size.
        actual: usize,
    },

    /// Execution result exceeds the configured maximum size.
    #[error("output exceeds maximum size of {max} bytes")]
    OutputTooLarge {
        /// Maximum allowed size.
        max: usize,
    },

    /// Execution timed out (async event loop or CPU-bound watchdog).
    #[error("execution timed out after {timeout_ms}ms")]
    Timeout {
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /// A banned code pattern was detected during validation.
    #[error("banned pattern detected: `{pattern}` — the sandbox has no filesystem, network, or module access. Use forge.callTool() or forge.server() to interact with external services.")]
    BannedPattern {
        /// The pattern that was matched.
        pattern: String,
    },

    /// Generic execution failure.
    #[error("sandbox execution failed: {0}")]
    Execution(#[from] anyhow::Error),

    /// A JavaScript error was thrown during execution.
    #[error("javascript error: {message}")]
    JsError {
        /// The error message from JavaScript.
        message: String,
    },

    /// Result serialization failed.
    #[error("result serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Too many concurrent sandbox executions.
    #[error("concurrency limit reached (max {max} concurrent executions)")]
    ConcurrencyLimit {
        /// Maximum allowed concurrent executions.
        max: usize,
    },

    /// Too many tool calls in a single execution.
    #[error("tool call limit exceeded (max {max} calls per execution)")]
    ToolCallLimit {
        /// Maximum allowed tool calls.
        max: usize,
    },

    /// Tool call arguments exceed the configured maximum size.
    #[error("tool call arguments too large (max {max} bytes, got {actual})")]
    ToolCallArgsTooLarge {
        /// Maximum allowed argument size.
        max: usize,
        /// Actual argument size.
        actual: usize,
    },

    /// V8 heap memory limit was exceeded.
    #[error("V8 heap limit exceeded")]
    HeapLimitExceeded,
}
