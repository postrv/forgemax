#![warn(missing_docs)]

//! # forge-sandbox
//!
//! V8 sandbox for the Forgemax Code Mode Gateway.
//!
//! Executes LLM-generated JavaScript in a deno_core isolate with no filesystem,
//! network, or environment access. The only bridge to the host is through
//! explicitly registered ops that dispatch to a [`ToolDispatcher`].
//!
//! ## Security model
//!
//! - **V8 isolate**: Same process-level isolation as Chrome tabs
//! - **No ambient capabilities**: No fs, net, env, or child_process access
//! - **Fresh runtime per call**: No state leakage between executions
//! - **Pre-execution validation**: Banned patterns caught before reaching V8
//! - **Timeout enforcement**: Execution killed after configurable deadline
//! - **Output size limits**: Prevents exfiltration of large data sets
//! - **Opaque bindings**: Credentials never exposed to sandbox code

pub mod audit;
pub mod error;
pub mod executor;
pub mod groups;
pub mod host;
pub mod ipc;
pub mod ops;
pub mod redact;
pub mod validator;

pub use error::SandboxError;
pub use executor::{ExecutionMode, SandboxConfig, SandboxExecutor};

/// Trait for dispatching tool calls from the sandbox to downstream MCP servers.
///
/// Implementations hold credentials and manage connections to backend servers.
/// The sandbox code never sees tokens, file paths, or internal state — it calls
/// through opaque proxy objects that route here.
#[async_trait::async_trait]
pub trait ToolDispatcher: Send + Sync {
    /// Call a tool on a downstream server.
    ///
    /// - `server`: The server name (e.g., "github", "narsil")
    /// - `tool`: The tool identifier (e.g., "symbols.find", "issues.list")
    /// - `args`: The tool arguments as a JSON value
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, anyhow::Error>;
}
