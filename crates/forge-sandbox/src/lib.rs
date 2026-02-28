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

#[cfg(feature = "ast-validator")]
pub mod ast_validator;
pub mod audit;
pub mod error;
pub mod executor;
pub mod groups;
pub mod host;
pub mod ipc;
pub mod ops;
pub mod pool;
pub mod redact;
pub mod stash;
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
    ) -> Result<serde_json::Value, forge_error::DispatchError>;
}

/// Trait for dispatching resource reads from the sandbox to downstream MCP servers.
///
/// Resources are data objects (logs, files, database rows) exposed via MCP's
/// resources/read protocol. Unlike tool calls, resources are read-only.
#[async_trait::async_trait]
pub trait ResourceDispatcher: Send + Sync {
    /// Read a resource by URI from a downstream server.
    ///
    /// - `server`: The server name (e.g., "postgres", "github")
    /// - `uri`: The resource URI (e.g., "file:///logs/app.log")
    ///
    /// Returns the resource content as a JSON value.
    async fn read_resource(
        &self,
        server: &str,
        uri: &str,
    ) -> Result<serde_json::Value, forge_error::DispatchError>;
}

/// Trait for dispatching stash operations from the sandbox.
///
/// The stash is a per-session key/value store that persists across sandbox
/// executions within the same session. Entries are scoped by server group
/// for isolation.
#[async_trait::async_trait]
pub trait StashDispatcher: Send + Sync {
    /// Store a value under a key with an optional TTL.
    ///
    /// - `key`: Alphanumeric key (plus `_`, `-`, `.`, `:`) up to 256 chars
    /// - `value`: The JSON value to store
    /// - `ttl_secs`: TTL in seconds (0 = use default)
    /// - `current_group`: The server group of the current execution, if any
    async fn put(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: Option<u32>,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError>;

    /// Retrieve the value stored under a key.
    ///
    /// Returns `null` if the key does not exist or has expired.
    async fn get(
        &self,
        key: &str,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError>;

    /// Delete the entry stored under a key.
    ///
    /// Returns `{"deleted": true}` if the entry was removed, `{"deleted": false}` otherwise.
    async fn delete(
        &self,
        key: &str,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError>;

    /// List all keys visible to the current group.
    async fn keys(
        &self,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError>;
}
