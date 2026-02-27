#![warn(missing_docs)]

//! # forge-server
//!
//! MCP server for the Forgemax Code Mode Gateway.
//!
//! Exposes exactly two tools to agents:
//! - `search` — query the capability manifest to discover tools
//! - `execute` — run code against the tool API
//!
//! This collapses N servers x M tools into a fixed ~1,000 token footprint.

use std::sync::Arc;
use std::time::Duration;

use forge_manifest::Manifest;
use forge_sandbox::groups::{
    GroupEnforcingDispatcher, GroupEnforcingResourceDispatcher, GroupPolicy,
};
use forge_sandbox::stash::{SessionStash, StashConfig};
use forge_sandbox::{
    ResourceDispatcher, SandboxConfig, SandboxExecutor, StashDispatcher, ToolDispatcher,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use serde::Deserialize;

/// The Forge MCP server handler.
///
/// Implements `ServerHandler` from rmcp to serve the `search` and `execute`
/// Code Mode tools over MCP stdio or SSE transport.
#[derive(Clone)]
pub struct ForgeServer {
    executor: Arc<SandboxExecutor>,
    manifest: Arc<Manifest>,
    dispatcher: Arc<dyn ToolDispatcher>,
    resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    group_policy: Option<Arc<GroupPolicy>>,
    session_stash: Option<Arc<tokio::sync::Mutex<SessionStash>>>,
    tool_router: ToolRouter<Self>,
}

/// Stash dispatcher that wraps a shared [`SessionStash`] behind a Mutex.
///
/// Created per-execution by `ForgeServer::execute()` to provide the stash API
/// to sandbox code. The `current_group` is set from the server group context.
struct ServerStashDispatcher {
    stash: Arc<tokio::sync::Mutex<SessionStash>>,
    current_group: Option<String>,
}

#[async_trait::async_trait]
impl StashDispatcher for ServerStashDispatcher {
    async fn put(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: Option<u32>,
        _current_group: Option<String>,
    ) -> Result<serde_json::Value, anyhow::Error> {
        let ttl = ttl_secs
            .filter(|&s| s > 0)
            .map(|s| Duration::from_secs(s as u64));
        let mut stash = self.stash.lock().await;
        stash.put(key, value, ttl, self.current_group.as_deref())?;
        Ok(serde_json::json!({"ok": true}))
    }

    async fn get(
        &self,
        key: &str,
        _current_group: Option<String>,
    ) -> Result<serde_json::Value, anyhow::Error> {
        let stash = self.stash.lock().await;
        match stash.get(key, self.current_group.as_deref())? {
            Some(v) => Ok(v.clone()),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn delete(
        &self,
        key: &str,
        _current_group: Option<String>,
    ) -> Result<serde_json::Value, anyhow::Error> {
        let mut stash = self.stash.lock().await;
        let deleted = stash.delete(key, self.current_group.as_deref())?;
        Ok(serde_json::json!({"deleted": deleted}))
    }

    async fn keys(
        &self,
        _current_group: Option<String>,
    ) -> Result<serde_json::Value, anyhow::Error> {
        let stash = self.stash.lock().await;
        let keys: Vec<&str> = stash.keys(self.current_group.as_deref());
        Ok(serde_json::json!(keys))
    }
}

impl ForgeServer {
    /// Create a new Forge server with the given config, manifest, dispatcher,
    /// and optional resource dispatcher.
    pub fn new(
        config: SandboxConfig,
        manifest: Manifest,
        dispatcher: Arc<dyn ToolDispatcher>,
        resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    ) -> Self {
        Self {
            executor: Arc::new(SandboxExecutor::new(config)),
            manifest: Arc::new(manifest),
            dispatcher,
            resource_dispatcher,
            group_policy: None,
            session_stash: None,
            tool_router: Self::tool_router(),
        }
    }

    /// Set a group policy for cross-server data flow enforcement.
    ///
    /// When set, each `execute()` call wraps the dispatcher with a fresh
    /// [`GroupEnforcingDispatcher`] that tracks group access for that execution.
    /// If a resource dispatcher is also configured, it is wrapped with a
    /// [`GroupEnforcingResourceDispatcher`] sharing the same lock.
    pub fn with_group_policy(mut self, policy: GroupPolicy) -> Self {
        if !policy.is_empty() {
            self.group_policy = Some(Arc::new(policy));
        }
        self
    }

    /// Enable the session stash with the given configuration.
    ///
    /// When enabled, `forge.stash.put/get/delete/keys()` are available in
    /// sandbox execute mode.
    pub fn with_stash(mut self, config: StashConfig) -> Self {
        self.session_stash = Some(Arc::new(tokio::sync::Mutex::new(SessionStash::new(config))));
        self
    }
}

/// Input for the `search` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchInput {
    /// JavaScript async arrow function to search the capability manifest.
    /// The manifest is available as `globalThis.manifest` with servers,
    /// categories, and tool schemas.
    ///
    /// IMPORTANT: `server.categories` is an Object keyed by name (NOT an array).
    /// Use `Object.entries(s.categories)` or `Object.values(s.categories)` to iterate.
    /// Each category has a `.tools` Array with `.name`, `.description`, `.input_schema`.
    /// Check `input_schema.required` before calling a tool to get the right parameters.
    pub code: String,
}

/// Input for the `execute` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteInput {
    /// JavaScript async arrow function to execute against the tool API.
    /// Use `forge.callTool(server, tool, args)` or
    /// `forge.server("name").category.tool(args)` to call tools.
    ///
    /// Runs in a sandboxed V8 isolate — no filesystem, network, or module access.
    /// `import()`, `require()`, `eval()`, and `Deno.*` are all blocked.
    pub code: String,
}

#[tool_router(router = tool_router)]
impl ForgeServer {
    /// Search the capability manifest to discover available tools across all
    /// connected servers. The manifest is available as `globalThis.manifest`.
    #[tool(
        name = "search",
        description = "Search the capability manifest to discover available tools across all connected servers. The manifest is available as `globalThis.manifest` with servers, categories, and tool schemas. Write a JavaScript async arrow function to query it.\n\nManifest structure: manifest.servers is an Array of {name, description, categories}. IMPORTANT: categories is an Object keyed by name (NOT an array) — use Object.entries() or Object.values() to iterate. Each category has a .tools Array with {name, description, input_schema}. Check input_schema for required parameters before calling a tool.\n\nExample: `async () => { const s = manifest.servers[0]; return Object.entries(s.categories).map(([name, cat]) => ({ name, tools: cat.tools.map(t => t.name) })); }`"
    )]
    pub async fn search(
        &self,
        Parameters(input): Parameters<SearchInput>,
    ) -> Result<String, String> {
        tracing::info!(code_len = input.code.len(), "search: starting");

        let manifest_json = self
            .manifest
            .to_json()
            .map_err(|e| format!("manifest serialization failed: {e}"))?;

        match self
            .executor
            .execute_search(&input.code, &manifest_json)
            .await
        {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result)
                    .map_err(|e| format!("result serialization failed: {e}"))?;
                tracing::info!(result_len = json.len(), "search: complete");
                Ok(json)
            }
            Err(e) => {
                tracing::warn!(error = %e, "search: failed");
                Err(forge_sandbox::redact::redact_error_message(&format!("{e}")))
            }
        }
    }

    /// Execute code against the tool API in a sandboxed V8 isolate.
    #[tool(
        name = "execute",
        description = "Execute JavaScript against the tool API. Use `forge.server('name').category.tool(args)` or `forge.callTool(server, tool, args)` to call tools on connected servers. Chain multiple operations in a single call.\n\nIMPORTANT: Code runs in a sandboxed V8 isolate with NO filesystem, network, or module access. import(), require(), eval(), and Deno.* are all blocked. Use forge.callTool() for all external operations.\n\nExample: `async () => { const result = await forge.callTool('narsil', 'scan_security', { repo: 'MyProject' }); return result; }`\n\nAdditional APIs:\n- `forge.readResource(server, uri)` — read MCP resources\n- `forge.stash.put(key, value, {ttl?})` / `.get(key)` / `.delete(key)` / `.keys()` — session key-value store\n- `forge.parallel(calls, opts)` — bounded concurrent execution"
    )]
    pub async fn execute(
        &self,
        Parameters(input): Parameters<ExecuteInput>,
    ) -> Result<String, String> {
        tracing::info!(code_len = input.code.len(), "execute: starting");

        // Wrap dispatcher(s) with group enforcement if a policy is configured.
        // A fresh pair of GroupEnforcingDispatcher/GroupEnforcingResourceDispatcher
        // is created per-execution so that group locking state doesn't leak
        // between executions. Both share the same lock for consistent enforcement.
        let (dispatcher, resource_dispatcher): (
            Arc<dyn ToolDispatcher>,
            Option<Arc<dyn ResourceDispatcher>>,
        ) = match &self.group_policy {
            Some(policy) => {
                let tool_enforcer =
                    GroupEnforcingDispatcher::new(self.dispatcher.clone(), policy.clone());
                let shared_lock = tool_enforcer.shared_lock();

                let resource = self.resource_dispatcher.as_ref().map(|rd| {
                    Arc::new(GroupEnforcingResourceDispatcher::new(
                        rd.clone(),
                        policy.clone(),
                        shared_lock,
                    )) as Arc<dyn ResourceDispatcher>
                });

                (Arc::new(tool_enforcer), resource)
            }
            None => (self.dispatcher.clone(), self.resource_dispatcher.clone()),
        };

        // Create stash dispatcher if session stash is configured
        let stash_dispatcher: Option<Arc<dyn StashDispatcher>> =
            self.session_stash.as_ref().map(|stash| {
                Arc::new(ServerStashDispatcher {
                    stash: stash.clone(),
                    current_group: None, // Group tracking done at ForgeServer level
                }) as Arc<dyn StashDispatcher>
            });

        // SR-R6: Collect known server names from manifest for op-level validation
        let known_servers: std::collections::HashSet<String> = self
            .manifest
            .servers
            .iter()
            .map(|s| s.name.clone())
            .collect();

        match self
            .executor
            .execute_code_with_options(
                &input.code,
                dispatcher,
                resource_dispatcher,
                stash_dispatcher,
                Some(known_servers),
            )
            .await
        {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result)
                    .map_err(|e| format!("result serialization failed: {e}"))?;
                tracing::info!(result_len = json.len(), "execute: complete");
                Ok(json)
            }
            Err(e) => {
                tracing::warn!(error = %e, "execute: failed");
                Err(forge_sandbox::redact::redact_error_message(&format!("{e}")))
            }
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ForgeServer {
    fn get_info(&self) -> ServerInfo {
        let stats = format!(
            "{} servers, {} tools",
            self.manifest.total_servers(),
            self.manifest.total_tools(),
        );

        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(format!(
                "Forgemax Code Mode Gateway ({stats}). \
                 Use search() to discover available tools, then execute() to call them.\n\
                 \n\
                 Both tools take a `code` parameter containing a JavaScript async arrow function.\n\
                 Example: `async () => {{ return manifest.servers.map(s => s.name); }}`\n\
                 \n\
                 Manifest shape:\n\
                 - manifest.servers: Array of {{ name, description, categories }}\n\
                 - server.categories: Object (NOT array) keyed by category name, e.g. categories[\"ast\"]\n\
                 - Use Object.entries(s.categories) or Object.values(s.categories) to iterate categories\n\
                 - Each category has .tools (Array) with .name, .description, .input_schema\n\
                 - Always check a tool's input_schema.required before calling it\n\
                 \n\
                 Sandboxed environment — no filesystem, network, or module imports (import/require/eval are blocked). \
                 Use forge.callTool(server, tool, args) for all external operations.\n\
                 \n\
                 Additional APIs (execute mode only):\n\
                 - forge.readResource(server, uri) — read MCP resources from downstream servers\n\
                 - forge.stash.put(key, value, {{ttl?}}) / .get(key) / .delete(key) / .keys() — \
                 session-scoped key-value store for sharing data across executions\n\
                 - forge.parallel(calls, opts) — bounded concurrent execution of tool/resource calls"
            )),
            server_info: Implementation {
                name: "forge".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                title: None,
                description: None,
                icons: None,
                website_url: None,
            },
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_manifest::{Category, ManifestBuilder, ServerBuilder, ToolEntry};

    struct TestDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for TestDispatcher {
        async fn call_tool(
            &self,
            server: &str,
            tool: &str,
            args: serde_json::Value,
        ) -> Result<serde_json::Value, anyhow::Error> {
            Ok(serde_json::json!({
                "server": server,
                "tool": tool,
                "args": args,
                "status": "ok"
            }))
        }
    }

    fn test_server() -> ForgeServer {
        let manifest = ManifestBuilder::new()
            .add_server(
                ServerBuilder::new("test-server", "A test server")
                    .add_category(Category {
                        name: "tools".into(),
                        description: "Test tools".into(),
                        tools: vec![ToolEntry {
                            name: "echo".into(),
                            description: "Echoes input".into(),
                            params: vec![],
                            returns: Some("The input".into()),
                            input_schema: None,
                        }],
                    })
                    .build(),
            )
            .build();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        ForgeServer::new(SandboxConfig::default(), manifest, dispatcher, None)
    }

    #[test]
    fn get_info_returns_correct_metadata() {
        let server = test_server();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "forge");
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
        let instructions = info.instructions.unwrap();
        assert!(instructions.contains("search()"));
        assert!(instructions.contains("execute()"));
        assert!(instructions.contains("1 servers, 1 tools"));
        // Verify improved documentation is present
        assert!(
            instructions.contains("async arrow function"),
            "instructions should mention async arrow function format"
        );
        assert!(
            instructions.contains("Object (NOT array)"),
            "instructions should warn about categories being an Object"
        );
        assert!(
            instructions.contains("input_schema"),
            "instructions should mention input_schema for parameter discovery"
        );
        assert!(
            instructions.contains("no filesystem"),
            "instructions should mention sandbox constraints"
        );
    }

    #[tokio::test]
    async fn search_returns_json() {
        let server = test_server();
        let result = server
            .search(Parameters(SearchInput {
                code: r#"async () => { return manifest.servers.map(s => s.name); }"#.into(),
            }))
            .await;
        match result {
            Ok(json) => {
                let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
                let names = parsed.as_array().unwrap();
                assert_eq!(names[0], "test-server");
            }
            Err(e) => panic!("search should succeed: {e}"),
        }
    }

    #[tokio::test]
    async fn search_with_invalid_code_returns_error() {
        let server = test_server();
        let result = server
            .search(Parameters(SearchInput {
                // eval( is a banned pattern
                code: r#"async () => { return eval("bad"); }"#.into(),
            }))
            .await;
        assert!(result.is_err(), "search with banned code should fail");
        assert!(result.unwrap_err().contains("banned pattern"));
    }

    #[tokio::test]
    async fn execute_calls_tool() {
        let server = test_server();
        let result = server
            .execute(Parameters(ExecuteInput {
                code: r#"async () => {
                    return await forge.callTool("test-server", "tools.echo", { msg: "hi" });
                }"#
                .into(),
            }))
            .await;
        match result {
            Ok(json) => {
                let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(parsed["server"], "test-server");
                assert_eq!(parsed["tool"], "tools.echo");
                assert_eq!(parsed["status"], "ok");
            }
            Err(e) => panic!("execute should succeed: {e}"),
        }
    }

    #[tokio::test]
    async fn execute_with_banned_code_returns_error() {
        let server = test_server();
        let result = server
            .execute(Parameters(ExecuteInput {
                code: r#"async () => { return eval("bad"); }"#.into(),
            }))
            .await;
        assert!(result.is_err(), "execute with banned code should fail");
        assert!(result.unwrap_err().contains("banned pattern"));
    }

    #[tokio::test]
    async fn empty_code_returns_error() {
        let server = test_server();
        let result = server
            .search(Parameters(SearchInput { code: "   ".into() }))
            .await;
        assert!(result.is_err(), "empty code should fail");
        assert!(result.unwrap_err().contains("empty"));
    }
}
