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

use forge_manifest::{LiveManifest, Manifest};
use forge_sandbox::groups::{
    GroupEnforcingDispatcher, GroupEnforcingResourceDispatcher, GroupPolicy, SharedGroupLock,
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

/// Maximum result size in characters before truncation.
///
/// Results exceeding this limit are wrapped in a JSON envelope with metadata
/// about the truncation. This prevents oversized results from consuming the
/// LLM's entire context window.
const MAX_RESULT_CHARS: usize = 100_000;

/// Truncate an oversized JSON result string, wrapping it with metadata.
///
/// Short results pass through unchanged. Results exceeding [`MAX_RESULT_CHARS`]
/// are cut at a structure-aware boundary and wrapped in a JSON envelope with
/// `_truncated`, `_data_is_fragment`, `_original_chars`, `_shown_chars`, and `data`.
///
/// The `data` field is a **string fragment**, not valid JSON — LLMs should not
/// attempt to `JSON.parse()` it.
fn truncate_result_if_needed(json: String) -> String {
    if json.len() <= MAX_RESULT_CHARS {
        return json;
    }
    let budget = MAX_RESULT_CHARS.saturating_sub(300); // reserve for envelope
    let cut_point = find_safe_cut_point(&json, budget);

    serde_json::json!({
        "_truncated": true,
        "_data_is_fragment": true,
        "_original_chars": json.len(),
        "_shown_chars": cut_point,
        "data": &json[..cut_point]
    })
    .to_string()
}

/// Find the best cut point that minimizes JSON breakage.
///
/// For pretty-printed JSON (which we produce via `serde_json::to_string_pretty`),
/// cutting at a newline boundary means we always end on a complete line.
/// Falls back to the last comma, then to a character boundary.
fn find_safe_cut_point(json: &str, max_pos: usize) -> usize {
    let limit = floor_char_boundary(json, max_pos);
    let search_region = &json[..limit];

    // For pretty-printed JSON, cut at the last newline
    if let Some(pos) = search_region.rfind('\n') {
        if pos > limit / 2 {
            return pos;
        }
    }

    // Fallback: cut at the last comma (array/object separator)
    if let Some(pos) = search_region.rfind(',') {
        if pos > limit / 2 {
            return pos + 1; // include the comma
        }
    }

    // Final fallback: last valid character boundary
    search_region
        .char_indices()
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0)
}

fn floor_char_boundary(s: &str, max: usize) -> usize {
    let mut end = max.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Format a sandbox execution result for the LLM.
///
/// Shared between `search()` and `execute()` to avoid duplicated error handling.
fn format_sandbox_result(
    result: Result<serde_json::Value, impl std::fmt::Display>,
) -> Result<String, String> {
    match result {
        Ok(value) => {
            let json = serde_json::to_string_pretty(&value)
                .map_err(|e| format!("result serialization failed: {e}"))?;
            Ok(truncate_result_if_needed(json))
        }
        Err(e) => {
            let msg = format!("{e}");
            let clean = msg.strip_prefix("javascript error: ").unwrap_or(&msg);
            Ok(serde_json::json!({"error": clean}).to_string())
        }
    }
}

/// The Forge MCP server handler.
///
/// Implements `ServerHandler` from rmcp to serve the `search` and `execute`
/// Code Mode tools over MCP stdio or SSE transport.
#[derive(Clone)]
pub struct ForgeServer {
    executor: Arc<SandboxExecutor>,
    manifest: LiveManifest,
    dispatcher: Arc<dyn ToolDispatcher>,
    resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    group_policy: Option<Arc<GroupPolicy>>,
    session_stash: Option<Arc<tokio::sync::Mutex<SessionStash>>>,
    tool_router: ToolRouter<Self>,
}

struct ExecutionDispatchers {
    dispatcher: Arc<dyn ToolDispatcher>,
    resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    group_lock: Option<SharedGroupLock>,
}

/// Stash dispatcher that wraps a shared [`SessionStash`] behind a Mutex.
///
/// Created per-execution by `ForgeServer::execute()` to provide the stash API
/// to sandbox code. The `current_group` is set from the server group context.
struct ServerStashDispatcher {
    stash: Arc<tokio::sync::Mutex<SessionStash>>,
    group_lock: Option<SharedGroupLock>,
}

impl ServerStashDispatcher {
    async fn current_group(&self, op_group: Option<String>) -> Option<String> {
        if let Some(lock) = &self.group_lock {
            return lock.lock().await.clone();
        }
        op_group
    }
}

#[async_trait::async_trait]
impl StashDispatcher for ServerStashDispatcher {
    async fn put(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: Option<u32>,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let ttl = ttl_secs
            .filter(|&s| s > 0)
            .map(|s| Duration::from_secs(s as u64));
        let current_group = self.current_group(current_group).await;
        let mut stash = self.stash.lock().await;
        stash
            .put(key, value, ttl, current_group.as_deref())
            .map_err(|e| forge_error::DispatchError::Internal(e.into()))?;
        Ok(serde_json::json!({"ok": true}))
    }

    async fn get(
        &self,
        key: &str,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let current_group = self.current_group(current_group).await;
        let stash = self.stash.lock().await;
        match stash
            .get(key, current_group.as_deref())
            .map_err(|e| forge_error::DispatchError::Internal(e.into()))?
        {
            Some(v) => Ok(v.clone()),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn delete(
        &self,
        key: &str,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let current_group = self.current_group(current_group).await;
        let mut stash = self.stash.lock().await;
        let deleted = stash
            .delete(key, current_group.as_deref())
            .map_err(|e| forge_error::DispatchError::Internal(e.into()))?;
        Ok(serde_json::json!({"deleted": deleted}))
    }

    async fn keys(
        &self,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let current_group = self.current_group(current_group).await;
        let stash = self.stash.lock().await;
        let keys: Vec<&str> = stash.keys(current_group.as_deref());
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
            manifest: LiveManifest::new(manifest),
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

    /// Create a new Forge server with a pre-configured executor.
    ///
    /// Use this when you need to attach a worker pool to the executor
    /// before wrapping it in the server.
    pub fn new_with_executor(
        executor: SandboxExecutor,
        manifest: Manifest,
        dispatcher: Arc<dyn ToolDispatcher>,
        resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    ) -> Self {
        Self {
            executor: Arc::new(executor),
            manifest: LiveManifest::new(manifest),
            dispatcher,
            resource_dispatcher,
            group_policy: None,
            session_stash: None,
            tool_router: Self::tool_router(),
        }
    }

    /// Get a reference to the live manifest for external updates.
    ///
    /// Background tasks can call [`LiveManifest::update()`] to refresh
    /// the manifest without restarting the server.
    pub fn live_manifest(&self) -> &LiveManifest {
        &self.manifest
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
    #[tracing::instrument(skip(self, input), fields(code_len = input.code.len()))]
    pub async fn search(
        &self,
        Parameters(input): Parameters<SearchInput>,
    ) -> Result<String, String> {
        tracing::info!("search: starting");

        // Snapshot the manifest for this search — lock-free read
        let manifest = self.manifest.current();
        let manifest_json = manifest
            .to_json()
            .map_err(|e| format!("manifest serialization failed: {e}"))?;

        let result = self
            .executor
            .execute_search(&input.code, &manifest_json)
            .await;

        if result.is_ok() {
            tracing::info!("search: complete");
        } else {
            tracing::warn!("search: failed");
        }

        format_sandbox_result(result)
    }

    /// Execute code against the tool API in a sandboxed V8 isolate.
    #[tool(
        name = "execute",
        description = "Execute JavaScript against the tool API. Use `forge.server('name').category.tool(args)` or `forge.callTool(server, tool, args)` to call tools on connected servers. Chain multiple operations in a single call.\n\nIMPORTANT: Code runs in a sandboxed V8 isolate with NO filesystem, network, or module access. import(), require(), eval(), and Deno.* are all blocked. Use forge.callTool() for all external operations.\n\nExample: `async () => { const result = await forge.callTool('narsil', 'scan_security', { repo: 'MyProject' }); return result; }`\n\nAdditional APIs:\n- `forge.readResource(server, uri)` — read MCP resources\n- `forge.stash.put(key, value, {ttl?})` / `.get(key)` / `.delete(key)` / `.keys()` — session key-value store\n- `forge.parallel(calls, opts)` — bounded concurrent execution\n\nAlways check tool input_schema via search() before calling unfamiliar tools."
    )]
    #[tracing::instrument(skip(self, input), fields(code_len = input.code.len()))]
    pub async fn execute(
        &self,
        Parameters(input): Parameters<ExecuteInput>,
    ) -> Result<String, String> {
        tracing::info!("execute: starting");

        // Wrap dispatcher(s) with group enforcement if a policy is configured.
        // A fresh pair of GroupEnforcingDispatcher/GroupEnforcingResourceDispatcher
        // is created per-execution so that group locking state doesn't leak
        // between executions. Both share the same lock for consistent enforcement.
        let dispatchers = match &self.group_policy {
            Some(policy) => {
                let tool_enforcer =
                    GroupEnforcingDispatcher::new(self.dispatcher.clone(), policy.clone());
                let shared_lock = tool_enforcer.shared_lock();

                let resource = self.resource_dispatcher.as_ref().map(|rd| {
                    Arc::new(GroupEnforcingResourceDispatcher::new(
                        rd.clone(),
                        policy.clone(),
                        shared_lock.clone(),
                    )) as Arc<dyn ResourceDispatcher>
                });

                ExecutionDispatchers {
                    dispatcher: Arc::new(tool_enforcer),
                    resource_dispatcher: resource,
                    group_lock: Some(shared_lock),
                }
            }
            None => ExecutionDispatchers {
                dispatcher: self.dispatcher.clone(),
                resource_dispatcher: self.resource_dispatcher.clone(),
                group_lock: None,
            },
        };

        // Create stash dispatcher if session stash is configured
        let stash_dispatcher: Option<Arc<dyn StashDispatcher>> =
            self.session_stash.as_ref().map(|stash| {
                Arc::new(ServerStashDispatcher {
                    stash: stash.clone(),
                    group_lock: dispatchers.group_lock.clone(),
                }) as Arc<dyn StashDispatcher>
            });

        // Snapshot the manifest for this execution — lock-free read
        let manifest = self.manifest.current();

        // SR-R6: Collect known server names from manifest for op-level validation
        let known_servers: std::collections::HashSet<String> =
            manifest.servers.iter().map(|s| s.name.clone()).collect();

        // Collect known (server, tool) pairs for structured error fuzzy matching
        let known_tools: Vec<(String, String)> = manifest
            .servers
            .iter()
            .flat_map(|s| {
                s.categories
                    .values()
                    .flat_map(|cat| cat.tools.iter().map(|t| (s.name.clone(), t.name.clone())))
            })
            .collect();

        let result = self
            .executor
            .execute_code_with_options(
                &input.code,
                dispatchers.dispatcher,
                dispatchers.resource_dispatcher,
                stash_dispatcher,
                Some(known_servers),
                Some(known_tools),
            )
            .await;

        if result.is_ok() {
            tracing::info!("execute: complete");
        } else {
            tracing::warn!("execute: failed");
        }

        format_sandbox_result(result)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ForgeServer {
    fn get_info(&self) -> ServerInfo {
        let manifest = self.manifest.current();
        let stats = format!(
            "{} servers, {} tools",
            manifest.total_servers(),
            manifest.total_tools(),
        );

        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(format!(
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
                 When calling tools, use the tool name only (e.g. \"find_symbols\"), \
                 not the category-prefixed form (e.g. NOT \"general.find_symbols\").\n\
                 \n\
                 Additional APIs (execute mode only):\n\
                 - forge.readResource(server, uri) — read MCP resources from downstream servers\n\
                 - forge.stash.put(key, value, {{ttl?}}) / .get(key) / .delete(key) / .keys() — \
                 session-scoped key-value store for sharing data across executions\n\
                 - forge.parallel(calls, opts) — bounded concurrent execution of tool/resource calls\n\
                 \n\
                 ## TypeScript API Definitions\n\
                 \n\
                 ```typescript\n\
                 {dts}\n\
                 ```",
                dts = forge_manifest::FORGE_DTS
            ))
            .with_server_info(Implementation::new("forge", env!("CARGO_PKG_VERSION")))
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
        ) -> Result<serde_json::Value, forge_error::DispatchError> {
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

    #[tokio::test]
    async fn stash_dispatcher_uses_group_lock_for_writes_and_reads() {
        let stash = Arc::new(tokio::sync::Mutex::new(SessionStash::new(
            StashConfig::default(),
        )));
        let internal_lock: SharedGroupLock =
            Arc::new(tokio::sync::Mutex::new(Some("internal".to_string())));
        let external_lock: SharedGroupLock =
            Arc::new(tokio::sync::Mutex::new(Some("external".to_string())));

        let internal = ServerStashDispatcher {
            stash: stash.clone(),
            group_lock: Some(internal_lock),
        };
        internal
            .put("secret", serde_json::json!({"token": "red"}), None, None)
            .await
            .unwrap();

        let same_group = internal.get("secret", None).await.unwrap();
        assert_eq!(same_group["token"], "red");

        let external = ServerStashDispatcher {
            stash,
            group_lock: Some(external_lock),
        };
        let err = external.get("secret", None).await.unwrap_err();
        assert!(
            err.to_string().contains("cross-group"),
            "expected cross-group denial, got: {err}"
        );
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
        assert!(
            instructions.contains("use the tool name only"),
            "instructions should clarify tool name vs category-prefixed form"
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
        // WI-1: Errors return Ok with JSON error field (not Err) to prevent
        // sibling tool call cascade failures.
        assert!(result.is_ok(), "should return Ok with error JSON");
        let json = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            parsed["error"].as_str().unwrap().contains("banned pattern"),
            "error should mention banned pattern: {parsed}"
        );
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
        // WI-1: Errors return Ok with JSON error field (not Err)
        assert!(result.is_ok(), "should return Ok with error JSON");
        let json = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            parsed["error"].as_str().unwrap().contains("banned pattern"),
            "error should mention banned pattern: {parsed}"
        );
    }

    #[tokio::test]
    async fn empty_code_returns_error() {
        let server = test_server();
        let result = server
            .search(Parameters(SearchInput { code: "   ".into() }))
            .await;
        // WI-1: Errors return Ok with JSON error field (not Err)
        assert!(result.is_ok(), "should return Ok with error JSON");
        let json = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            parsed["error"].as_str().unwrap().contains("empty"),
            "error should mention empty: {parsed}"
        );
    }

    // --- WI-2: Output truncation tests ---

    #[test]
    fn truncate_result_short_passthrough() {
        let short = r#"{"data": "hello"}"#.to_string();
        let result = truncate_result_if_needed(short.clone());
        assert_eq!(result, short, "short strings should pass through unchanged");
    }

    #[test]
    fn truncate_result_long_truncates() {
        // Create a string longer than MAX_RESULT_CHARS
        let long = "x".repeat(MAX_RESULT_CHARS + 1000);
        let result = truncate_result_if_needed(long.clone());

        // Should be valid JSON with truncation metadata
        let parsed: serde_json::Value =
            serde_json::from_str(&result).expect("truncated result should be valid JSON");
        assert_eq!(parsed["_truncated"], true);
        assert_eq!(parsed["_original_chars"], long.len());
        let shown = parsed["_shown_chars"].as_u64().unwrap() as usize;
        assert!(
            shown < long.len(),
            "shown chars should be less than original"
        );
        assert!(shown > 0, "should show some content");
        let data = parsed["data"].as_str().unwrap();
        assert_eq!(data.len(), shown, "data length should match _shown_chars");
    }

    #[test]
    fn tr_02_truncate_cuts_at_newline() {
        // Pretty-printed JSON should be cut at a newline boundary
        let mut obj = serde_json::Map::new();
        for i in 0..5000 {
            obj.insert(format!("key_{i}"), serde_json::json!(format!("value_{i}")));
        }
        let pretty = serde_json::to_string_pretty(&obj).unwrap();
        assert!(
            pretty.len() > MAX_RESULT_CHARS,
            "test fixture should exceed limit"
        );

        let result = truncate_result_if_needed(pretty);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        let data = parsed["data"].as_str().unwrap();
        // Should end at a newline (last char of the fragment)
        assert!(
            data.ends_with('\n') || data.ends_with(','),
            "should cut at newline or comma boundary, but ends with: {:?}",
            data.chars().last()
        );
    }

    #[test]
    fn tr_03_truncate_envelope_is_valid_json() {
        let long = "x".repeat(MAX_RESULT_CHARS + 500);
        let result = truncate_result_if_needed(long);
        let parsed: serde_json::Value =
            serde_json::from_str(&result).expect("envelope should be valid JSON");
        assert!(parsed.is_object(), "envelope should be a JSON object");
        assert!(parsed.get("_truncated").is_some());
        assert!(parsed.get("data").is_some());
    }

    #[test]
    fn tr_04_truncate_data_fragment_flag() {
        let long = "y".repeat(MAX_RESULT_CHARS + 100);
        let result = truncate_result_if_needed(long);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["_data_is_fragment"], true,
            "truncated results should carry _data_is_fragment flag"
        );
    }

    #[test]
    fn tr_05_truncate_minified_json_fallback() {
        // Minified JSON (no newlines) should fall back to comma boundary
        let items: Vec<String> = (0..20000).map(|i| format!("\"item_{i}\"")).collect();
        let minified = format!("[{}]", items.join(","));
        assert!(minified.len() > MAX_RESULT_CHARS);

        let result = truncate_result_if_needed(minified);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["_truncated"], true);
        let data = parsed["data"].as_str().unwrap();
        // Should end at a comma boundary (includes the comma)
        let trimmed = data.trim_end();
        assert!(
            trimmed.ends_with(',') || trimmed.ends_with('"'),
            "minified JSON should cut at comma: ends with {:?}",
            trimmed.chars().last()
        );
    }

    #[test]
    fn tr_06_truncate_unicode_safe() {
        // Multi-byte UTF-8 should not be split mid-character
        let emoji = "\u{1F600}"; // 4-byte emoji
        let mut long = String::new();
        while long.len() < MAX_RESULT_CHARS + 500 {
            long.push_str(emoji);
        }
        let result = truncate_result_if_needed(long);
        // Should not panic, and envelope should be valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&result).expect("unicode truncation should produce valid JSON");
        assert_eq!(parsed["_truncated"], true);
    }

    #[test]
    fn tr_06b_truncate_three_byte_unicode_safe() {
        let cjk = "漢";
        let mut long = String::new();
        while long.len() < MAX_RESULT_CHARS + 500 {
            long.push_str(cjk);
        }

        let result = truncate_result_if_needed(long);
        let parsed: serde_json::Value =
            serde_json::from_str(&result).expect("unicode truncation should produce valid JSON");
        assert_eq!(parsed["_truncated"], true);
        assert!(parsed["data"].as_str().unwrap().chars().all(|c| c == '漢'));
    }

    #[test]
    fn tr_07_format_sandbox_result_ok() {
        let value = serde_json::json!({"result": "hello"});
        let result = format_sandbox_result(Ok::<_, String>(value));
        assert!(result.is_ok());
        let json = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["result"], "hello");
    }

    #[test]
    fn tr_08_format_sandbox_result_err_strips_prefix() {
        let err = "javascript error: some problem";
        let result = format_sandbox_result(Err::<serde_json::Value, _>(err));
        assert!(result.is_ok());
        let json = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"], "some problem");
    }

    // --- Phase R3: FORGE_DTS in instructions ---

    #[test]
    fn dts_01_instructions_contain_typescript_defs() {
        let server = test_server();
        let info = server.get_info();
        let instructions = info.instructions.unwrap();
        assert!(
            instructions.contains("callTool"),
            "instructions should contain callTool: {instructions}"
        );
    }

    #[test]
    fn dts_02_instructions_contain_forge_interface() {
        let server = test_server();
        let info = server.get_info();
        let instructions = info.instructions.unwrap();
        assert!(
            instructions.contains("interface") || instructions.contains("Forge"),
            "instructions should contain Forge interface"
        );
    }

    #[test]
    fn dts_03_instructions_contain_stash_types() {
        let server = test_server();
        let info = server.get_info();
        let instructions = info.instructions.unwrap();
        assert!(
            instructions.contains("ForgeStash"),
            "instructions should contain ForgeStash type"
        );
    }
}
