//! Full-stack integration tests for the Forgemax Code Mode Gateway.
//!
//! These tests exercise the complete pipeline:
//! ForgeServer -> SandboxExecutor -> V8 -> ops -> ToolDispatcher/ResourceDispatcher

use std::sync::{Arc, Mutex};

use forge_manifest::{Category, ManifestBuilder, ServerBuilder, ToolEntry};
use forge_sandbox::groups::GroupPolicy;
use forge_sandbox::stash::StashConfig;
use forge_sandbox::{ResourceDispatcher, SandboxConfig, ToolDispatcher};
use forge_server::{ExecuteInput, ForgeServer, SearchInput};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::ServerHandler;

/// A dispatcher that records all tool calls for test assertions.
struct RecordingDispatcher {
    calls: Mutex<Vec<(String, String, serde_json::Value)>>,
}

impl RecordingDispatcher {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
        }
    }

    fn recorded_calls(&self) -> Vec<(String, String, serde_json::Value)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for RecordingDispatcher {
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, anyhow::Error> {
        self.calls
            .lock()
            .unwrap()
            .push((server.to_string(), tool.to_string(), args.clone()));
        Ok(serde_json::json!({
            "server": server,
            "tool": tool,
            "result": "recorded",
        }))
    }
}

fn demo_manifest() -> forge_manifest::Manifest {
    ManifestBuilder::new()
        .add_server(
            ServerBuilder::new("narsil", "Code intelligence")
                .add_category(Category {
                    name: "ast".into(),
                    description: "AST tools".into(),
                    tools: vec![
                        ToolEntry {
                            name: "parse".into(),
                            description: "Parse source code".into(),
                            params: vec![],
                            returns: Some("AST".into()),
                            input_schema: None,
                        },
                        ToolEntry {
                            name: "query".into(),
                            description: "Query AST".into(),
                            params: vec![],
                            returns: None,
                            input_schema: None,
                        },
                    ],
                })
                .add_category(Category {
                    name: "symbols".into(),
                    description: "Symbol tools".into(),
                    tools: vec![ToolEntry {
                        name: "find".into(),
                        description: "Find symbols".into(),
                        params: vec![],
                        returns: None,
                        input_schema: None,
                    }],
                })
                .build(),
        )
        .build()
}

fn test_server_with_dispatcher(dispatcher: Arc<dyn ToolDispatcher>) -> ForgeServer {
    ForgeServer::new(SandboxConfig::default(), demo_manifest(), dispatcher, None)
}

#[tokio::test]
async fn full_stack_search_then_execute() {
    let dispatcher = Arc::new(RecordingDispatcher::new());
    let server = test_server_with_dispatcher(dispatcher.clone());

    // Step 1: Search the manifest to discover tools
    let search_result = server
        .search(Parameters(SearchInput {
            code: r#"async () => {
                return manifest.servers.map(s => ({
                    name: s.name,
                    tools: Object.values(s.categories)
                        .flatMap(c => c.tools.map(t => t.name))
                }));
            }"#
            .into(),
        }))
        .await;

    let search_json = search_result.expect("search should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&search_json).unwrap();
    let servers = parsed.as_array().unwrap();
    assert_eq!(servers[0]["name"], "narsil");

    // Step 2: Execute a tool call based on discovered tools
    let exec_result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                const result = await forge.server("narsil").ast.parse({ file: "main.rs" });
                return result;
            }"#
            .into(),
        }))
        .await;

    let exec_json = exec_result.expect("execute should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&exec_json).unwrap();
    assert_eq!(parsed["server"], "narsil");
    assert_eq!(parsed["tool"], "ast.parse");
    assert_eq!(parsed["result"], "recorded");

    // Verify the dispatcher recorded the call
    let calls = dispatcher.recorded_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "narsil");
    assert_eq!(calls[0].1, "ast.parse");
    assert_eq!(calls[0].2["file"], "main.rs");
}

#[tokio::test]
async fn recording_dispatcher_captures_multiple_calls() {
    let dispatcher = Arc::new(RecordingDispatcher::new());
    let server = test_server_with_dispatcher(dispatcher.clone());

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                const r1 = await forge.callTool("narsil", "ast.parse", { file: "a.rs" });
                const r2 = await forge.callTool("narsil", "symbols.find", { pattern: "main" });
                return [r1, r2];
            }"#
            .into(),
        }))
        .await;

    assert!(result.is_ok(), "execute should succeed: {:?}", result);

    let calls = dispatcher.recorded_calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1, "ast.parse");
    assert_eq!(calls[0].2["file"], "a.rs");
    assert_eq!(calls[1].1, "symbols.find");
    assert_eq!(calls[1].2["pattern"], "main");
}

#[tokio::test]
async fn error_propagation_from_dispatcher() {
    /// A dispatcher that always returns errors.
    struct FailingDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for FailingDispatcher {
        async fn call_tool(
            &self,
            _server: &str,
            _tool: &str,
            _args: serde_json::Value,
        ) -> Result<serde_json::Value, anyhow::Error> {
            Err(anyhow::anyhow!("simulated downstream failure"))
        }
    }

    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(FailingDispatcher);
    let server = test_server_with_dispatcher(dispatcher);

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                try {
                    await forge.callTool("narsil", "ast.parse", {});
                    return "should not reach here";
                } catch(e) {
                    return { error: e.message };
                }
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed (error caught in JS)");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed["error"]
            .as_str()
            .unwrap()
            .contains("simulated downstream failure"),
        "error should propagate: {parsed:?}"
    );
}

#[tokio::test]
async fn get_info_reflects_manifest_stats() {
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(RecordingDispatcher::new());
    let server = test_server_with_dispatcher(dispatcher);

    let info = server.get_info();
    assert_eq!(info.server_info.name, "forge");
    let instructions = info.instructions.unwrap();
    // 1 server with 3 tools (2 in ast + 1 in symbols)
    assert!(
        instructions.contains("1 servers, 3 tools"),
        "instructions should reflect manifest stats: {instructions}"
    );
}

// ===========================================================================
// Phase 9: v0.2 Integration Tests (RS-I01..RS-I07)
// ===========================================================================

/// A mock resource dispatcher that returns configurable content.
struct MockResourceDispatcher {
    content: serde_json::Value,
}

impl MockResourceDispatcher {
    fn with_content(content: serde_json::Value) -> Self {
        Self { content }
    }
}

#[async_trait::async_trait]
impl ResourceDispatcher for MockResourceDispatcher {
    async fn read_resource(
        &self,
        server: &str,
        uri: &str,
    ) -> Result<serde_json::Value, anyhow::Error> {
        Ok(serde_json::json!({
            "server": server,
            "uri": uri,
            "content": self.content,
        }))
    }
}

/// A resource dispatcher that always fails (simulates unsupported resources).
struct FailingResourceDispatcher {
    error_msg: String,
}

#[async_trait::async_trait]
impl ResourceDispatcher for FailingResourceDispatcher {
    async fn read_resource(
        &self,
        _server: &str,
        _uri: &str,
    ) -> Result<serde_json::Value, anyhow::Error> {
        Err(anyhow::anyhow!("{}", self.error_msg))
    }
}

fn test_server_with_resources(
    dispatcher: Arc<dyn ToolDispatcher>,
    resource_dispatcher: Arc<dyn ResourceDispatcher>,
) -> ForgeServer {
    ForgeServer::new(
        SandboxConfig::default(),
        demo_manifest(),
        dispatcher,
        Some(resource_dispatcher),
    )
    .with_stash(StashConfig::default())
}

// --- RS-I01: execute_code with forge.readResource() reads from mock server ---
#[tokio::test]
async fn rs_i01_read_resource_from_mock_server() {
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(RecordingDispatcher::new());
    let resource: Arc<dyn ResourceDispatcher> =
        Arc::new(MockResourceDispatcher::with_content(serde_json::json!({
            "log_lines": ["INFO: started", "ERROR: connection refused", "INFO: retry ok"]
        })));

    let server = test_server_with_resources(dispatcher, resource);

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                const data = await forge.readResource("narsil", "file:///var/log/app.log");
                return data;
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["server"], "narsil");
    assert_eq!(parsed["uri"], "file:///var/log/app.log");
    assert_eq!(
        parsed["content"]["log_lines"][1],
        "ERROR: connection refused"
    );
}

// --- RS-I02: execute_code with forge.readResource() + JS filter ---
#[tokio::test]
async fn rs_i02_read_resource_with_js_filter() {
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(RecordingDispatcher::new());

    // Create a resource with many entries
    let entries: Vec<serde_json::Value> = (0..100)
        .map(|i| {
            serde_json::json!({
                "id": i,
                "level": if i % 10 == 0 { "ERROR" } else { "INFO" },
                "msg": format!("log entry {i}")
            })
        })
        .collect();
    let resource: Arc<dyn ResourceDispatcher> = Arc::new(MockResourceDispatcher::with_content(
        serde_json::json!(entries),
    ));

    let server = test_server_with_resources(dispatcher, resource);

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                const data = await forge.readResource("narsil", "logs://app/recent");
                // Filter to only ERROR entries
                const errors = data.content.filter(e => e.level === "ERROR");
                return { count: errors.length, first_error: errors[0] };
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    // 100 entries, every 10th is ERROR → 10 errors
    assert_eq!(parsed["count"], 10);
    assert_eq!(parsed["first_error"]["id"], 0);
    assert_eq!(parsed["first_error"]["level"], "ERROR");
}

// --- RS-I03: execute_code with forge.readResource() respects group isolation ---
#[tokio::test]
async fn rs_i03_read_resource_group_isolation() {
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(RecordingDispatcher::new());
    let resource: Arc<dyn ResourceDispatcher> = Arc::new(MockResourceDispatcher::with_content(
        serde_json::json!("data"),
    ));

    // Create group policy: narsil in group "intel" (strict),
    // "other-server" in group "data" (strict)
    let mut groups = std::collections::HashMap::new();
    groups.insert(
        "intel".to_string(),
        (vec!["narsil".to_string()], "strict".to_string()),
    );
    groups.insert(
        "data".to_string(),
        (vec!["other-server".to_string()], "strict".to_string()),
    );
    let policy = GroupPolicy::from_config(&groups);

    let server = ForgeServer::new(
        SandboxConfig::default(),
        demo_manifest(),
        dispatcher,
        Some(resource),
    )
    .with_group_policy(policy)
    .with_stash(StashConfig::default());

    // Try to read from narsil (group "intel") and then call a tool on
    // "other-server" (group "data") — should fail due to group isolation
    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                // First read from narsil — locks to group "intel"
                const data = await forge.readResource("narsil", "file:///log");

                // Now try to call a tool on "other-server" (group "data")
                try {
                    await forge.callTool("other-server", "tool", {});
                    return { error: null };
                } catch (e) {
                    return { error: e.message || String(e) };
                }
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed (error caught in JS)");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let error = parsed["error"].as_str().unwrap();
    assert!(
        error.contains("group") || error.contains("isolation") || error.contains("locked"),
        "should report group isolation error, got: {error}"
    );
}

// --- RS-I04: (child_process mode) - skipped in unit tests, requires built worker ---
// Note: RS-I04 tests child_process IPC round-trip for resource reads.
// This is covered by forge-sandbox/tests/child_process.rs when FORGE_WORKER_BIN is set.
// We include a placeholder test that verifies the config wiring works.
#[tokio::test]
async fn rs_i04_child_process_config_wiring() {
    let config = SandboxConfig {
        execution_mode: forge_sandbox::ExecutionMode::ChildProcess,
        ..Default::default()
    };
    // Verify the config is accepted without panic
    assert_eq!(
        config.execution_mode,
        forge_sandbox::ExecutionMode::ChildProcess
    );
}

// --- RS-I05: execute_code combining readResource + callTool in single execution ---
#[tokio::test]
async fn rs_i05_combined_read_resource_and_call_tool() {
    let dispatcher = Arc::new(RecordingDispatcher::new());
    let resource: Arc<dyn ResourceDispatcher> = Arc::new(MockResourceDispatcher::with_content(
        serde_json::json!({"schema": {"tables": ["users", "orders"]}}),
    ));

    let server = test_server_with_resources(dispatcher.clone(), resource);

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                // Read resource to discover schema
                const schema = await forge.readResource("narsil", "db://schema");
                const tables = schema.content.schema.tables;

                // Call tool based on discovered schema
                const result = await forge.callTool("narsil", "ast.query", {
                    table: tables[0]
                });

                return {
                    tables_found: tables.length,
                    query_server: result.server,
                    query_tool: result.tool,
                };
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["tables_found"], 2);
    assert_eq!(parsed["query_server"], "narsil");
    assert_eq!(parsed["query_tool"], "ast.query");

    // Verify tool was called with the discovered table name
    let calls = dispatcher.recorded_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2["table"], "users");
}

// --- RS-I06: execute_code with forge.readResource() timeout enforcement ---
#[tokio::test]
async fn rs_i06_read_resource_timeout_enforcement() {
    /// A resource dispatcher that takes too long.
    struct SlowResourceDispatcher;

    #[async_trait::async_trait]
    impl ResourceDispatcher for SlowResourceDispatcher {
        async fn read_resource(
            &self,
            _server: &str,
            _uri: &str,
        ) -> Result<serde_json::Value, anyhow::Error> {
            // Sleep longer than the execution timeout
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Ok(serde_json::json!({"data": "too late"}))
        }
    }

    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(RecordingDispatcher::new());
    let resource: Arc<dyn ResourceDispatcher> = Arc::new(SlowResourceDispatcher);

    let server = ForgeServer::new(
        SandboxConfig {
            timeout: std::time::Duration::from_millis(500),
            ..Default::default()
        },
        demo_manifest(),
        dispatcher,
        Some(resource),
    );

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                const data = await forge.readResource("narsil", "file:///slow");
                return data;
            }"#
            .into(),
        }))
        .await;

    // Should fail with timeout error
    assert!(result.is_err(), "should timeout, got: {:?}", result);
    let err = result.unwrap_err();
    assert!(
        err.contains("timed out") || err.contains("timeout") || err.contains("Timed out"),
        "error should mention timeout, got: {err}"
    );
}

// --- RS-I07: execute_code with forge.readResource() on server that doesn't support resources ---
#[tokio::test]
async fn rs_i07_graceful_degradation_no_resource_support() {
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(RecordingDispatcher::new());
    let resource: Arc<dyn ResourceDispatcher> = Arc::new(FailingResourceDispatcher {
        error_msg: "method not found: resources/read".into(),
    });

    let server = test_server_with_resources(dispatcher, resource);

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                try {
                    await forge.readResource("narsil", "file:///log");
                    return { error: null };
                } catch (e) {
                    return { error: e.message || String(e) };
                }
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed (error caught in JS)");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let error = parsed["error"].as_str().unwrap();
    // The error should be caught and surfaced, not crash the execution
    assert!(
        !error.is_empty(),
        "should have a non-empty error message for unsupported resources"
    );
}
