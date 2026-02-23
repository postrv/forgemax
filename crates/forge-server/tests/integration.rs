//! Full-stack integration tests for the Forge Code Mode Gateway.
//!
//! These tests exercise the complete pipeline:
//! ForgeServer -> SandboxExecutor -> V8 -> ops -> ToolDispatcher

use std::sync::{Arc, Mutex};

use forge_manifest::{Category, ManifestBuilder, ServerBuilder, ToolEntry};
use forge_sandbox::{SandboxConfig, ToolDispatcher};
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
    ForgeServer::new(SandboxConfig::default(), demo_manifest(), dispatcher)
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
