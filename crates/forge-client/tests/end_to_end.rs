//! End-to-end integration tests for the Forgemax Code Mode Gateway.
//!
//! These tests spawn a real mock MCP server (forge-test-server) as a child
//! process, connect to it via McpClient, build a manifest from live tool
//! discovery, and exercise the full search → execute pipeline.

use std::sync::Arc;

use forge_client::{McpClient, RouterDispatcher};
use forge_manifest::{server_entry_from_tools, ManifestBuilder, McpTool};
use forge_sandbox::{SandboxConfig, ToolDispatcher};
use forge_server::{ExecuteInput, ForgeServer, SearchInput};
use rmcp::handler::server::wrapper::Parameters;

/// Path to the test server binary (built by cargo).
fn test_server_bin() -> String {
    // The binary is in target/debug/ when built with cargo test
    let mut path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push("forge-test-server");
    path.to_str().unwrap().to_string()
}

/// Connect to the test server and build a ForgeServer wired to it.
async fn setup_forge_with_test_server() -> (ForgeServer, Arc<McpClient>) {
    let bin = test_server_bin();
    let client = McpClient::connect_stdio("test-server", &bin, &[])
        .await
        .expect("failed to connect to test server");

    // Discover tools
    let tools = client.list_tools().await.expect("failed to list tools");
    assert!(!tools.is_empty(), "test server should expose tools");

    // Build manifest from live tool list
    let mcp_tools: Vec<McpTool> = tools
        .into_iter()
        .map(|t| McpTool {
            name: t.name,
            description: t.description,
            input_schema: Some(t.input_schema),
        })
        .collect();

    let server_entry = server_entry_from_tools("test-server", "Mock test server", mcp_tools);
    let manifest = ManifestBuilder::new().add_server(server_entry).build();

    let client = Arc::new(client);

    // Wire up router
    let mut router = RouterDispatcher::new();
    router.add_client("test-server", client.clone() as Arc<dyn ToolDispatcher>);

    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(router);
    let server = ForgeServer::new(SandboxConfig::default(), manifest, dispatcher);

    (server, client)
}

#[tokio::test]
async fn mcpclient_connects_to_stdio_server() {
    let bin = test_server_bin();
    let client = McpClient::connect_stdio("test-server", &bin, &[])
        .await
        .expect("failed to connect to test server");

    assert_eq!(client.name(), "test-server");

    let tools = client.list_tools().await.expect("failed to list tools");
    assert!(
        tools.len() >= 3,
        "expected at least 3 tools, got {}",
        tools.len()
    );

    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(tool_names.contains(&"echo"), "should have echo tool");
    assert!(
        tool_names.contains(&"math.add"),
        "should have math.add tool"
    );
    assert!(
        tool_names.contains(&"symbols.find"),
        "should have symbols.find tool"
    );

    client.disconnect().await.expect("disconnect failed");
}

#[tokio::test]
async fn mcpclient_calls_tool_and_gets_result() {
    let bin = test_server_bin();
    let client = McpClient::connect_stdio("test-server", &bin, &[])
        .await
        .expect("failed to connect");

    let result = client
        .call_tool(
            "test-server",
            "echo",
            serde_json::json!({"message": "hello forge"}),
        )
        .await
        .expect("echo tool call failed");

    assert_eq!(result["echoed"], "hello forge");

    client.disconnect().await.ok();
}

#[tokio::test]
async fn mcpclient_handles_connection_failure() {
    let result = McpClient::connect_stdio("nonexistent", "/nonexistent/path/to/binary", &[]).await;

    assert!(
        result.is_err(),
        "connecting to nonexistent binary should fail"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("nonexistent") || err.contains("spawn") || err.contains("No such file"),
        "error should be meaningful: {err}"
    );
}

#[tokio::test]
async fn end_to_end_search_discovers_tools() {
    let (server, _client) = setup_forge_with_test_server().await;

    // Search for all server names
    let result = server
        .search(Parameters(SearchInput {
            code: r#"async () => manifest.servers.map(s => s.name)"#.into(),
        }))
        .await;

    let json = result.expect("search should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let names = parsed.as_array().unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0], "test-server");
}

#[tokio::test]
async fn end_to_end_search_discovers_categories() {
    let (server, _client) = setup_forge_with_test_server().await;

    // Search for categories and tool counts
    let result = server
        .search(Parameters(SearchInput {
            code: r#"async () => manifest.servers.map(s => ({
                name: s.name,
                categories: Object.keys(s.categories),
                totalTools: Object.values(s.categories).reduce((sum, c) => sum + c.tools.length, 0)
            }))"#
                .into(),
        }))
        .await;

    let json = result.expect("search should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let servers = parsed.as_array().unwrap();
    let server_info = &servers[0];
    assert_eq!(server_info["name"], "test-server");
    assert!(server_info["totalTools"].as_i64().unwrap() >= 3);
}

#[tokio::test]
async fn end_to_end_execute_calls_echo() {
    let (server, _client) = setup_forge_with_test_server().await;

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                return await forge.callTool("test-server", "echo", { message: "from sandbox" });
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["echoed"], "from sandbox");
}

#[tokio::test]
async fn end_to_end_execute_calls_math() {
    let (server, _client) = setup_forge_with_test_server().await;

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                return await forge.callTool("test-server", "math.add", { a: 17, b: 25 });
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["result"], 42.0);
}

#[tokio::test]
async fn end_to_end_execute_chains_multiple_calls() {
    let (server, _client) = setup_forge_with_test_server().await;

    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                const symbols = await forge.callTool("test-server", "symbols.find", {
                    pattern: "handle",
                    limit: 2
                });
                const sum = await forge.callTool("test-server", "math.add", {
                    a: symbols.length,
                    b: 10
                });
                return { symbols, sum };
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let symbols = parsed["symbols"].as_array().unwrap();
    assert_eq!(symbols.len(), 2);
    assert_eq!(symbols[0]["name"], "handle_0");
    assert_eq!(parsed["sum"]["result"], 12.0);
}

#[tokio::test]
async fn end_to_end_execute_via_proxy_api() {
    let (server, _client) = setup_forge_with_test_server().await;

    // Use the forge.server("name").category.tool(args) proxy syntax
    let result = server
        .execute(Parameters(ExecuteInput {
            code: r#"async () => {
                return await forge.server("test-server").symbols.find({
                    pattern: "main",
                    limit: 3
                });
            }"#
            .into(),
        }))
        .await;

    let json = result.expect("execute should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let symbols = parsed.as_array().unwrap();
    assert_eq!(symbols.len(), 3);
    assert_eq!(symbols[0]["name"], "main_0");
}
