//! Minimal MCP server for integration testing.
//!
//! Exposes a few tools that can be called via stdio transport.
//! Used by forge-client integration tests.

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use serde::Deserialize;

#[derive(Clone)]
struct TestServer {
    tool_router: ToolRouter<Self>,
}

impl TestServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EchoInput {
    /// The message to echo back.
    message: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AddInput {
    /// First number.
    a: f64,
    /// Second number.
    b: f64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchSymbolsInput {
    /// Pattern to search for.
    pattern: String,
    /// Maximum results to return.
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    10
}

#[tool_router(router = tool_router)]
impl TestServer {
    /// Echo a message back.
    #[tool(name = "echo", description = "Echo a message back unchanged")]
    async fn echo(&self, Parameters(input): Parameters<EchoInput>) -> Result<String, String> {
        Ok(serde_json::json!({
            "echoed": input.message
        })
        .to_string())
    }

    /// Add two numbers.
    #[tool(name = "math.add", description = "Add two numbers together")]
    async fn add(&self, Parameters(input): Parameters<AddInput>) -> Result<String, String> {
        Ok(serde_json::json!({
            "result": input.a + input.b
        })
        .to_string())
    }

    /// Search for symbols (mock).
    #[tool(
        name = "symbols.find",
        description = "Find symbol definitions matching a pattern"
    )]
    async fn find_symbols(
        &self,
        Parameters(input): Parameters<SearchSymbolsInput>,
    ) -> Result<String, String> {
        let results: Vec<serde_json::Value> = (0..input.limit.min(3))
            .map(|i| {
                serde_json::json!({
                    "name": format!("{}_{}", input.pattern, i),
                    "kind": "function",
                    "file": format!("src/lib.rs"),
                    "line": i * 10 + 1,
                })
            })
            .collect();
        Ok(serde_json::to_string(&results).unwrap())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for TestServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some("Test MCP server for Forge integration tests".into()),
            server_info: Implementation {
                name: "forge-test-server".into(),
                version: "0.1.0".into(),
                title: None,
                description: None,
                icons: None,
                website_url: None,
            },
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() {
    let server = TestServer::new();
    let service = server.serve(rmcp::transport::io::stdio()).await.unwrap();
    service.waiting().await.unwrap();
}
