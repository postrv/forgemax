//! Minimal MCP server for integration testing.
//!
//! Exposes a few tools and resources that can be called via stdio transport.
//! Used by forge-client integration tests.

use std::future::Future;
use std::path::PathBuf;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    DiscoverRequestMethod, DiscoverResult, Implementation, ListResourcesResult,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult,
    Resource, ResourceContents, ServerCapabilities, ServerConfig,
};
use rmcp::schemars::JsonSchema;
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde::Deserialize;

#[derive(Clone)]
struct TestServer {
    tool_router: ToolRouter<Self>,
    legacy: bool,
    reconnect_marker: Option<PathBuf>,
}

impl TestServer {
    fn new(legacy: bool, reconnect_marker: Option<PathBuf>) -> Self {
        let mut tool_router = Self::tool_router();
        if !reconnect_marker.as_ref().is_some_and(|path| path.exists()) {
            tool_router.remove_route("reconnected");
        }
        Self {
            tool_router,
            legacy,
            reconnect_marker,
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
    async fn echo(
        &self,
        Parameters(input): Parameters<EchoInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, String> {
        if input.message == "disconnect once" {
            if let Some(path) = self.reconnect_marker.as_ref().filter(|path| !path.exists()) {
                tokio::fs::write(path, b"reconnect")
                    .await
                    .map_err(|e| e.to_string())?;
                std::process::exit(0);
            }
        }
        Ok(serde_json::json!({
            "echoed": input.message,
            "protocolVersion": context.protocol_version(),
        })
        .to_string())
    }

    #[tool(
        name = "reconnected",
        description = "Confirm the replacement process is active"
    )]
    async fn reconnected(&self) -> String {
        r#"{"reconnected":true}"#.into()
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
                    "file": "src/lib.rs",
                    "line": i * 10 + 1,
                })
            })
            .collect();
        Ok(serde_json::to_string(&results).unwrap())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for TestServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_instructions("Test MCP server for Forge integration tests")
        .with_server_info(Implementation::new("forge-test-server", "0.1.0"))
    }

    async fn discover(&self, _: RequestContext<RoleServer>) -> Result<DiscoverResult, ErrorData> {
        if self.legacy {
            return Err(ErrorData::method_not_found::<DiscoverRequestMethod>());
        }
        Ok(DiscoverResult::from_server_info(
            self.supported_protocol_versions().into_owned(),
            self.get_info(),
        ))
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, ErrorData> {
        let mut tools = self.tool_router.list_all();
        if self
            .reconnect_marker
            .as_ref()
            .is_some_and(|path| path.exists())
        {
            // Keep its handler installed so the test proves the gateway enforces the catalog.
            tools.retain(|tool| tool.name != "math.add");
        }
        Ok(rmcp::model::ListToolsResult::with_all_items(tools))
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(ListResourcesResult::with_all_items(vec![
            {
                let mut r = Resource::new("file:///logs/app.log", "Application Log");
                r.description = Some("Recent application log entries".into());
                r.mime_type = Some("text/plain".into());
                r
            },
            {
                let mut r = Resource::new("db://schema/users", "Users Table Schema");
                r.description = Some("Schema for the users table".into());
                r.mime_type = Some("application/json".into());
                r
            },
        ])))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, ErrorData>> + Send + '_ {
        std::future::ready(match request.uri.as_str() {
            "file:///logs/app.log" => Ok(ReadResourceResult::new(vec![ResourceContents::text(
                "2024-01-01 INFO startup complete",
                "file:///logs/app.log",
            )])
            .into()),
            "db://schema/users" => {
                Ok(
                    ReadResourceResult::new(vec![ResourceContents::TextResourceContents {
                        uri: "db://schema/users".into(),
                        mime_type: Some("application/json".into()),
                        text: r#"{"table":"users","columns":["id","name","email"]}"#.into(),
                        meta: None,
                    }])
                    .into(),
                )
            }
            _ => Err(ErrorData::resource_not_found(
                format!("resource not found: {}", request.uri),
                None,
            )),
        })
    }
}

#[tokio::main]
async fn main() {
    let server = TestServer::new(
        std::env::args().any(|arg| arg == "--legacy"),
        std::env::var_os("FORGE_TEST_RECONNECT_MARKER").map(PathBuf::from),
    );
    let service = server.serve(rmcp::transport::io::stdio()).await.unwrap();
    service.waiting().await.unwrap();
}
