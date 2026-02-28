//! Router dispatcher for routing tool calls to the correct downstream MCP client.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use forge_error::DispatchError;
use forge_sandbox::{ResourceDispatcher, ToolDispatcher};
use serde_json::Value;

/// A [`ToolDispatcher`] that routes `call_tool(server, tool, args)` to the
/// correct downstream MCP client based on server name.
///
/// Validates both server names and tool names before dispatching, returning
/// [`DispatchError::ServerNotFound`] or [`DispatchError::ToolNotFound`] with
/// fuzzy-match suggestions when appropriate.
pub struct RouterDispatcher {
    clients: HashMap<String, Arc<dyn ToolDispatcher>>,
    /// Known tool names per server, for pre-dispatch validation.
    known_tools: HashMap<String, HashSet<String>>,
}

impl RouterDispatcher {
    /// Create a new empty router.
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
            known_tools: HashMap::new(),
        }
    }

    /// Register a dispatcher for a named server.
    pub fn add_client(&mut self, name: impl Into<String>, client: Arc<dyn ToolDispatcher>) {
        let name = name.into();
        self.clients.insert(name.clone(), client);
        // Ensure a tools entry exists even if no tools are registered yet
        self.known_tools.entry(name).or_default();
    }

    /// Register known tool names for a server (for pre-dispatch validation).
    pub fn set_known_tools(
        &mut self,
        server: impl Into<String>,
        tools: impl IntoIterator<Item = String>,
    ) {
        self.known_tools
            .insert(server.into(), tools.into_iter().collect());
    }

    /// List all registered server names.
    pub fn server_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.clients.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    /// Number of registered servers.
    pub fn server_count(&self) -> usize {
        self.clients.len()
    }
}

impl Default for RouterDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for RouterDispatcher {
    #[tracing::instrument(skip(self, args))]
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: Value,
    ) -> Result<Value, DispatchError> {
        let client = self
            .clients
            .get(server)
            .ok_or_else(|| DispatchError::ServerNotFound(server.into()))?;

        // Pre-dispatch tool name validation: if we know the server's tools,
        // check the tool exists before sending to the upstream server.
        if let Some(tools) = self.known_tools.get(server) {
            if !tools.is_empty() && !tools.contains(tool) {
                return Err(DispatchError::ToolNotFound {
                    server: server.into(),
                    tool: tool.into(),
                });
            }
        }

        client.call_tool(server, tool, args).await
    }
}

/// A [`ResourceDispatcher`] that routes `read_resource(server, uri)` to the
/// correct downstream MCP client based on server name.
pub struct RouterResourceDispatcher {
    clients: HashMap<String, Arc<dyn ResourceDispatcher>>,
}

impl RouterResourceDispatcher {
    /// Create a new empty resource router.
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    /// Register a resource dispatcher for a named server.
    pub fn add_client(&mut self, name: impl Into<String>, client: Arc<dyn ResourceDispatcher>) {
        self.clients.insert(name.into(), client);
    }

    /// List all registered server names.
    pub fn server_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.clients.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }
}

impl Default for RouterResourceDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ResourceDispatcher for RouterResourceDispatcher {
    #[tracing::instrument(skip(self), fields(server, uri))]
    async fn read_resource(&self, server: &str, uri: &str) -> Result<Value, DispatchError> {
        let client = self
            .clients
            .get(server)
            .ok_or_else(|| DispatchError::ServerNotFound(server.into()))?;
        client.read_resource(server, uri).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A mock dispatcher that records calls and returns a fixed response.
    struct MockDispatcher {
        name: String,
        calls: Mutex<Vec<(String, String, Value)>>,
    }

    impl MockDispatcher {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl ToolDispatcher for MockDispatcher {
        async fn call_tool(
            &self,
            server: &str,
            tool: &str,
            args: Value,
        ) -> Result<Value, DispatchError> {
            self.calls
                .lock()
                .unwrap()
                .push((server.to_string(), tool.to_string(), args.clone()));
            Ok(serde_json::json!({
                "dispatcher": self.name,
                "server": server,
                "tool": tool,
                "status": "ok"
            }))
        }
    }

    /// A dispatcher that always fails.
    struct FailingDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for FailingDispatcher {
        async fn call_tool(
            &self,
            _server: &str,
            _tool: &str,
            _args: Value,
        ) -> Result<Value, DispatchError> {
            Err(DispatchError::Internal(anyhow::anyhow!(
                "downstream connection failed"
            )))
        }
    }

    #[tokio::test]
    async fn router_dispatches_to_correct_server() {
        let client_a = Arc::new(MockDispatcher::new("client-a"));
        let client_b = Arc::new(MockDispatcher::new("client-b"));

        let mut router = RouterDispatcher::new();
        router.add_client("server-a", client_a.clone());
        router.add_client("server-b", client_b.clone());

        // Call server-a
        let result = router
            .call_tool("server-a", "tool1", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(result["dispatcher"], "client-a");
        assert_eq!(result["tool"], "tool1");

        // Call server-b
        let result = router
            .call_tool("server-b", "tool2", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(result["dispatcher"], "client-b");
        assert_eq!(result["tool"], "tool2");

        // Each client received exactly one call
        assert_eq!(client_a.call_count(), 1);
        assert_eq!(client_b.call_count(), 1);
    }

    #[tokio::test]
    async fn router_returns_error_for_unknown_server() {
        let mut router = RouterDispatcher::new();
        router.add_client("known", Arc::new(MockDispatcher::new("known")));

        let result = router
            .call_tool("nonexistent", "tool", serde_json::json!({}))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DispatchError::ServerNotFound(ref s) if s == "nonexistent"),
            "expected ServerNotFound, got: {err}"
        );
    }

    #[tokio::test]
    async fn router_handles_concurrent_calls_to_same_server() {
        let client = Arc::new(MockDispatcher::new("shared"));
        let mut router = RouterDispatcher::new();
        router.add_client("server", client.clone());

        let router = Arc::new(router);
        let mut handles = Vec::new();

        for i in 0..10 {
            let router = router.clone();
            handles.push(tokio::spawn(async move {
                router
                    .call_tool("server", &format!("tool-{i}"), serde_json::json!({"i": i}))
                    .await
            }));
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "concurrent call should succeed");
        }

        assert_eq!(client.call_count(), 10, "all 10 calls should be recorded");
    }

    #[tokio::test]
    async fn router_handles_client_failure_gracefully() {
        let healthy = Arc::new(MockDispatcher::new("healthy"));
        let failing: Arc<dyn ToolDispatcher> = Arc::new(FailingDispatcher);

        let mut router = RouterDispatcher::new();
        router.add_client("healthy-server", healthy.clone());
        router.add_client("failing-server", failing);

        // Failing server returns error
        let result = router
            .call_tool("failing-server", "tool", serde_json::json!({}))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("downstream connection failed"));

        // Healthy server still works
        let result = router
            .call_tool("healthy-server", "tool", serde_json::json!({}))
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["dispatcher"], "healthy");
    }

    #[test]
    fn router_server_names_is_sorted() {
        let mut router = RouterDispatcher::new();
        router.add_client("zebra", Arc::new(MockDispatcher::new("z")));
        router.add_client("alpha", Arc::new(MockDispatcher::new("a")));
        router.add_client("middle", Arc::new(MockDispatcher::new("m")));

        assert_eq!(router.server_names(), vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn router_server_count() {
        let mut router = RouterDispatcher::new();
        assert_eq!(router.server_count(), 0);

        router.add_client("a", Arc::new(MockDispatcher::new("a")));
        router.add_client("b", Arc::new(MockDispatcher::new("b")));
        assert_eq!(router.server_count(), 2);
    }

    #[tokio::test]
    async fn router_empty_returns_error() {
        let router = RouterDispatcher::new();
        let result = router.call_tool("any", "tool", serde_json::json!({})).await;
        assert!(matches!(result, Err(DispatchError::ServerNotFound(_))));
    }

    #[tokio::test]
    async fn router_returns_tool_not_found_for_unknown_tool() {
        let mut router = RouterDispatcher::new();
        router.set_known_tools("server", vec!["tool_a".into(), "tool_b".into()]);
        router.add_client("server", Arc::new(MockDispatcher::new("server")));

        // Known tool works
        let result = router
            .call_tool("server", "tool_a", serde_json::json!({}))
            .await;
        assert!(result.is_ok(), "known tool should succeed");

        // Unknown tool returns ToolNotFound
        let result = router
            .call_tool("server", "tool_x", serde_json::json!({}))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DispatchError::ToolNotFound { ref server, ref tool }
                if server == "server" && tool == "tool_x"),
            "expected ToolNotFound, got: {err}"
        );
    }

    #[tokio::test]
    async fn router_skips_tool_validation_when_no_tools_registered() {
        let mut router = RouterDispatcher::new();
        // No set_known_tools call — tools list is empty
        router.add_client("server", Arc::new(MockDispatcher::new("server")));

        // Should pass through to the client even though tool name is unknown
        let result = router
            .call_tool("server", "anything", serde_json::json!({}))
            .await;
        assert!(result.is_ok(), "should pass through when no tools registered");
    }

    // --- v0.2 Resource Router Tests (RS-C05..RS-C06) ---

    struct MockResourceDispatcher {
        name: String,
    }

    #[async_trait::async_trait]
    impl ResourceDispatcher for MockResourceDispatcher {
        async fn read_resource(&self, server: &str, uri: &str) -> Result<Value, DispatchError> {
            Ok(serde_json::json!({
                "dispatcher": self.name,
                "server": server,
                "uri": uri,
                "content": "mock data"
            }))
        }
    }

    #[tokio::test]
    async fn rs_c05_resource_router_dispatches_to_correct_client() {
        let client_a = Arc::new(MockResourceDispatcher {
            name: "client-a".into(),
        });
        let client_b = Arc::new(MockResourceDispatcher {
            name: "client-b".into(),
        });

        let mut router = RouterResourceDispatcher::new();
        router.add_client("server-a", client_a);
        router.add_client("server-b", client_b);

        let result = router
            .read_resource("server-a", "file:///log")
            .await
            .unwrap();
        assert_eq!(result["dispatcher"], "client-a");

        let result = router
            .read_resource("server-b", "db://table")
            .await
            .unwrap();
        assert_eq!(result["dispatcher"], "client-b");
    }

    #[tokio::test]
    async fn rs_c06_resource_router_returns_error_for_unknown_server() {
        let mut router = RouterResourceDispatcher::new();
        router.add_client(
            "known",
            Arc::new(MockResourceDispatcher {
                name: "known".into(),
            }),
        );

        let result = router.read_resource("nonexistent", "uri").await;
        assert!(matches!(result, Err(DispatchError::ServerNotFound(ref s)) if s == "nonexistent"));
    }
}
