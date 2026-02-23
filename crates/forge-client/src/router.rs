//! Router dispatcher for routing tool calls to the correct downstream MCP client.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use forge_sandbox::ToolDispatcher;
use serde_json::Value;

/// A [`ToolDispatcher`] that routes `call_tool(server, tool, args)` to the
/// correct downstream MCP client based on server name.
pub struct RouterDispatcher {
    clients: HashMap<String, Arc<dyn ToolDispatcher>>,
}

impl RouterDispatcher {
    /// Create a new empty router.
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    /// Register a dispatcher for a named server.
    pub fn add_client(&mut self, name: impl Into<String>, client: Arc<dyn ToolDispatcher>) {
        self.clients.insert(name.into(), client);
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
    async fn call_tool(&self, server: &str, tool: &str, args: Value) -> Result<Value> {
        let client = self.clients.get(server).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown server '{}', available servers: {:?}",
                server,
                self.server_names()
            )
        })?;
        client.call_tool(server, tool, args).await
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
        async fn call_tool(&self, server: &str, tool: &str, args: Value) -> Result<Value> {
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
        async fn call_tool(&self, _server: &str, _tool: &str, _args: Value) -> Result<Value> {
            Err(anyhow::anyhow!("downstream connection failed"))
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
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent"),
            "error should mention the unknown server name: {err}"
        );
        assert!(
            err.contains("known"),
            "error should list available servers: {err}"
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
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown server"));
    }
}
