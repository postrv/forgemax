//! Per-server timeout wrapper for tool dispatchers.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use forge_sandbox::ToolDispatcher;
use serde_json::Value;

/// A [`ToolDispatcher`] that enforces a per-call timeout on the inner dispatcher.
pub struct TimeoutDispatcher {
    inner: Arc<dyn ToolDispatcher>,
    timeout: Duration,
    server_name: String,
}

impl TimeoutDispatcher {
    /// Wrap an inner dispatcher with a per-call timeout.
    pub fn new(
        inner: Arc<dyn ToolDispatcher>,
        timeout: Duration,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            timeout,
            server_name: server_name.into(),
        }
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for TimeoutDispatcher {
    async fn call_tool(&self, server: &str, tool: &str, args: Value) -> Result<Value> {
        match tokio::time::timeout(self.timeout, self.inner.call_tool(server, tool, args)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(anyhow::anyhow!(
                "timeout after {}s calling tool '{}' on server '{}'",
                self.timeout.as_secs(),
                tool,
                self.server_name,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct InstantDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for InstantDispatcher {
        async fn call_tool(&self, _server: &str, tool: &str, _args: Value) -> Result<Value> {
            Ok(serde_json::json!({"tool": tool, "status": "ok"}))
        }
    }

    struct SlowDispatcher {
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl ToolDispatcher for SlowDispatcher {
        async fn call_tool(&self, _server: &str, _tool: &str, _args: Value) -> Result<Value> {
            tokio::time::sleep(self.delay).await;
            Ok(serde_json::json!({"status": "ok"}))
        }
    }

    struct FailingDispatcher {
        calls: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl ToolDispatcher for FailingDispatcher {
        async fn call_tool(&self, _server: &str, _tool: &str, _args: Value) -> Result<Value> {
            *self.calls.lock().unwrap() += 1;
            Err(anyhow::anyhow!("inner error"))
        }
    }

    #[tokio::test]
    async fn fast_call_passes_through() {
        let inner = Arc::new(InstantDispatcher);
        let td = TimeoutDispatcher::new(inner, Duration::from_secs(5), "test-server");
        let result = td
            .call_tool("test-server", "echo", serde_json::json!({}))
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["tool"], "echo");
    }

    #[tokio::test]
    async fn slow_call_times_out() {
        let inner = Arc::new(SlowDispatcher {
            delay: Duration::from_secs(10),
        });
        let td = TimeoutDispatcher::new(inner, Duration::from_millis(50), "slow-server");
        let result = td
            .call_tool("slow-server", "scan", serde_json::json!({}))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn timeout_error_message_contains_context() {
        let inner = Arc::new(SlowDispatcher {
            delay: Duration::from_secs(10),
        });
        let td = TimeoutDispatcher::new(inner, Duration::from_millis(50), "narsil");
        let err = td
            .call_tool("narsil", "symbols.find", serde_json::json!({}))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("timeout"), "should mention timeout: {msg}");
        assert!(
            msg.contains("symbols.find"),
            "should mention tool name: {msg}"
        );
        assert!(msg.contains("narsil"), "should mention server name: {msg}");
    }

    #[tokio::test]
    async fn inner_error_preserved() {
        let inner = Arc::new(FailingDispatcher {
            calls: Mutex::new(0),
        });
        let td = TimeoutDispatcher::new(inner, Duration::from_secs(5), "test");
        let err = td
            .call_tool("test", "tool", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("inner error"),
            "inner error should propagate: {}",
            err
        );
    }
}
