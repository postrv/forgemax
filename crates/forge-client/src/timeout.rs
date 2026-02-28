//! Per-server timeout wrapper for tool dispatchers.

use std::sync::Arc;
use std::time::Duration;

use forge_error::DispatchError;
use forge_sandbox::{ResourceDispatcher, ToolDispatcher};
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
    #[tracing::instrument(skip(self, args), fields(server, tool))]
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: Value,
    ) -> Result<Value, DispatchError> {
        match tokio::time::timeout(self.timeout, self.inner.call_tool(server, tool, args)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(DispatchError::Timeout {
                server: self.server_name.clone(),
                timeout_ms: self.timeout.as_millis() as u64,
            }),
        }
    }
}

/// A [`ResourceDispatcher`] that enforces a per-call timeout on the inner dispatcher.
pub struct TimeoutResourceDispatcher {
    inner: Arc<dyn ResourceDispatcher>,
    timeout: Duration,
    server_name: String,
}

impl TimeoutResourceDispatcher {
    /// Wrap an inner resource dispatcher with a per-call timeout.
    pub fn new(
        inner: Arc<dyn ResourceDispatcher>,
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
impl ResourceDispatcher for TimeoutResourceDispatcher {
    #[tracing::instrument(skip(self), fields(server, uri))]
    async fn read_resource(
        &self,
        server: &str,
        uri: &str,
    ) -> Result<serde_json::Value, DispatchError> {
        match tokio::time::timeout(self.timeout, self.inner.read_resource(server, uri)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(DispatchError::Timeout {
                server: self.server_name.clone(),
                timeout_ms: self.timeout.as_millis() as u64,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct InstantDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for InstantDispatcher {
        async fn call_tool(
            &self,
            _server: &str,
            tool: &str,
            _args: Value,
        ) -> Result<Value, DispatchError> {
            Ok(serde_json::json!({"tool": tool, "status": "ok"}))
        }
    }

    struct SlowDispatcher {
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl ToolDispatcher for SlowDispatcher {
        async fn call_tool(
            &self,
            _server: &str,
            _tool: &str,
            _args: Value,
        ) -> Result<Value, DispatchError> {
            tokio::time::sleep(self.delay).await;
            Ok(serde_json::json!({"status": "ok"}))
        }
    }

    struct FailingDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for FailingDispatcher {
        async fn call_tool(
            &self,
            _server: &str,
            _tool: &str,
            _args: Value,
        ) -> Result<Value, DispatchError> {
            Err(DispatchError::Internal(anyhow::anyhow!("inner error")))
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
        assert!(matches!(result.unwrap_err(), DispatchError::Timeout { .. }));
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
        assert!(matches!(err, DispatchError::Timeout { ref server, .. } if server == "narsil"));
        let msg = err.to_string();
        assert!(msg.contains("timeout"), "should mention timeout: {msg}");
        assert!(msg.contains("narsil"), "should mention server name: {msg}");
    }

    // --- v0.2 Resource Timeout Test (RS-C07) ---

    struct InstantResourceDispatcher;

    #[async_trait::async_trait]
    impl ResourceDispatcher for InstantResourceDispatcher {
        async fn read_resource(
            &self,
            _server: &str,
            uri: &str,
        ) -> Result<serde_json::Value, DispatchError> {
            Ok(serde_json::json!({"uri": uri}))
        }
    }

    struct SlowResourceDispatcher;

    #[async_trait::async_trait]
    impl ResourceDispatcher for SlowResourceDispatcher {
        async fn read_resource(
            &self,
            _server: &str,
            _uri: &str,
        ) -> Result<serde_json::Value, DispatchError> {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(serde_json::json!({}))
        }
    }

    #[tokio::test]
    async fn rs_c07_timeout_wraps_resource_reads() {
        // Fast read succeeds
        let fast = TimeoutResourceDispatcher::new(
            Arc::new(InstantResourceDispatcher),
            Duration::from_secs(5),
            "fast-server",
        );
        let result = fast.read_resource("fast-server", "file:///log").await;
        assert!(result.is_ok());

        // Slow read times out
        let slow = TimeoutResourceDispatcher::new(
            Arc::new(SlowResourceDispatcher),
            Duration::from_millis(50),
            "slow-server",
        );
        let result = slow.read_resource("slow-server", "file:///log").await;
        assert!(matches!(result, Err(DispatchError::Timeout { .. })));
    }

    #[tokio::test]
    async fn inner_error_preserved() {
        let inner = Arc::new(FailingDispatcher);
        let td = TimeoutDispatcher::new(inner, Duration::from_secs(5), "test");
        let err = td
            .call_tool("test", "tool", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, DispatchError::Internal(_)));
    }
}
