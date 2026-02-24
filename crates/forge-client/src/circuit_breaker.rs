//! Circuit breaker wrapper for tool dispatchers.
//!
//! Prevents cascade failures by tracking consecutive errors per-server and
//! temporarily rejecting calls when the failure threshold is exceeded.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use forge_sandbox::ToolDispatcher;
use serde_json::Value;
use tokio::sync::Mutex;

/// Configuration for a circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before the circuit opens.
    pub failure_threshold: u32,
    /// How long to wait before probing a tripped circuit.
    pub recovery_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            recovery_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

struct CircuitBreakerState {
    state: CircuitState,
    consecutive_failures: u32,
    last_failure_time: Option<Instant>,
}

/// A [`ToolDispatcher`] that implements the circuit breaker pattern.
///
/// Wraps an inner dispatcher and tracks consecutive failures. After
/// `failure_threshold` consecutive errors, the circuit opens and all calls
/// are rejected immediately until `recovery_timeout` elapses. The first
/// call after recovery is a probe (half-open): success closes the circuit,
/// failure re-opens it.
pub struct CircuitBreakerDispatcher {
    inner: Arc<dyn ToolDispatcher>,
    config: CircuitBreakerConfig,
    server_name: String,
    state: Mutex<CircuitBreakerState>,
}

impl CircuitBreakerDispatcher {
    /// Wrap an inner dispatcher with circuit breaker logic.
    pub fn new(
        inner: Arc<dyn ToolDispatcher>,
        config: CircuitBreakerConfig,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            config,
            server_name: server_name.into(),
            state: Mutex::new(CircuitBreakerState {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                last_failure_time: None,
            }),
        }
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for CircuitBreakerDispatcher {
    async fn call_tool(&self, server: &str, tool: &str, args: Value) -> Result<Value> {
        // Check circuit state before calling
        {
            let mut st = self.state.lock().await;
            match st.state {
                CircuitState::Open => {
                    // Check if recovery timeout has elapsed
                    if let Some(last_fail) = st.last_failure_time {
                        if last_fail.elapsed() >= self.config.recovery_timeout {
                            // Transition to half-open: allow a single probe
                            st.state = CircuitState::HalfOpen;
                            tracing::info!(
                                server = %self.server_name,
                                "circuit breaker half-open, allowing probe call"
                            );
                        } else {
                            return Err(anyhow::anyhow!(
                                "circuit breaker open for server '{}': {} consecutive failures, \
                                 recovery in {}s",
                                self.server_name,
                                st.consecutive_failures,
                                (self.config.recovery_timeout - last_fail.elapsed()).as_secs()
                            ));
                        }
                    }
                }
                CircuitState::HalfOpen | CircuitState::Closed => {
                    // Allow the call through
                }
            }
        }

        // Execute the call
        let result = self.inner.call_tool(server, tool, args).await;

        // Update state based on result
        {
            let mut st = self.state.lock().await;
            match &result {
                Ok(_) => {
                    if st.state == CircuitState::HalfOpen {
                        tracing::info!(
                            server = %self.server_name,
                            "circuit breaker closed after successful probe"
                        );
                    }
                    st.state = CircuitState::Closed;
                    st.consecutive_failures = 0;
                    st.last_failure_time = None;
                }
                Err(_) => {
                    st.consecutive_failures += 1;
                    st.last_failure_time = Some(Instant::now());
                    if st.state == CircuitState::HalfOpen {
                        st.state = CircuitState::Open;
                        tracing::warn!(
                            server = %self.server_name,
                            "circuit breaker re-opened after failed probe"
                        );
                    } else if st.consecutive_failures >= self.config.failure_threshold {
                        st.state = CircuitState::Open;
                        tracing::warn!(
                            server = %self.server_name,
                            failures = st.consecutive_failures,
                            "circuit breaker opened"
                        );
                    }
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct OkDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for OkDispatcher {
        async fn call_tool(&self, _server: &str, tool: &str, _args: Value) -> Result<Value> {
            Ok(serde_json::json!({"tool": tool, "status": "ok"}))
        }
    }

    struct FailDispatcher {
        calls: AtomicUsize,
    }

    impl FailDispatcher {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl ToolDispatcher for FailDispatcher {
        async fn call_tool(&self, _server: &str, _tool: &str, _args: Value) -> Result<Value> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!("server error"))
        }
    }

    /// Dispatcher that fails N times then succeeds.
    struct FailThenOkDispatcher {
        calls: AtomicUsize,
        fail_count: usize,
    }

    #[async_trait::async_trait]
    impl ToolDispatcher for FailThenOkDispatcher {
        async fn call_tool(&self, _server: &str, tool: &str, _args: Value) -> Result<Value> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_count {
                Err(anyhow::anyhow!("server error"))
            } else {
                Ok(serde_json::json!({"tool": tool, "status": "ok"}))
            }
        }
    }

    fn test_config(threshold: u32, recovery_ms: u64) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: threshold,
            recovery_timeout: Duration::from_millis(recovery_ms),
        }
    }

    #[tokio::test]
    async fn passes_through_on_success() {
        let inner = Arc::new(OkDispatcher);
        let cb = CircuitBreakerDispatcher::new(inner, test_config(3, 1000), "test");
        let result = cb.call_tool("test", "echo", serde_json::json!({})).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["status"], "ok");
    }

    #[tokio::test]
    async fn opens_after_threshold_failures() {
        let inner = Arc::new(FailDispatcher::new());
        let cb = CircuitBreakerDispatcher::new(inner.clone(), test_config(3, 60_000), "flaky");

        // 3 failures to trip the breaker
        for _ in 0..3 {
            let _ = cb.call_tool("flaky", "tool", serde_json::json!({})).await;
        }
        assert_eq!(inner.call_count(), 3);

        // 4th call should be rejected without reaching inner
        let result = cb.call_tool("flaky", "tool", serde_json::json!({})).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("circuit breaker open"), "got: {msg}");
        assert!(msg.contains("flaky"), "should mention server: {msg}");
        assert_eq!(
            inner.call_count(),
            3,
            "inner should not be called when open"
        );
    }

    #[tokio::test]
    async fn rejects_when_open() {
        let inner = Arc::new(FailDispatcher::new());
        let cb = CircuitBreakerDispatcher::new(inner.clone(), test_config(2, 60_000), "s");

        // Trip the breaker
        for _ in 0..2 {
            let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        }

        // Multiple calls should all be rejected
        for _ in 0..5 {
            let result = cb.call_tool("s", "t", serde_json::json!({})).await;
            assert!(result.is_err());
        }
        assert_eq!(
            inner.call_count(),
            2,
            "no additional calls should reach inner"
        );
    }

    #[tokio::test]
    async fn half_open_after_recovery_timeout() {
        let inner = Arc::new(FailThenOkDispatcher {
            calls: AtomicUsize::new(0),
            fail_count: 3, // fail first 3, then succeed
        });
        let cb = CircuitBreakerDispatcher::new(inner, test_config(3, 50), "s");

        // Trip the breaker (3 failures)
        for _ in 0..3 {
            let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        }

        // Should be open
        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_err());

        // Wait for recovery
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Probe call should succeed (fail_count=3, this is call #3 zero-indexed → success)
        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_ok(), "probe should succeed after recovery");
    }

    #[tokio::test]
    async fn probe_failure_reopens_circuit() {
        let inner = Arc::new(FailDispatcher::new());
        let cb = CircuitBreakerDispatcher::new(inner.clone(), test_config(2, 50), "s");

        // Trip the breaker
        for _ in 0..2 {
            let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        }

        // Wait for recovery
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Probe call will fail → circuit should re-open
        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_err());

        // Next call should be rejected immediately (circuit re-opened)
        let before = inner.call_count();
        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_err());
        assert_eq!(
            inner.call_count(),
            before,
            "should not reach inner after probe failure"
        );
    }

    #[tokio::test]
    async fn success_resets_failure_counter() {
        let inner = Arc::new(FailThenOkDispatcher {
            calls: AtomicUsize::new(0),
            fail_count: 2, // fail first 2, then succeed
        });
        let cb = CircuitBreakerDispatcher::new(inner, test_config(3, 60_000), "s");

        // 2 failures (threshold is 3, so still closed)
        let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        let _ = cb.call_tool("s", "t", serde_json::json!({})).await;

        // 1 success (call index 2) → counter should reset
        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_ok());

        // Circuit should still be closed — the counter was reset
        let st = cb.state.lock().await;
        assert_eq!(st.state, CircuitState::Closed);
        assert_eq!(st.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn error_message_includes_server_and_failure_count() {
        let inner = Arc::new(FailDispatcher::new());
        let cb = CircuitBreakerDispatcher::new(inner, test_config(2, 60_000), "my-server");

        for _ in 0..2 {
            let _ = cb
                .call_tool("my-server", "tool", serde_json::json!({}))
                .await;
        }

        let err = cb
            .call_tool("my-server", "tool", serde_json::json!({}))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("my-server"), "should mention server: {msg}");
        assert!(
            msg.contains("2 consecutive failures"),
            "should mention failure count: {msg}"
        );
    }

    #[tokio::test]
    async fn probe_success_closes_circuit() {
        let inner = Arc::new(FailThenOkDispatcher {
            calls: AtomicUsize::new(0),
            fail_count: 2,
        });
        let cb = CircuitBreakerDispatcher::new(inner, test_config(2, 50), "s");

        // Trip the breaker
        for _ in 0..2 {
            let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        }

        // Wait for recovery
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Probe succeeds (call index 2)
        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_ok());

        // Circuit should be closed now — next call should go through
        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_ok());
    }
}
