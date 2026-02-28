//! Circuit breaker wrapper for tool dispatchers.
//!
//! Prevents cascade failures by tracking consecutive errors per-server and
//! temporarily rejecting calls when the failure threshold is exceeded.

use std::sync::Arc;
use std::time::{Duration, Instant};

use forge_error::DispatchError;
use forge_sandbox::{ResourceDispatcher, ToolDispatcher};
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
pub(crate) enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Internal state for the circuit breaker (shared between tool and resource dispatchers).
pub(crate) struct CircuitBreakerState {
    pub(crate) state: CircuitState,
    pub(crate) consecutive_failures: u32,
    pub(crate) last_failure_time: Option<Instant>,
}

/// A [`ToolDispatcher`] that implements the circuit breaker pattern.
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
    #[tracing::instrument(skip(self, args), fields(server, tool))]
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: Value,
    ) -> Result<Value, DispatchError> {
        {
            let mut st = self.state.lock().await;
            match st.state {
                CircuitState::Open => {
                    if let Some(last_fail) = st.last_failure_time {
                        if last_fail.elapsed() >= self.config.recovery_timeout {
                            st.state = CircuitState::HalfOpen;
                            tracing::info!(
                                server = %self.server_name,
                                "circuit breaker half-open, allowing probe call"
                            );
                        } else {
                            return Err(DispatchError::CircuitOpen(self.server_name.clone()));
                        }
                    }
                }
                CircuitState::HalfOpen | CircuitState::Closed => {}
            }
        }

        let result = self.inner.call_tool(server, tool, args).await;

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

/// A [`ResourceDispatcher`] wrapper with independent circuit breaker state.
pub struct CircuitBreakerResourceDispatcher {
    inner: Arc<dyn ResourceDispatcher>,
    server_name: String,
    config: CircuitBreakerConfig,
    state: Arc<Mutex<CircuitBreakerState>>,
}

impl CircuitBreakerResourceDispatcher {
    /// Wrap a resource dispatcher with circuit breaker logic.
    pub fn new(
        inner: Arc<dyn ResourceDispatcher>,
        config: CircuitBreakerConfig,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            config,
            server_name: server_name.into(),
            state: Arc::new(Mutex::new(CircuitBreakerState {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                last_failure_time: None,
            })),
        }
    }
}

#[async_trait::async_trait]
impl ResourceDispatcher for CircuitBreakerResourceDispatcher {
    #[tracing::instrument(skip(self), fields(server, uri))]
    async fn read_resource(
        &self,
        server: &str,
        uri: &str,
    ) -> Result<serde_json::Value, DispatchError> {
        {
            let mut st = self.state.lock().await;
            match st.state {
                CircuitState::Open => {
                    if let Some(last_fail) = st.last_failure_time {
                        if last_fail.elapsed() >= self.config.recovery_timeout {
                            st.state = CircuitState::HalfOpen;
                        } else {
                            return Err(DispatchError::CircuitOpen(self.server_name.clone()));
                        }
                    }
                }
                CircuitState::HalfOpen | CircuitState::Closed => {}
            }
        }

        let result = self.inner.read_resource(server, uri).await;

        {
            let mut st = self.state.lock().await;
            match &result {
                Ok(_) => {
                    st.state = CircuitState::Closed;
                    st.consecutive_failures = 0;
                    st.last_failure_time = None;
                }
                Err(_) => {
                    st.consecutive_failures += 1;
                    st.last_failure_time = Some(Instant::now());
                    if st.state == CircuitState::HalfOpen
                        || st.consecutive_failures >= self.config.failure_threshold
                    {
                        st.state = CircuitState::Open;
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
        async fn call_tool(
            &self,
            _server: &str,
            tool: &str,
            _args: Value,
        ) -> Result<Value, DispatchError> {
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
        async fn call_tool(
            &self,
            _server: &str,
            _tool: &str,
            _args: Value,
        ) -> Result<Value, DispatchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(DispatchError::Upstream {
                server: "s".into(),
                message: "server error".into(),
            })
        }
    }

    /// Dispatcher that fails N times then succeeds.
    struct FailThenOkDispatcher {
        calls: AtomicUsize,
        fail_count: usize,
    }

    #[async_trait::async_trait]
    impl ToolDispatcher for FailThenOkDispatcher {
        async fn call_tool(
            &self,
            _server: &str,
            tool: &str,
            _args: Value,
        ) -> Result<Value, DispatchError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_count {
                Err(DispatchError::Upstream {
                    server: "s".into(),
                    message: "server error".into(),
                })
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

        for _ in 0..3 {
            let _ = cb.call_tool("flaky", "tool", serde_json::json!({})).await;
        }
        assert_eq!(inner.call_count(), 3);

        let result = cb.call_tool("flaky", "tool", serde_json::json!({})).await;
        assert!(matches!(result, Err(DispatchError::CircuitOpen(_))));
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

        for _ in 0..2 {
            let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        }

        for _ in 0..5 {
            let result = cb.call_tool("s", "t", serde_json::json!({})).await;
            assert!(matches!(result, Err(DispatchError::CircuitOpen(_))));
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
            fail_count: 3,
        });
        let cb = CircuitBreakerDispatcher::new(inner, test_config(3, 50), "s");

        for _ in 0..3 {
            let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        }

        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_err());

        tokio::time::sleep(Duration::from_millis(60)).await;

        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_ok(), "probe should succeed after recovery");
    }

    #[tokio::test]
    async fn probe_failure_reopens_circuit() {
        let inner = Arc::new(FailDispatcher::new());
        let cb = CircuitBreakerDispatcher::new(inner.clone(), test_config(2, 50), "s");

        for _ in 0..2 {
            let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        }

        tokio::time::sleep(Duration::from_millis(60)).await;

        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_err());

        let before = inner.call_count();
        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(matches!(result, Err(DispatchError::CircuitOpen(_))));
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
            fail_count: 2,
        });
        let cb = CircuitBreakerDispatcher::new(inner, test_config(3, 60_000), "s");

        let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        let _ = cb.call_tool("s", "t", serde_json::json!({})).await;

        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_ok());

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
        assert!(matches!(err, DispatchError::CircuitOpen(ref s) if s == "my-server"));
    }

    // --- v0.2 Resource Circuit Breaker Test (RS-C08) ---

    struct FailResourceDispatcher;

    #[async_trait::async_trait]
    impl ResourceDispatcher for FailResourceDispatcher {
        async fn read_resource(&self, _server: &str, _uri: &str) -> Result<Value, DispatchError> {
            Err(DispatchError::Upstream {
                server: "flaky".into(),
                message: "resource read failed".into(),
            })
        }
    }

    #[tokio::test]
    async fn rs_c08_circuit_breaker_trips_on_repeated_resource_failures() {
        let inner: Arc<dyn ResourceDispatcher> = Arc::new(FailResourceDispatcher);
        let cb = CircuitBreakerResourceDispatcher::new(inner, test_config(2, 60_000), "flaky");

        for _ in 0..2 {
            let _ = cb.read_resource("flaky", "file:///log").await;
        }

        let result = cb.read_resource("flaky", "file:///log").await;
        assert!(matches!(result, Err(DispatchError::CircuitOpen(_))));
    }

    #[tokio::test]
    async fn probe_success_closes_circuit() {
        let inner = Arc::new(FailThenOkDispatcher {
            calls: AtomicUsize::new(0),
            fail_count: 2,
        });
        let cb = CircuitBreakerDispatcher::new(inner, test_config(2, 50), "s");

        for _ in 0..2 {
            let _ = cb.call_tool("s", "t", serde_json::json!({})).await;
        }

        tokio::time::sleep(Duration::from_millis(60)).await;

        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_ok());

        let result = cb.call_tool("s", "t", serde_json::json!({})).await;
        assert!(result.is_ok());
    }
}
