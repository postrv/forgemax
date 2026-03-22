//! Auto-reconnecting client decorator for transport resilience.
//!
//! Wraps an [`McpClient`] and automatically reconnects when a
//! [`TransportDead`](forge_error::DispatchError::TransportDead) error is detected.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use forge_sandbox::{ResourceDispatcher, ToolDispatcher};
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};

use crate::{McpClient, TransportConfig};

/// A client wrapper that auto-reconnects on transport death.
///
/// Implements both [`ToolDispatcher`] and [`ResourceDispatcher`] by delegating
/// to an inner [`McpClient`]. When a `TransportDead` error is detected, the
/// client is transparently replaced with a fresh connection.
///
/// Uses a `RwLock` for the inner client so that in-flight read operations
/// (tool calls, resource reads) can proceed concurrently, while reconnection
/// briefly takes a write lock.
pub struct ReconnectingClient {
    name: String,
    transport_config: TransportConfig,
    inner: RwLock<Arc<McpClient>>,
    reconnecting: AtomicBool,
    max_backoff: Duration,
    current_backoff: Mutex<Duration>,
}

impl ReconnectingClient {
    /// Create a new reconnecting wrapper around an existing client.
    pub fn new(
        name: String,
        transport_config: TransportConfig,
        client: Arc<McpClient>,
        max_backoff: Duration,
    ) -> Self {
        Self {
            name,
            transport_config,
            inner: RwLock::new(client),
            reconnecting: AtomicBool::new(false),
            max_backoff,
            current_backoff: Mutex::new(Duration::from_secs(1)),
        }
    }

    /// Attempt to reconnect, returning true on success.
    ///
    /// Uses CAS on `reconnecting` to ensure only one reconnection attempt
    /// proceeds at a time. Other callers wait for the reconnection to complete.
    async fn try_reconnect(&self) -> bool {
        // CAS: only one task reconnects at a time
        if self
            .reconnecting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            // Another task is already reconnecting — wait for it
            tracing::debug!(server = %self.name, "waiting for concurrent reconnection");
            // Brief sleep to let the other reconnection attempt complete
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Check if the reconnection flag was cleared (success)
            return !self.reconnecting.load(Ordering::SeqCst);
        }

        // Apply backoff delay
        let backoff = {
            let guard = self.current_backoff.lock().await;
            *guard
        };
        tracing::info!(
            server = %self.name,
            backoff_ms = backoff.as_millis(),
            "attempting reconnection after backoff"
        );
        tokio::time::sleep(backoff).await;

        // Try to create a new connection
        match McpClient::connect(self.name.clone(), &self.transport_config).await {
            Ok(new_client) => {
                tracing::info!(server = %self.name, "reconnection successful");
                // Swap the client under write lock
                {
                    let mut inner = self.inner.write().await;
                    *inner = Arc::new(new_client);
                }
                // Reset backoff on success
                {
                    let mut guard = self.current_backoff.lock().await;
                    *guard = Duration::from_secs(1);
                }
                self.reconnecting.store(false, Ordering::SeqCst);
                true
            }
            Err(e) => {
                tracing::warn!(
                    server = %self.name,
                    error = %e,
                    "reconnection failed"
                );
                // Increase backoff (exponential, capped)
                {
                    let mut guard = self.current_backoff.lock().await;
                    *guard = (*guard * 2).min(self.max_backoff);
                }
                self.reconnecting.store(false, Ordering::SeqCst);
                false
            }
        }
    }

    /// Get a clone of the current inner client.
    async fn current_client(&self) -> Arc<McpClient> {
        self.inner.read().await.clone()
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for ReconnectingClient {
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: Value,
    ) -> Result<Value, forge_error::DispatchError> {
        let client = self.current_client().await;
        let result = client.call_tool(server, tool, args.clone()).await;

        match result {
            Err(forge_error::DispatchError::TransportDead { .. }) => {
                tracing::warn!(
                    server = %self.name,
                    tool = %tool,
                    "transport dead, attempting reconnection"
                );
                if self.try_reconnect().await {
                    // Retry once with the new client
                    let new_client = self.current_client().await;
                    new_client.call_tool(server, tool, args).await
                } else {
                    Err(forge_error::DispatchError::TransportDead {
                        server: self.name.clone(),
                        reason: "reconnection failed".into(),
                    })
                }
            }
            other => other,
        }
    }
}

#[async_trait::async_trait]
impl ResourceDispatcher for ReconnectingClient {
    async fn read_resource(
        &self,
        server: &str,
        uri: &str,
    ) -> Result<Value, forge_error::DispatchError> {
        let client = self.current_client().await;
        let result = ResourceDispatcher::read_resource(client.as_ref(), server, uri).await;

        match result {
            Err(forge_error::DispatchError::TransportDead { .. }) => {
                tracing::warn!(
                    server = %self.name,
                    uri = %uri,
                    "transport dead, attempting reconnection"
                );
                if self.try_reconnect().await {
                    let new_client = self.current_client().await;
                    ResourceDispatcher::read_resource(new_client.as_ref(), server, uri).await
                } else {
                    Err(forge_error::DispatchError::TransportDead {
                        server: self.name.clone(),
                        reason: "reconnection failed".into(),
                    })
                }
            }
            other => other,
        }
    }
}
