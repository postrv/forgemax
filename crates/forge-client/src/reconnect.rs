//! Auto-reconnecting client decorator for transport resilience.
//!
//! Wraps an [`McpClient`] and automatically reconnects when a
//! [`TransportDead`](forge_error::DispatchError::TransportDead) error is detected.
//!
//! Concurrent calls serialize reconnection and share the replacement client.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use forge_error::DispatchError;
use forge_sandbox::{ResourceDispatcher, ToolDispatcher};
use serde_json::Value;
use tokio::runtime::Handle;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinSet;

use crate::{McpClient, ToolInfo, TransportConfig, DEFAULT_CATALOG_TIMEOUT};

/// A client wrapper that auto-reconnects on transport death.
///
/// Implements both [`ToolDispatcher`] and [`ResourceDispatcher`] by delegating
/// to an inner [`McpClient`]. When a `TransportDead` error is detected, the
/// client is transparently replaced with a fresh connection.
///
/// Uses a `RwLock` for the inner client so that in-flight read operations
/// (tool calls, resource reads) can proceed concurrently, while reconnection
/// briefly takes a write lock.
///
/// A replacement connection runs on the runtime that created the wrapper.
/// It stays alive even when discovery or dispatch uses a short-lived runtime.
pub struct ReconnectingClient {
    name: String,
    transport_config: TransportConfig,
    runtime: Option<Handle>,
    inner: RwLock<ActiveConnection>,
    max_backoff: Duration,
    current_backoff: Mutex<Duration>,
}

struct ActiveConnection {
    client: Arc<McpClient>,
    /// The startup router has already checked the first connection. Every
    /// replacement must supply its own catalog before taking over.
    tool_names: Option<HashSet<String>>,
}

impl ReconnectingClient {
    /// List tools on the same active connection used for dispatch.
    pub async fn list_tools(&self) -> anyhow::Result<Vec<ToolInfo>> {
        let client = self.current_client().await;
        let tools = client.list_tools().await?;
        let mut active = self.inner.write().await;
        anyhow::ensure!(
            Arc::ptr_eq(&client, &active.client),
            "downstream connection was replaced during catalog discovery"
        );
        active.tool_names = Some(tools.iter().map(|tool| tool.name.clone()).collect());
        Ok(tools)
    }

    /// Create a new reconnecting wrapper around an existing client.
    ///
    /// Construct this on the long-lived host runtime when dispatch may run
    /// on a separate runtime. Outside a runtime, reconnection uses the caller's runtime.
    pub fn new(
        name: String,
        transport_config: TransportConfig,
        client: Arc<McpClient>,
        max_backoff: Duration,
    ) -> Self {
        Self {
            name,
            transport_config,
            runtime: Handle::try_current().ok(),
            inner: RwLock::new(ActiveConnection {
                client,
                tool_names: None,
            }),
            max_backoff,
            current_backoff: Mutex::new(Duration::from_secs(1)),
        }
    }

    /// Replace the failed connection if another caller has not already done so.
    async fn try_reconnect(&self, failed: &Arc<McpClient>) -> bool {
        let mut backoff = self.current_backoff.lock().await;
        if !Arc::ptr_eq(failed, &self.current_client().await) {
            return true;
        }

        tracing::info!(
            server = %self.name,
            backoff_ms = backoff.as_millis(),
            "attempting reconnection after backoff"
        );
        tokio::time::sleep(*backoff).await;

        match self.connect_replacement().await {
            Ok(new_client) => {
                tracing::info!(server = %self.name, "reconnection successful");
                *self.inner.write().await = new_client;
                *backoff = Duration::from_secs(1);
                true
            }
            Err(e) => {
                tracing::warn!(
                    server = %self.name,
                    error = %e,
                    "reconnection failed"
                );
                *backoff = (*backoff * 2).min(self.max_backoff);
                false
            }
        }
    }

    async fn connect_replacement(&self) -> anyhow::Result<ActiveConnection> {
        let name = self.name.clone();
        let config = self.transport_config.clone();
        let connect = async move {
            let client = McpClient::connect(name, &config).await?;
            let tools = tokio::time::timeout(DEFAULT_CATALOG_TIMEOUT, client.list_tools())
                .await
                .context("replacement tool catalog discovery timed out")??;
            Ok(ActiveConnection {
                client: Arc::new(client),
                tool_names: Some(tools.into_iter().map(|tool| tool.name).collect()),
            })
        };
        let Some(runtime) = &self.runtime else {
            return connect.await;
        };
        // Dropping the caller also cancels a replacement still being established.
        let mut connection = JoinSet::new();
        connection.spawn_on(connect, runtime);
        connection
            .join_next()
            .await
            .context("missing reconnection task")?
            .context("reconnection task failed")?
    }

    /// Get a clone of the current inner client.
    async fn current_client(&self) -> Arc<McpClient> {
        self.inner.read().await.client.clone()
    }

    async fn client_for_tool(
        &self,
        server: &str,
        tool: &str,
    ) -> Result<Arc<McpClient>, DispatchError> {
        let active = self.inner.read().await;
        if active
            .tool_names
            .as_ref()
            .is_some_and(|tools| !tools.contains(tool))
        {
            return Err(DispatchError::ToolNotFound {
                server: server.into(),
                tool: tool.into(),
            });
        }
        Ok(active.client.clone())
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
        let client = self.client_for_tool(server, tool).await?;
        let result = client.call_tool(server, tool, args).await;
        if matches!(result, Err(DispatchError::TransportDead { .. })) {
            tracing::warn!(
                server = %self.name,
                tool = %tool,
                "transport lost during tool call, reconnecting for future requests"
            );
            // The peer may have applied effects before its response was lost.
            self.try_reconnect(&client).await;
        }
        result
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
                if self.try_reconnect(&client).await {
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
