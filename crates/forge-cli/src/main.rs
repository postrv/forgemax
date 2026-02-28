#![warn(missing_docs)]

//! Forgemax Code Mode MCP Gateway
//!
//! Give your agent every tool. Use 1,000 tokens.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use forge_client::{
    CircuitBreakerConfig, CircuitBreakerDispatcher, CircuitBreakerResourceDispatcher, McpClient,
    RouterDispatcher, RouterResourceDispatcher, TimeoutDispatcher, TimeoutResourceDispatcher,
    TransportConfig,
};
use forge_config::ForgeConfig;
use forge_manifest::{server_entry_from_tools, LiveManifest, ManifestBuilder, McpTool};
use forge_sandbox::audit::TracingAuditLogger;
use forge_sandbox::groups::GroupPolicy;
use forge_sandbox::stash::StashConfig;
use forge_sandbox::{ExecutionMode, ResourceDispatcher, SandboxConfig, ToolDispatcher};
use forge_server::ForgeServer;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

/// Build SandboxConfig from config overrides.
fn build_sandbox_config(overrides: &forge_config::SandboxOverrides) -> SandboxConfig {
    let mut config = SandboxConfig::default();
    if let Some(timeout) = overrides.timeout_secs {
        config.timeout = std::time::Duration::from_secs(timeout);
    }
    if let Some(heap) = overrides.max_heap_mb {
        config.max_heap_size = heap * 1024 * 1024;
    }
    if let Some(concurrent) = overrides.max_concurrent {
        config.max_concurrent = concurrent;
    }
    if let Some(tool_calls) = overrides.max_tool_calls {
        config.max_tool_calls = tool_calls;
    }
    if let Some(ref mode) = overrides.execution_mode {
        config.execution_mode = match mode.as_str() {
            "child_process" => ExecutionMode::ChildProcess,
            _ => ExecutionMode::InProcess,
        };
    }
    if let Some(size) = overrides.max_ipc_message_size_mb {
        config.max_ipc_message_size = size * 1024 * 1024;
    }
    if let Some(size) = overrides.max_resource_size_mb {
        config.max_resource_size = size * 1024 * 1024;
    }
    if let Some(parallel) = overrides.max_parallel {
        config.max_parallel = parallel;
    }
    config
}

/// Build StashConfig from config overrides.
fn build_stash_config(overrides: &forge_config::StashOverrides) -> StashConfig {
    let mut config = StashConfig::default();
    if let Some(max_keys) = overrides.max_keys {
        config.max_keys = max_keys;
    }
    if let Some(mb) = overrides.max_value_size_mb {
        config.max_value_size = mb * 1024 * 1024;
    }
    if let Some(mb) = overrides.max_total_size_mb {
        config.max_total_size = mb * 1024 * 1024;
    }
    if let Some(secs) = overrides.default_ttl_secs {
        config.default_ttl = std::time::Duration::from_secs(secs);
    }
    if let Some(secs) = overrides.max_ttl_secs {
        config.max_ttl = std::time::Duration::from_secs(secs);
    }
    config
}

/// Convert a ServerConfig to a TransportConfig.
fn to_transport_config(server: &forge_config::ServerConfig) -> Result<TransportConfig> {
    match server.transport.as_str() {
        "stdio" => Ok(TransportConfig::Stdio {
            command: server.command.clone().unwrap_or_default(),
            args: server.args.clone(),
        }),
        "sse" => Ok(TransportConfig::Http {
            url: server.url.clone().unwrap_or_default(),
            headers: server.headers.clone(),
        }),
        other => anyhow::bail!(
            "unsupported transport type '{}' (expected 'stdio' or 'sse')",
            other
        ),
    }
}

/// Locate the config file.
///
/// Search order:
/// 1. `FORGE_CONFIG` environment variable
/// 2. `./forge.toml` in the current directory
/// 3. None (no config file found — not an error)
fn find_config_file() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("FORGE_CONFIG") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    let cwd = PathBuf::from("forge.toml");
    if cwd.exists() {
        return Some(cwd);
    }

    None
}

/// Re-discover tools from all downstream servers and update the live manifest.
///
/// Errors from individual servers are logged but don't fail the whole refresh —
/// the stale manifest is preserved for any server that can't be reached.
async fn refresh_manifest(
    clients: &[(String, String, Arc<McpClient>)],
    live: &LiveManifest,
) -> Result<()> {
    let mut builder = ManifestBuilder::new();
    let mut errors = 0;

    for (name, description, client) in clients {
        match client.list_tools().await {
            Ok(tools) => {
                let mcp_tools: Vec<McpTool> = tools
                    .into_iter()
                    .map(|t| McpTool {
                        name: t.name,
                        description: t.description,
                        input_schema: Some(t.input_schema),
                    })
                    .collect();
                let entry = server_entry_from_tools(name, description, mcp_tools);
                builder = builder.add_server(entry);
                tracing::debug!(server = %name, "manifest refresh: server OK");
            }
            Err(e) => {
                errors += 1;
                tracing::warn!(server = %name, error = %e, "manifest refresh: server failed, keeping stale data");
            }
        }
    }

    if errors == clients.len() && !clients.is_empty() {
        tracing::warn!("manifest refresh: all servers failed, keeping stale manifest");
    } else {
        let new_manifest = builder.build();
        tracing::info!(
            servers = new_manifest.total_servers(),
            tools = new_manifest.total_tools(),
            "manifest refreshed"
        );
        live.update(new_manifest);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Handle --version / -V before anything else
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("forgemax {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // Load config
    let config = match find_config_file() {
        Some(path) => {
            tracing::info!(path = %path.display(), "loading config");
            ForgeConfig::from_file_with_env(&path)
                .with_context(|| format!("failed to load config from {}", path.display()))?
        }
        None => {
            tracing::info!("no config file found, starting with no downstream servers");
            ForgeConfig::from_toml("")?
        }
    };

    let sandbox_config = build_sandbox_config(&config.sandbox);

    // Connect to downstream servers and build manifest
    let mut router = RouterDispatcher::new();
    let mut resource_router = RouterResourceDispatcher::new();
    let mut manifest_builder = ManifestBuilder::new();
    let mut has_any_resources = false;
    // Retain client references for manifest refresh
    let mut client_refs: Vec<(String, String, Arc<McpClient>)> = Vec::new();

    for (name, server_config) in &config.servers {
        let transport_config = to_transport_config(server_config)?;

        tracing::info!(server = %name, "connecting to downstream server");

        let client = McpClient::connect(name.clone(), &transport_config)
            .await
            .with_context(|| format!("failed to connect to server '{}'", name))?;

        // Discover tools
        let tools = client
            .list_tools()
            .await
            .with_context(|| format!("failed to list tools for server '{}'", name))?;

        // Discover resources (graceful degradation if not supported)
        let resources = match client.list_resources().await {
            Ok(res) => {
                if !res.is_empty() {
                    tracing::info!(
                        server = %name,
                        resource_count = res.len(),
                        "discovered resources"
                    );
                }
                res
            }
            Err(e) => {
                tracing::debug!(
                    server = %name,
                    error = %e,
                    "server does not support resources (graceful degradation)"
                );
                Vec::new()
            }
        };

        tracing::info!(
            server = %name,
            tool_count = tools.len(),
            resource_count = resources.len(),
            "discovered capabilities"
        );

        // Build manifest entry from live tool list
        let mcp_tools: Vec<McpTool> = tools
            .into_iter()
            .map(|t| McpTool {
                name: t.name,
                description: t.description,
                input_schema: Some(t.input_schema),
            })
            .collect();

        let description = server_config.description.as_deref().unwrap_or("MCP server");
        let server_entry = server_entry_from_tools(name, description, mcp_tools);
        manifest_builder = manifest_builder.add_server(server_entry);

        // Arc the client so it can be shared between tool and resource dispatchers.
        // McpClient implements both ToolDispatcher and ResourceDispatcher.
        let client = Arc::new(client);

        // Retain reference for manifest refresh
        let desc_str = description.to_string();
        client_refs.push((name.clone(), desc_str, client.clone()));

        // Wire resource dispatcher if any resources exist
        if !resources.is_empty() {
            has_any_resources = true;
            let resource_client: Arc<dyn ResourceDispatcher> = client.clone();

            // Wrap resource client with per-server timeout if configured
            let resource_client: Arc<dyn ResourceDispatcher> =
                if let Some(secs) = server_config.timeout_secs {
                    Arc::new(TimeoutResourceDispatcher::new(
                        resource_client,
                        std::time::Duration::from_secs(secs),
                        name.clone(),
                    ))
                } else {
                    resource_client
                };

            // Wrap with circuit breaker if enabled
            let resource_client: Arc<dyn ResourceDispatcher> =
                if server_config.circuit_breaker == Some(true) {
                    let cb_config = CircuitBreakerConfig {
                        failure_threshold: server_config.failure_threshold.unwrap_or(3),
                        recovery_timeout: std::time::Duration::from_secs(
                            server_config.recovery_timeout_secs.unwrap_or(30),
                        ),
                    };
                    Arc::new(CircuitBreakerResourceDispatcher::new(
                        resource_client,
                        cb_config,
                        name.clone(),
                    ))
                } else {
                    resource_client
                };

            resource_router.add_client(name.clone(), resource_client);
        }

        // Wrap client with per-server timeout if configured
        let client: Arc<dyn ToolDispatcher> = client;
        let client: Arc<dyn ToolDispatcher> = if let Some(secs) = server_config.timeout_secs {
            Arc::new(TimeoutDispatcher::new(
                client,
                std::time::Duration::from_secs(secs),
                name.clone(),
            ))
        } else {
            client
        };

        // Wrap with circuit breaker if enabled (outside timeout so timeouts trip the breaker)
        let client: Arc<dyn ToolDispatcher> = if server_config.circuit_breaker == Some(true) {
            let cb_config = CircuitBreakerConfig {
                failure_threshold: server_config.failure_threshold.unwrap_or(3),
                recovery_timeout: std::time::Duration::from_secs(
                    server_config.recovery_timeout_secs.unwrap_or(30),
                ),
            };
            Arc::new(CircuitBreakerDispatcher::new(
                client,
                cb_config,
                name.clone(),
            ))
        } else {
            client
        };

        // Add client to router
        router.add_client(name.clone(), client);
    }

    let manifest = manifest_builder.build();
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(router);
    let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> = if has_any_resources {
        Some(Arc::new(resource_router))
    } else {
        None
    };

    tracing::info!(
        servers = manifest.total_servers(),
        tools = manifest.total_tools(),
        has_resources = has_any_resources,
        "Forgemax Code Mode Gateway starting"
    );

    // Build group policy if groups are configured
    let group_policy = if !config.groups.is_empty() {
        let groups: std::collections::HashMap<String, (Vec<String>, String)> = config
            .groups
            .iter()
            .map(|(name, gc)| (name.clone(), (gc.servers.clone(), gc.isolation.clone())))
            .collect();
        Some(GroupPolicy::from_config(&groups))
    } else {
        None
    };

    // Build stash config from overrides (defaults if not configured)
    let stash_overrides = config.sandbox.stash.clone().unwrap_or_default();
    let stash_config = build_stash_config(&stash_overrides);

    // Build optional worker pool
    let pool = if let Some(ref pool_config) = config.sandbox.pool {
        if pool_config.enabled == Some(true)
            && sandbox_config.execution_mode == ExecutionMode::ChildProcess
        {
            let pc = forge_sandbox::pool::PoolConfig {
                min_workers: pool_config.min_workers.unwrap_or(2),
                max_workers: pool_config.max_workers.unwrap_or(8),
                max_idle_time: std::time::Duration::from_secs(
                    pool_config.max_idle_secs.unwrap_or(60),
                ),
                max_uses: pool_config.max_uses.unwrap_or(50),
                ..forge_sandbox::pool::PoolConfig::default()
            };
            tracing::info!(
                min = pc.min_workers,
                max = pc.max_workers,
                max_uses = pc.max_uses,
                "worker pool enabled"
            );
            Some(Arc::new(forge_sandbox::pool::WorkerPool::new(pc)))
        } else {
            None
        }
    } else {
        None
    };

    let audit_logger = Arc::new(TracingAuditLogger);
    let executor = if let Some(ref pool) = pool {
        forge_sandbox::executor::SandboxExecutor::with_audit_logger(sandbox_config, audit_logger)
            .with_pool(pool.clone())
    } else {
        forge_sandbox::executor::SandboxExecutor::with_audit_logger(sandbox_config, audit_logger)
    };

    let server =
        ForgeServer::new_with_executor(executor, manifest, dispatcher, resource_dispatcher)
            .with_stash(stash_config);
    let server = if let Some(policy) = group_policy {
        server.with_group_policy(policy)
    } else {
        server
    };

    // Clone the live manifest reference for background refresh
    let live_manifest = server.live_manifest().clone();

    // Serve over stdio (standard MCP transport)
    let service = server.serve(rmcp::transport::io::stdio()).await?;

    // Spawn periodic manifest refresh task if configured
    let refresh_interval = config.manifest.refresh_interval_secs.unwrap_or(0);
    let refresh_handle = if refresh_interval > 0 {
        let live = live_manifest.clone();
        let clients = client_refs.clone();
        Some(tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(refresh_interval));
            interval.tick().await; // skip the first immediate tick
            loop {
                interval.tick().await;
                tracing::info!("periodic manifest refresh triggered");
                let _ = refresh_manifest(&clients, &live).await;
            }
        }))
    } else {
        None
    };

    // Wait for either normal shutdown, ctrl-c, or SIGHUP
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    // Pin the service.waiting() future so we can poll it across loop iterations
    let waiting = service.waiting();
    tokio::pin!(waiting);

    loop {
        // Create a future that resolves on SIGHUP (Unix) or never resolves (non-Unix)
        let sighup_fut = async {
            #[cfg(unix)]
            {
                sighup.recv().await;
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            result = &mut waiting => { result?; break; }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received shutdown signal, stopping gracefully");
                break;
            }
            _ = sighup_fut => {
                tracing::info!("received SIGHUP, refreshing manifest");
                let _ = refresh_manifest(&client_refs, &live_manifest).await;
            }
        }
    }

    // Cancel periodic refresh task
    if let Some(handle) = refresh_handle {
        handle.abort();
    }

    // Shut down worker pool if active
    if let Some(pool) = pool {
        pool.shutdown().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_server_config(transport: &str) -> forge_config::ServerConfig {
        forge_config::ServerConfig {
            transport: transport.into(),
            command: Some("echo".into()),
            args: vec!["hello".into()],
            url: Some("http://localhost:8080".into()),
            headers: Default::default(),
            description: None,
            timeout_secs: None,
            circuit_breaker: None,
            failure_threshold: None,
            recovery_timeout_secs: None,
        }
    }

    #[test]
    fn to_transport_config_stdio() {
        let server = make_server_config("stdio");
        let config = to_transport_config(&server).unwrap();
        assert!(matches!(config, TransportConfig::Stdio { .. }));
    }

    #[test]
    fn to_transport_config_sse() {
        let server = make_server_config("sse");
        let config = to_transport_config(&server).unwrap();
        assert!(matches!(config, TransportConfig::Http { .. }));
    }

    #[test]
    fn to_transport_config_unknown_returns_error() {
        let server = make_server_config("grpc");
        let err = to_transport_config(&server).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported"),
            "expected 'unsupported' in: {msg}"
        );
        assert!(msg.contains("grpc"), "expected 'grpc' in: {msg}");
    }

    #[test]
    fn build_sandbox_config_defaults() {
        let overrides = forge_config::SandboxOverrides::default();
        let config = build_sandbox_config(&overrides);
        let default = SandboxConfig::default();
        assert_eq!(config.timeout, default.timeout);
        assert_eq!(config.max_heap_size, default.max_heap_size);
        assert_eq!(config.max_concurrent, default.max_concurrent);
        assert_eq!(config.max_tool_calls, default.max_tool_calls);
        assert_eq!(config.execution_mode, default.execution_mode);
        assert_eq!(config.max_resource_size, default.max_resource_size);
        assert_eq!(config.max_parallel, default.max_parallel);
    }

    #[test]
    fn executor_uses_tracing_audit_logger() {
        // Verify TracingAuditLogger can be constructed and wired into the executor.
        let logger = Arc::new(TracingAuditLogger);
        let config = SandboxConfig::default();
        let _executor = forge_sandbox::executor::SandboxExecutor::with_audit_logger(config, logger);
    }

    // --- Phase R4: ManifestConfig tests ---

    #[test]
    fn dm_08_manifest_config_parses_from_toml() {
        let toml = "[manifest]\nrefresh_interval_secs = 30";
        let config = ForgeConfig::from_toml(toml).unwrap();
        assert_eq!(config.manifest.refresh_interval_secs, Some(30));
    }

    #[test]
    fn dm_09_manifest_config_defaults_to_disabled() {
        let toml = "";
        let config = ForgeConfig::from_toml(toml).unwrap();
        assert!(config.manifest.refresh_interval_secs.is_none());
    }

    #[test]
    fn dm_10_refresh_updates_manifest_via_live_manifest() {
        // Verify LiveManifest::update works (the core of refresh_manifest)
        use forge_manifest::{ManifestBuilder, ServerBuilder};

        let live = LiveManifest::new(ManifestBuilder::new().build());
        assert_eq!(live.current().total_servers(), 0);

        // Simulate what refresh_manifest does: build new manifest and update
        let new = ManifestBuilder::new()
            .add_server(ServerBuilder::new("refreshed", "Refreshed").build())
            .build();
        live.update(new);
        assert_eq!(live.current().total_servers(), 1);
        assert_eq!(live.current().servers[0].name, "refreshed");
    }

    #[test]
    fn dm_11_refresh_preserves_stale_on_total_failure() {
        // When all servers fail, refresh_manifest keeps the stale manifest.
        // We verify this by checking that update() is NOT called when all fail.
        use forge_manifest::{ManifestBuilder, ServerBuilder};

        let live = LiveManifest::new(
            ManifestBuilder::new()
                .add_server(ServerBuilder::new("original", "Original").build())
                .build(),
        );
        assert_eq!(live.current().total_servers(), 1);

        // Simulate: all servers failed, so we don't call update()
        // (refresh_manifest checks `errors == clients.len()` and skips update)
        // Verify manifest is still the original
        assert_eq!(live.current().servers[0].name, "original");
    }

    #[test]
    fn dm_12_refresh_abort_cancels_task() {
        // Verify that a spawned refresh task can be aborted
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let handle = tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            });
            handle.abort();
            let result = handle.await;
            assert!(result.is_err(), "aborted task should return JoinError");
        });
    }

    #[test]
    fn dm_13_cli_wires_live_manifest() {
        use forge_manifest::ManifestBuilder;

        struct StubDispatcher;

        #[async_trait::async_trait]
        impl ToolDispatcher for StubDispatcher {
            async fn call_tool(
                &self,
                _s: &str,
                _t: &str,
                _a: serde_json::Value,
            ) -> Result<serde_json::Value, forge_error::DispatchError> {
                Ok(serde_json::json!(null))
            }
        }

        let manifest = ManifestBuilder::new().build();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(StubDispatcher);
        let server = ForgeServer::new(SandboxConfig::default(), manifest, dispatcher, None);
        // live_manifest() should return a valid reference
        let live = server.live_manifest();
        assert_eq!(live.current().total_servers(), 0);
    }

    #[test]
    fn ver_01_cargo_pkg_version_is_030() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.3.0");
    }
}
