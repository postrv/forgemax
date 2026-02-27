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
use forge_manifest::{server_entry_from_tools, ManifestBuilder, McpTool};
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

    let server = ForgeServer::new(sandbox_config, manifest, dispatcher, resource_dispatcher)
        .with_stash(stash_config);
    let server = if let Some(policy) = group_policy {
        server.with_group_policy(policy)
    } else {
        server
    };

    // Serve over stdio (standard MCP transport)
    let service = server.serve(rmcp::transport::io::stdio()).await?;

    // Wait for either normal shutdown or ctrl-c
    tokio::select! {
        result = service.waiting() => { result?; }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received shutdown signal, stopping gracefully");
        }
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
}
