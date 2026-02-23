#![warn(missing_docs)]

//! Forge Code Mode MCP Gateway
//!
//! Give your agent every tool. Use 1,000 tokens.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use forge_client::{McpClient, RouterDispatcher, TransportConfig};
use forge_config::ForgeConfig;
use forge_manifest::{server_entry_from_tools, ManifestBuilder, McpTool};
use forge_sandbox::{ExecutionMode, SandboxConfig, ToolDispatcher};
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
    config
}

/// Convert a ServerConfig to a TransportConfig.
fn to_transport_config(server: &forge_config::ServerConfig) -> TransportConfig {
    match server.transport.as_str() {
        "stdio" => TransportConfig::Stdio {
            command: server.command.clone().unwrap_or_default(),
            args: server.args.clone(),
        },
        "sse" => TransportConfig::Http {
            url: server.url.clone().unwrap_or_default(),
            headers: server.headers.clone(),
        },
        _ => unreachable!("validated in config"),
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
    let mut manifest_builder = ManifestBuilder::new();

    for (name, server_config) in &config.servers {
        let transport_config = to_transport_config(server_config);

        tracing::info!(server = %name, "connecting to downstream server");

        let client = McpClient::connect(name.clone(), &transport_config)
            .await
            .with_context(|| format!("failed to connect to server '{}'", name))?;

        // Discover tools
        let tools = client
            .list_tools()
            .await
            .with_context(|| format!("failed to list tools for server '{}'", name))?;

        tracing::info!(
            server = %name,
            tool_count = tools.len(),
            "discovered tools"
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

        let description = server_config
            .description
            .as_deref()
            .unwrap_or("MCP server");
        let server_entry = server_entry_from_tools(name, description, mcp_tools);
        manifest_builder = manifest_builder.add_server(server_entry);

        // Add client to router
        let client: Arc<dyn ToolDispatcher> = Arc::new(client);
        router.add_client(name.clone(), client);
    }

    let manifest = manifest_builder.build();
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(router);

    tracing::info!(
        servers = manifest.total_servers(),
        tools = manifest.total_tools(),
        "Forge Code Mode Gateway starting"
    );

    let server = ForgeServer::new(sandbox_config, manifest, dispatcher);

    // Serve over stdio (standard MCP transport)
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;

    Ok(())
}
