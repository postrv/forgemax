//! Shared utility functions used by multiple CLI subcommands.

use std::collections::HashMap;
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
use forge_sandbox::stash::StashConfig;
use forge_sandbox::{ExecutionMode, ResourceDispatcher, SandboxConfig, ToolDispatcher};

/// Result of connecting to all configured servers and building a manifest.
pub struct ConnectResult {
    /// The tool router dispatcher.
    pub dispatcher: Arc<dyn ToolDispatcher>,
    /// The resource router dispatcher (if any server exposes resources).
    pub resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    /// The built manifest.
    pub manifest: forge_manifest::Manifest,
    /// Client references for manifest refresh.
    pub client_refs: Vec<(String, String, Arc<McpClient>)>,
}

/// Build SandboxConfig from config overrides.
pub fn build_sandbox_config(overrides: &forge_config::SandboxOverrides) -> SandboxConfig {
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
pub fn build_stash_config(overrides: &forge_config::StashOverrides) -> StashConfig {
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
pub fn to_transport_config(server: &forge_config::ServerConfig) -> Result<TransportConfig> {
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
pub fn find_config_file() -> Option<PathBuf> {
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

/// Load configuration from a config path or auto-detected location.
pub fn load_config(config_path: Option<&PathBuf>) -> Result<ForgeConfig> {
    let path = config_path.cloned().or_else(find_config_file);
    match path {
        Some(path) => {
            tracing::info!(path = %path.display(), "loading config");
            ForgeConfig::from_file_with_env(&path)
                .with_context(|| format!("failed to load config from {}", path.display()))
        }
        None => {
            tracing::info!("no config file found, starting with no downstream servers");
            ForgeConfig::from_toml("").map_err(Into::into)
        }
    }
}

/// Report which optional features are compiled in.
pub fn feature_status_line() -> String {
    let pool = if cfg!(feature = "worker-pool") {
        "on"
    } else {
        "off"
    };
    let metrics = if cfg!(feature = "metrics") {
        "on"
    } else {
        "off"
    };
    let watch = if cfg!(feature = "config-watch") {
        "on"
    } else {
        "off"
    };
    format!(
        "features: worker-pool={}, metrics={}, config-watch={}",
        pool, metrics, watch
    )
}

/// Connect to all downstream servers and build the capability manifest.
pub async fn connect_and_build_manifest(config: &ForgeConfig) -> Result<ConnectResult> {
    let mut router = RouterDispatcher::new();
    let mut resource_router = RouterResourceDispatcher::new();
    let mut manifest_builder = ManifestBuilder::new();
    let mut has_any_resources = false;
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

        // Extract tool names for pre-dispatch validation before mcp_tools is consumed
        let tool_names: Vec<String> = mcp_tools.iter().map(|t| t.name.clone()).collect();

        let description = server_config.description.as_deref().unwrap_or("MCP server");
        let server_entry = server_entry_from_tools(name, description, mcp_tools);
        manifest_builder = manifest_builder.add_server(server_entry);

        // Arc the client so it can be shared between tool and resource dispatchers.
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

        // Register known tool names for pre-dispatch validation, then add client
        router.set_known_tools(name.clone(), tool_names);
        router.add_client(name.clone(), client);
    }

    let manifest = manifest_builder.build();
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(router);
    let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> = if has_any_resources {
        Some(Arc::new(resource_router))
    } else {
        None
    };

    Ok(ConnectResult {
        dispatcher,
        resource_dispatcher,
        manifest,
        client_refs,
    })
}

/// Scan a string for `${VAR}` patterns and return the variable names.
pub fn find_env_var_refs(input: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            for c in chars.by_ref() {
                if c == '}' {
                    break;
                }
                var_name.push(c);
            }
            if !var_name.is_empty() {
                vars.push(var_name);
            }
        }
    }

    vars
}

/// Build a HashMap of group configurations from the ForgeConfig.
pub fn build_group_map(config: &ForgeConfig) -> HashMap<String, (Vec<String>, String)> {
    config
        .groups
        .iter()
        .map(|(name, gc)| (name.clone(), (gc.servers.clone(), gc.isolation.clone())))
        .collect()
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
        use forge_sandbox::audit::TracingAuditLogger;
        let logger = Arc::new(TracingAuditLogger);
        let config = SandboxConfig::default();
        let _executor = forge_sandbox::executor::SandboxExecutor::with_audit_logger(config, logger);
    }

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
        use forge_manifest::{LiveManifest, ManifestBuilder, ServerBuilder};

        let live = LiveManifest::new(ManifestBuilder::new().build());
        assert_eq!(live.current().total_servers(), 0);

        let new = ManifestBuilder::new()
            .add_server(ServerBuilder::new("refreshed", "Refreshed").build())
            .build();
        live.update(new);
        assert_eq!(live.current().total_servers(), 1);
        assert_eq!(live.current().servers[0].name, "refreshed");
    }

    #[test]
    fn dm_11_refresh_preserves_stale_on_total_failure() {
        use forge_manifest::{LiveManifest, ManifestBuilder, ServerBuilder};

        let live = LiveManifest::new(
            ManifestBuilder::new()
                .add_server(ServerBuilder::new("original", "Original").build())
                .build(),
        );
        assert_eq!(live.current().total_servers(), 1);
        assert_eq!(live.current().servers[0].name, "original");
    }

    #[test]
    fn dm_12_refresh_abort_cancels_task() {
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
        let server =
            forge_server::ForgeServer::new(SandboxConfig::default(), manifest, dispatcher, None);
        let live = server.live_manifest();
        assert_eq!(live.current().total_servers(), 0);
    }

    #[test]
    fn find_env_var_refs_finds_vars() {
        let vars = find_env_var_refs("Bearer ${TOKEN} from ${HOST}");
        assert_eq!(vars, vec!["TOKEN", "HOST"]);
    }

    #[test]
    fn find_env_var_refs_empty_on_no_vars() {
        let vars = find_env_var_refs("no variables here");
        assert!(vars.is_empty());
    }

    #[test]
    fn feature_status_line_has_all_features() {
        let line = feature_status_line();
        assert!(line.contains("worker-pool="), "got: {line}");
        assert!(line.contains("metrics="), "got: {line}");
        assert!(line.contains("config-watch="), "got: {line}");
    }

    #[test]
    fn ff_d07_feature_status_line_reports_enabled() {
        let line = feature_status_line();
        // These assertions are conditional: with default features, all are "on".
        // With --no-default-features, they would be "off".
        if cfg!(feature = "worker-pool") {
            assert!(line.contains("worker-pool=on"), "got: {line}");
        } else {
            assert!(line.contains("worker-pool=off"), "got: {line}");
        }
        if cfg!(feature = "metrics") {
            assert!(line.contains("metrics=on"), "got: {line}");
        } else {
            assert!(line.contains("metrics=off"), "got: {line}");
        }
        if cfg!(feature = "config-watch") {
            assert!(line.contains("config-watch=on"), "got: {line}");
        } else {
            assert!(line.contains("config-watch=off"), "got: {line}");
        }
    }
}
