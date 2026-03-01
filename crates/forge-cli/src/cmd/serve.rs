//! `forgemax serve` — start the MCP gateway server.
//!
//! This is the default command when no subcommand is specified.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use forge_manifest::{server_entry_from_tools, LiveManifest, ManifestBuilder, McpTool};
use forge_sandbox::audit::TracingAuditLogger;
use forge_sandbox::groups::GroupPolicy;
use forge_sandbox::ExecutionMode;
use forge_server::ForgeServer;
use rmcp::ServiceExt;

use crate::common;

/// Re-discover tools from all downstream servers and update the live manifest.
///
/// Errors from individual servers are logged but don't fail the whole refresh —
/// the stale manifest is preserved for any server that can't be reached.
async fn refresh_manifest(
    clients: &[(String, String, Arc<forge_client::McpClient>)],
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

/// Execute the serve command (start the MCP gateway).
pub async fn execute(config_path: Option<PathBuf>) -> Result<()> {
    let config = common::load_config(config_path.as_ref())?;
    let sandbox_config = common::build_sandbox_config(&config.sandbox);

    // Connect to downstream servers and build manifest
    let result = common::connect_and_build_manifest(&config).await?;

    tracing::info!(
        servers = result.manifest.total_servers(),
        tools = result.manifest.total_tools(),
        has_resources = result.resource_dispatcher.is_some(),
        "Forgemax Code Mode Gateway starting"
    );

    // Build group policy if groups are configured
    let group_policy = if !config.groups.is_empty() {
        let groups = common::build_group_map(&config);
        Some(GroupPolicy::from_config(&groups))
    } else {
        None
    };

    // Build stash config from overrides (defaults if not configured)
    let stash_overrides = config.sandbox.stash.clone().unwrap_or_default();
    let stash_config = common::build_stash_config(&stash_overrides);

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

    let server = ForgeServer::new_with_executor(
        executor,
        result.manifest,
        result.dispatcher,
        result.resource_dispatcher,
    )
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
        let clients = result.client_refs.clone();
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
                let _ = refresh_manifest(&result.client_refs, &live_manifest).await;
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
