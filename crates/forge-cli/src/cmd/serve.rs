//! `forgemax serve` — start the MCP gateway server.
//!
//! This is the default command when no subcommand is specified.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use forge_manifest::LiveManifest;
use forge_sandbox::audit::TracingAuditLogger;
use forge_sandbox::groups::GroupPolicy;
use forge_sandbox::ExecutionMode;
use forge_server::ForgeServer;
use rmcp::ServiceExt;
use tokio::time::{self, Instant, MissedTickBehavior};

use crate::common;

/// Re-discover tools from all downstream servers and update the live manifest.
///
/// Errors from individual servers are logged but don't fail the whole refresh —
/// the stale manifest is preserved for any server that can't be reached.
async fn refresh_manifest(sources: &[common::CatalogSource], live: &LiveManifest) {
    let mut next = (*live.snapshot()).clone();
    let manifest = Arc::make_mut(&mut next.manifest);
    let mut updated = false;

    for (source, entry) in sources.iter().zip(&mut manifest.servers) {
        match source.list_tools().await {
            Ok(tools) => {
                let (updated_entry, tool_names) =
                    common::catalog_entry(&source.name, &entry.description, tools);
                entry.categories = updated_entry.categories;
                next.tool_names.insert(source.name.clone(), tool_names);
                updated = true;
                tracing::debug!(server = %source.name, "manifest refresh: server OK");
            }
            Err(e) => {
                tracing::warn!(server = %source.name, error = %e, "manifest refresh: server failed, keeping stale data");
            }
        }
    }

    if updated {
        tracing::info!(
            servers = manifest.total_servers(),
            tools = manifest.total_tools(),
            "manifest refreshed"
        );
        live.publish(next);
    }
}

/// Execute the serve command (start the MCP gateway).
pub async fn execute(config_path: Option<PathBuf>) -> Result<()> {
    let config = common::load_config(config_path.as_ref())?;
    let sandbox_config = common::build_sandbox_config(&config.sandbox);

    // Connect to downstream servers and build manifest
    let result = common::connect_and_build_manifest(&config).await?;
    {
        let initial_manifest = result.manifest.current();
        tracing::info!(
            servers = initial_manifest.total_servers(),
            tools = initial_manifest.total_tools(),
            has_resources = result.resource_dispatcher.is_some(),
            "Forgemax Code Mode Gateway starting"
        );
    }

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

    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    let live_manifest = server.live_manifest().clone();
    let service = server.serve(rmcp::transport::io::stdio()).await?;

    // Serialize both triggers to keep overlapping refreshes from publishing out of order.
    let refresh_interval = config.manifest.refresh_interval_secs.unwrap_or(0);
    let mut interval = if refresh_interval == 0 {
        None
    } else {
        let period = Duration::from_secs(refresh_interval);
        let start = Instant::now()
            .checked_add(period)
            .context("manifest.refresh_interval_secs is too large")?;
        let mut interval = time::interval_at(start, period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Some(interval)
    };
    let refresh = async {
        loop {
            tokio::select! {
                _ = async {
                    match &mut interval {
                        Some(interval) => { interval.tick().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {}
                _ = async {
                    #[cfg(unix)]
                    { sighup.recv().await; }
                    #[cfg(not(unix))]
                    std::future::pending::<()>().await
                } => {}
            }
            refresh_manifest(&result.catalog_sources, &live_manifest).await;
        }
    };

    tokio::select! {
        result = service.waiting() => { result?; }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received shutdown signal, stopping gracefully");
        }
        _ = refresh => {}
    }

    // Shut down worker pool if active
    if let Some(pool) = pool {
        pool.shutdown().await;
    }

    Ok(())
}
