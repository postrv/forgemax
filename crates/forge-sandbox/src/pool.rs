//! Worker pool for reusing sandbox child processes across executions.
//!
//! Instead of spawning a new `forgemax-worker` for every `execute()` call (~50ms),
//! the pool keeps warm workers alive and reuses them. Each reuse sends a
//! [`Reset`](crate::ipc::ParentMessage::Reset) message that causes the worker to
//! drop its V8 runtime and create a fresh one (~5-10ms).
//!
//! **Security invariant**: Every execution gets a completely fresh V8 Isolate +
//! Context. There is no state leakage between executions.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::BufReader;
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

use crate::error::SandboxError;
use crate::host::{find_worker_binary, ipc_event_loop};
use crate::ipc::{read_message, write_message, ChildMessage, ParentMessage, WorkerConfig};
use crate::{ResourceDispatcher, StashDispatcher, ToolDispatcher};

/// Configuration for the worker pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum warm workers to keep ready.
    pub min_workers: usize,
    /// Maximum workers in the pool.
    pub max_workers: usize,
    /// Kill idle workers after this duration.
    pub max_idle_time: Duration,
    /// Recycle a worker after this many executions.
    pub max_uses: u32,
    /// Timeout for a health-check Reset round-trip.
    pub health_check_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_workers: 2,
            max_workers: 8,
            max_idle_time: Duration::from_secs(60),
            max_uses: 50,
            health_check_timeout: Duration::from_millis(500),
        }
    }
}

/// Atomic counters for pool observability.
#[derive(Debug, Default)]
pub struct PoolMetrics {
    /// Total workers spawned.
    pub spawned: AtomicU64,
    /// Total workers reused (acquired from idle pool).
    pub reused: AtomicU64,
    /// Workers killed because they hit max_uses.
    pub killed_max_uses: AtomicU64,
    /// Workers killed because they were idle too long.
    pub killed_idle: AtomicU64,
    /// Workers killed due to errors (crash, health-check failure).
    pub killed_error: AtomicU64,
}

/// A warm worker process that can be reused.
struct PoolWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    uses: u32,
    idle_since: Instant,
}

/// Outcome of using a worker, reported back to the pool on release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReleaseOutcome {
    /// Execution completed normally — worker can be reused.
    Ok,
    /// Execution failed fatally — worker must be killed (timeout, heap OOM, crash).
    Fatal,
}

/// A checked-out worker handle. The pool retains no reference to this worker
/// while it is in use; the caller owns it.
pub struct AcquiredWorker {
    worker: Option<PoolWorker>,
}

impl AcquiredWorker {
    /// Execute code on this worker, routing IPC through the given dispatchers.
    ///
    /// Returns the execution result. On completion, call
    /// [`WorkerPool::release`] with the appropriate outcome.
    pub async fn execute(
        &mut self,
        code: &str,
        config: &crate::SandboxConfig,
        dispatcher: Arc<dyn ToolDispatcher>,
        resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
        stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
    ) -> Result<serde_json::Value, SandboxError> {
        let w = self.worker.as_mut().expect("worker already consumed");

        // Send Execute message
        let worker_config = WorkerConfig::from(config);
        let execute_msg = ParentMessage::Execute {
            code: code.to_string(),
            manifest: None,
            config: worker_config,
        };
        write_message(&mut w.stdin, &execute_msg)
            .await
            .map_err(|e| {
                SandboxError::Execution(anyhow::anyhow!(
                    "failed to send Execute to pooled worker: {}",
                    e
                ))
            })?;

        w.uses += 1;

        // Run IPC event loop with timeout
        let timeout = config.timeout + Duration::from_secs(2);
        let result = tokio::time::timeout(
            timeout,
            ipc_event_loop(
                &mut w.stdin,
                &mut w.stdout,
                dispatcher,
                resource_dispatcher,
                stash_dispatcher,
            ),
        )
        .await;

        match result {
            Ok(inner) => inner,
            Err(_elapsed) => {
                // Timeout — the caller should release with Fatal
                Err(SandboxError::Timeout {
                    timeout_ms: config.timeout.as_millis() as u64,
                })
            }
        }
    }
}

/// A pool of warm worker processes.
pub struct WorkerPool {
    config: PoolConfig,
    idle_workers: Mutex<VecDeque<PoolWorker>>,
    /// Total workers currently alive (idle + checked out).
    alive_count: Mutex<usize>,
    metrics: Arc<PoolMetrics>,
    /// Flag to prevent new acquisitions during shutdown.
    shutting_down: Mutex<bool>,
}

impl WorkerPool {
    /// Create a new worker pool with the given configuration.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            idle_workers: Mutex::new(VecDeque::new()),
            alive_count: Mutex::new(0),
            metrics: Arc::new(PoolMetrics::default()),
            shutting_down: Mutex::new(false),
        }
    }

    /// Get a reference to the pool metrics.
    pub fn metrics(&self) -> &Arc<PoolMetrics> {
        &self.metrics
    }

    /// Acquire a worker from the pool, spawning a new one if necessary.
    ///
    /// Returns `None` if the pool is shutting down or at capacity.
    #[tracing::instrument(skip(self, sandbox_config))]
    pub async fn acquire(
        &self,
        sandbox_config: &crate::SandboxConfig,
    ) -> Result<AcquiredWorker, SandboxError> {
        if *self.shutting_down.lock().await {
            return Err(SandboxError::Execution(anyhow::anyhow!(
                "worker pool is shutting down"
            )));
        }

        let worker_config = WorkerConfig::from(sandbox_config);

        // Try to get an idle worker
        loop {
            let mut idle = self.idle_workers.lock().await;
            if let Some(mut w) = idle.pop_front() {
                drop(idle); // Release lock before I/O

                // Health check: send Reset and wait for ResetComplete
                let healthy = self.health_check(&mut w, &worker_config).await;
                if healthy {
                    self.metrics.reused.fetch_add(1, Ordering::Relaxed);
                    return Ok(AcquiredWorker { worker: Some(w) });
                } else {
                    // Kill unhealthy worker, try next
                    self.kill_worker(w).await;
                    self.metrics.killed_error.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            } else {
                drop(idle);
                break;
            }
        }

        // No idle workers — spawn a new one if under capacity
        let mut alive = self.alive_count.lock().await;
        if *alive >= self.config.max_workers {
            return Err(SandboxError::Execution(anyhow::anyhow!(
                "worker pool at capacity ({} workers)",
                self.config.max_workers
            )));
        }

        let worker = self.spawn_worker().await?;
        *alive += 1;
        drop(alive);

        // Send Reset to initialize for this execution's config
        let mut w = worker;
        let healthy = self.health_check(&mut w, &worker_config).await;
        if !healthy {
            self.kill_worker(w).await;
            return Err(SandboxError::Execution(anyhow::anyhow!(
                "newly spawned worker failed health check"
            )));
        }

        Ok(AcquiredWorker { worker: Some(w) })
    }

    /// Return a worker to the pool after use.
    ///
    /// If the outcome is [`ReleaseOutcome::Fatal`] or the worker has exceeded
    /// `max_uses`, the worker is killed instead of returned to the idle pool.
    #[tracing::instrument(skip(self, handle), fields(outcome = ?outcome))]
    pub async fn release(&self, mut handle: AcquiredWorker, outcome: ReleaseOutcome) {
        let worker = match handle.worker.take() {
            Some(w) => w,
            None => return,
        };

        if outcome == ReleaseOutcome::Fatal {
            self.kill_worker(worker).await;
            self.metrics.killed_error.fetch_add(1, Ordering::Relaxed);
            return;
        }

        if worker.uses >= self.config.max_uses {
            self.kill_worker(worker).await;
            self.metrics.killed_max_uses.fetch_add(1, Ordering::Relaxed);
            return;
        }

        if *self.shutting_down.lock().await {
            self.kill_worker(worker).await;
            return;
        }

        // Return to idle pool
        let mut w = worker;
        w.idle_since = Instant::now();
        self.idle_workers.lock().await.push_back(w);
    }

    /// Shut down the pool, killing all idle workers.
    pub async fn shutdown(&self) {
        *self.shutting_down.lock().await = true;

        let mut idle = self.idle_workers.lock().await;
        let workers: Vec<PoolWorker> = idle.drain(..).collect();
        drop(idle);

        for w in workers {
            self.kill_worker(w).await;
        }
    }

    /// Reap idle workers that have exceeded `max_idle_time`.
    ///
    /// Call this periodically (e.g., every 10 seconds) from a background task.
    pub async fn reap_idle(&self) {
        let mut idle = self.idle_workers.lock().await;
        let now = Instant::now();
        let mut to_kill = Vec::new();
        let mut kept = VecDeque::new();

        while let Some(w) = idle.pop_front() {
            if now.duration_since(w.idle_since) > self.config.max_idle_time {
                to_kill.push(w);
            } else {
                kept.push_back(w);
            }
        }
        *idle = kept;
        drop(idle);

        for w in to_kill {
            self.kill_worker(w).await;
            self.metrics.killed_idle.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Spawn a fresh worker process.
    async fn spawn_worker(&self) -> Result<PoolWorker, SandboxError> {
        let worker_bin = find_worker_binary()?;

        let mut child = tokio::process::Command::new(&worker_bin)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(if std::env::var("FORGE_DEBUG").is_ok() {
                std::process::Stdio::inherit()
            } else {
                std::process::Stdio::null()
            })
            .env_clear()
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                SandboxError::Execution(anyhow::anyhow!(
                    "failed to spawn pooled worker at {}: {}",
                    worker_bin.display(),
                    e
                ))
            })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| SandboxError::Execution(anyhow::anyhow!("no stdin on pooled worker")))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            SandboxError::Execution(anyhow::anyhow!("no stdout on pooled worker"))
        })?;

        self.metrics.spawned.fetch_add(1, Ordering::Relaxed);

        Ok(PoolWorker {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            uses: 0,
            idle_since: Instant::now(),
        })
    }

    /// Send a Reset message and wait for ResetComplete within the health check timeout.
    async fn health_check(&self, w: &mut PoolWorker, config: &WorkerConfig) -> bool {
        let reset_msg = ParentMessage::Reset {
            config: config.clone(),
        };

        // Send Reset
        if write_message(&mut w.stdin, &reset_msg).await.is_err() {
            return false;
        }

        // Wait for ResetComplete
        matches!(
            tokio::time::timeout(
                self.config.health_check_timeout,
                read_message::<ChildMessage, _>(&mut w.stdout),
            )
            .await,
            Ok(Ok(Some(ChildMessage::ResetComplete)))
        )
    }

    /// Kill a worker process and decrement the alive counter.
    async fn kill_worker(&self, mut w: PoolWorker) {
        let _ = w.child.kill().await;
        let mut alive = self.alive_count.lock().await;
        *alive = alive.saturating_sub(1);
    }
}

// Drop the worker handle — if it wasn't released properly, kill the worker.
impl Drop for AcquiredWorker {
    fn drop(&mut self) {
        if let Some(mut w) = self.worker.take() {
            // Best-effort kill — can't async in Drop, but kill_on_drop handles it
            let _ = w.child.start_kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.min_workers, 2);
        assert_eq!(config.max_workers, 8);
        assert_eq!(config.max_idle_time, Duration::from_secs(60));
        assert_eq!(config.max_uses, 50);
        assert_eq!(config.health_check_timeout, Duration::from_millis(500));
    }

    #[test]
    fn pool_metrics_default_zero() {
        let m = PoolMetrics::default();
        assert_eq!(m.spawned.load(Ordering::Relaxed), 0);
        assert_eq!(m.reused.load(Ordering::Relaxed), 0);
        assert_eq!(m.killed_max_uses.load(Ordering::Relaxed), 0);
        assert_eq!(m.killed_idle.load(Ordering::Relaxed), 0);
        assert_eq!(m.killed_error.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn release_outcome_eq() {
        assert_eq!(ReleaseOutcome::Ok, ReleaseOutcome::Ok);
        assert_eq!(ReleaseOutcome::Fatal, ReleaseOutcome::Fatal);
        assert_ne!(ReleaseOutcome::Ok, ReleaseOutcome::Fatal);
    }

    #[tokio::test]
    async fn pool_new_starts_empty() {
        let pool = WorkerPool::new(PoolConfig::default());
        let idle = pool.idle_workers.lock().await;
        assert_eq!(idle.len(), 0);
        assert_eq!(*pool.alive_count.lock().await, 0);
    }

    #[tokio::test]
    async fn pool_shutdown_sets_flag() {
        let pool = WorkerPool::new(PoolConfig::default());
        assert!(!*pool.shutting_down.lock().await);
        pool.shutdown().await;
        assert!(*pool.shutting_down.lock().await);
    }

    #[tokio::test]
    async fn pool_reap_empty_is_noop() {
        let pool = WorkerPool::new(PoolConfig::default());
        pool.reap_idle().await;
        assert_eq!(pool.idle_workers.lock().await.len(), 0);
    }
}
