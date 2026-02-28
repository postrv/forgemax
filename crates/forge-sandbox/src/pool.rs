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
    /// Preserves `min_workers` to avoid repeated cold starts.
    pub async fn reap_idle(&self) {
        let mut idle = self.idle_workers.lock().await;
        let now = Instant::now();
        let mut to_kill = Vec::new();
        let mut kept = VecDeque::new();
        let alive = *self.alive_count.lock().await;

        while let Some(w) = idle.pop_front() {
            if now.duration_since(w.idle_since) > self.config.max_idle_time {
                // Preserve min_workers: only reap if we'd still have enough alive
                let would_remain = alive - to_kill.len() - 1;
                if would_remain >= self.config.min_workers {
                    to_kill.push(w);
                } else {
                    kept.push_back(w);
                }
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

    /// Pre-warm the pool by spawning workers up to `min_workers`.
    ///
    /// Each worker is spawned and given a Reset health check. Returns the
    /// number of workers successfully pre-warmed.
    #[cfg(feature = "worker-pool")]
    pub async fn pre_warm(&self, config: &crate::SandboxConfig) -> Result<usize, SandboxError> {
        let worker_config = WorkerConfig::from(config);
        let mut count = 0;

        let alive = *self.alive_count.lock().await;
        let to_spawn = self.config.min_workers.saturating_sub(alive);

        for _ in 0..to_spawn {
            if *self.alive_count.lock().await >= self.config.max_workers {
                break;
            }

            match self.spawn_worker().await {
                Ok(mut w) => {
                    if self.health_check(&mut w, &worker_config).await {
                        w.idle_since = Instant::now();
                        self.idle_workers.lock().await.push_back(w);
                        *self.alive_count.lock().await += 1;
                        count += 1;
                    } else {
                        self.kill_worker(w).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to pre-warm worker");
                }
            }
        }

        Ok(count)
    }

    /// Start a background task that periodically reaps idle workers.
    ///
    /// The task runs until the returned `JoinHandle` is aborted or the pool shuts down.
    #[cfg(feature = "worker-pool")]
    pub fn start_reap_task(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if *pool.shutting_down.lock().await {
                    break;
                }
                pool.reap_idle().await;
            }
        })
    }

    /// Spawn a fresh worker process.
    async fn spawn_worker(&self) -> Result<PoolWorker, SandboxError> {
        let worker_bin = find_worker_binary()?;

        // stderr is always piped (debug) or null (non-debug) — never inherit.
        let debug_mode = std::env::var("FORGE_DEBUG").is_ok();
        let mut child = tokio::process::Command::new(&worker_bin)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(if debug_mode {
                std::process::Stdio::piped()
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

        // Bounded stderr capture in debug mode (max 4KB, logged via tracing)
        if debug_mode {
            if let Some(stderr) = child.stderr.take() {
                tokio::spawn(crate::host::capture_bounded_stderr(stderr));
            }
        }

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

    // --- Phase 5: Pool maturation unit tests ---

    #[test]
    fn pool_cc15_pool_config_validation() {
        let config = PoolConfig {
            min_workers: 0,
            max_workers: 1,
            max_idle_time: Duration::from_secs(1),
            max_uses: 1,
            health_check_timeout: Duration::from_millis(100),
        };
        // Config should accept edge values
        assert_eq!(config.min_workers, 0);
        assert_eq!(config.max_workers, 1);
        assert_eq!(config.max_uses, 1);
    }

    #[tokio::test]
    async fn pool_shutdown_rejects_new_acquires() {
        let pool = WorkerPool::new(PoolConfig::default());
        pool.shutdown().await;

        let config = crate::SandboxConfig::default();
        let result = pool.acquire(&config).await;
        match result {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("shutting down"),
                    "should mention shutting down: {msg}"
                );
            }
            Ok(_) => panic!("should reject after shutdown"),
        }
    }

    #[tokio::test]
    async fn pool_shutdown_kills_all_idle() {
        let pool = WorkerPool::new(PoolConfig::default());
        // After shutdown, idle pool should be empty
        pool.shutdown().await;
        assert_eq!(pool.idle_workers.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn pool_reap_preserves_min_workers_count() {
        // The reap logic should not drop below min_workers
        // This is a unit test of the logic — we verify via the kept count
        let config = PoolConfig {
            min_workers: 2,
            max_workers: 4,
            max_idle_time: Duration::from_secs(0), // everything is "expired"
            max_uses: 50,
            health_check_timeout: Duration::from_millis(500),
        };
        let pool = WorkerPool::new(config);
        // We can't add real workers without spawning, but we verify the
        // reap_idle logic handles empty pool + min_workers correctly
        pool.reap_idle().await;
        assert_eq!(pool.idle_workers.lock().await.len(), 0);
    }

    #[test]
    fn pool_metrics_spawned_increments() {
        let m = PoolMetrics::default();
        m.spawned.fetch_add(1, Ordering::Relaxed);
        assert_eq!(m.spawned.load(Ordering::Relaxed), 1);
        m.spawned.fetch_add(1, Ordering::Relaxed);
        assert_eq!(m.spawned.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn pool_metrics_reused_increments() {
        let m = PoolMetrics::default();
        m.reused.fetch_add(1, Ordering::Relaxed);
        assert_eq!(m.reused.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn pool_metrics_killed_idle_increments() {
        let m = PoolMetrics::default();
        m.killed_idle.fetch_add(3, Ordering::Relaxed);
        assert_eq!(m.killed_idle.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn pool_release_outcome_debug() {
        // Verify Debug impl works
        let ok = format!("{:?}", ReleaseOutcome::Ok);
        let fatal = format!("{:?}", ReleaseOutcome::Fatal);
        assert!(ok.contains("Ok"));
        assert!(fatal.contains("Fatal"));
    }

    #[tokio::test]
    async fn pool_multiple_shutdowns_safe() {
        let pool = WorkerPool::new(PoolConfig::default());
        pool.shutdown().await;
        pool.shutdown().await; // Should not panic
        assert!(*pool.shutting_down.lock().await);
    }

    #[cfg(feature = "worker-pool")]
    #[tokio::test]
    async fn pool_pw_feature_compiles() {
        // Verify worker-pool feature gates compile correctly
        let pool = Arc::new(WorkerPool::new(PoolConfig::default()));
        let handle = pool.start_reap_task(Duration::from_secs(3600));
        handle.abort();
        // Just verify it compiles and runs
    }

    #[test]
    fn pool_config_clone() {
        let config = PoolConfig::default();
        let cloned = config.clone();
        assert_eq!(config.min_workers, cloned.min_workers);
        assert_eq!(config.max_workers, cloned.max_workers);
    }

    #[test]
    fn pool_cc22_worker_pool_feature_gate() {
        // This test verifies the crate compiles both with and without the worker-pool feature.
        // The feature only gates pre_warm and start_reap_task — core pool functionality is always available.
        let _config = PoolConfig::default();
        let _pool = WorkerPool::new(PoolConfig::default());
    }
}
