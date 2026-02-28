//! Integration tests for the worker pool.
//!
//! These tests verify that the pool correctly:
//! - Reuses worker processes across executions
//! - Handles concurrent workloads
//! - Recovers from worker crashes/errors
//! - Enforces max_uses recycling
//! - Maintains complete context isolation between executions
//! - Shuts down gracefully
//!
//! All tests are serialized to avoid resource contention from multiple
//! V8 worker processes competing on CI runners.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use forge_sandbox::executor::ExecutionMode;
use forge_sandbox::pool::{PoolConfig, WorkerPool};
use forge_sandbox::{SandboxConfig, SandboxExecutor, ToolDispatcher};
use serial_test::serial;

/// Test dispatcher that echoes back server/tool/args.
struct EchoDispatcher;

#[async_trait::async_trait]
impl ToolDispatcher for EchoDispatcher {
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        Ok(serde_json::json!({
            "server": server,
            "tool": tool,
            "args": args,
            "status": "ok"
        }))
    }
}

fn pool_config() -> PoolConfig {
    PoolConfig {
        min_workers: 1,
        max_workers: 4,
        max_idle_time: Duration::from_secs(60),
        max_uses: 50,
        health_check_timeout: Duration::from_millis(2000),
    }
}

fn sandbox_config() -> SandboxConfig {
    SandboxConfig {
        execution_mode: ExecutionMode::ChildProcess,
        timeout: Duration::from_secs(30),
        ..Default::default()
    }
}

fn make_executor(pool: Arc<WorkerPool>) -> SandboxExecutor {
    SandboxExecutor::new(sandbox_config()).with_pool(pool)
}

// --- WP-I01: Sequential reuse ---
// Execute twice sequentially through the pool. Verify the second execution
// reuses the worker (spawned=1, reused=1).
#[tokio::test]
#[serial]
async fn wp_i01_sequential_reuse() {
    let pool = Arc::new(WorkerPool::new(pool_config()));
    let exec = make_executor(pool.clone());
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(EchoDispatcher);

    // First execution — should spawn a new worker
    let code = r#"async () => { return { run: 1 }; }"#;
    let r1 = exec
        .execute_code(code, dispatcher.clone(), None, None)
        .await
        .unwrap();
    assert_eq!(r1["run"], 1);

    // Second execution — should reuse the worker
    let code = r#"async () => { return { run: 2 }; }"#;
    let r2 = exec
        .execute_code(code, dispatcher, None, None)
        .await
        .unwrap();
    assert_eq!(r2["run"], 2);

    let metrics = pool.metrics();
    assert_eq!(
        metrics.spawned.load(Ordering::Relaxed),
        1,
        "should have spawned exactly 1 worker"
    );
    assert_eq!(
        metrics.reused.load(Ordering::Relaxed),
        1,
        "second execution should reuse the first worker"
    );

    pool.shutdown().await;
}

// --- WP-I02: Concurrent burst ---
// Execute multiple tasks concurrently. All should succeed. Workers spawned <= max_workers.
#[tokio::test]
#[serial]
async fn wp_i02_concurrent_burst() {
    let pool = Arc::new(WorkerPool::new(PoolConfig {
        max_workers: 4,
        ..pool_config()
    }));
    let exec = Arc::new(make_executor(pool.clone()));

    let mut handles = Vec::new();
    for i in 0..4 {
        let exec = exec.clone();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(EchoDispatcher);
        let handle = tokio::spawn(async move {
            let code = format!(r#"async () => {{ return {{ task: {} }}; }}"#, i);
            exec.execute_code(&code, dispatcher, None, None).await
        });
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await.unwrap().unwrap();
        results.push(result["task"].as_i64().unwrap());
    }
    results.sort();
    assert_eq!(results, vec![0, 1, 2, 3]);

    let metrics = pool.metrics();
    assert!(
        metrics.spawned.load(Ordering::Relaxed) <= 4,
        "should not spawn more than max_workers"
    );

    pool.shutdown().await;
}

// --- WP-I03: Crash recovery ---
// Execute code that causes the worker to fail fatally, then verify the pool
// recovers and can serve a subsequent healthy execution.
#[tokio::test]
#[serial]
async fn wp_i03_crash_recovery() {
    let pool = Arc::new(WorkerPool::new(pool_config()));
    let exec = make_executor(pool.clone());
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(EchoDispatcher);

    // This should time out (CPU-bound infinite loop kills the worker)
    let config = SandboxConfig {
        execution_mode: ExecutionMode::ChildProcess,
        timeout: Duration::from_millis(500),
        ..Default::default()
    };
    let exec_timeout = SandboxExecutor::new(config).with_pool(pool.clone());
    let code = r#"async () => { while(true) {} }"#;
    let err = exec_timeout
        .execute_code(code, dispatcher.clone(), None, None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("timed out") || msg.contains("timeout"),
        "expected timeout, got: {msg}"
    );

    // Pool should recover — next execution should work fine
    let code = r#"async () => { return { recovered: true }; }"#;
    let result = exec
        .execute_code(code, dispatcher, None, None)
        .await
        .unwrap();
    assert_eq!(result["recovered"], true);

    let metrics = pool.metrics();
    assert!(
        metrics.killed_error.load(Ordering::Relaxed) >= 1,
        "timeout worker should be killed via fatal release"
    );

    pool.shutdown().await;
}

// --- WP-I04: Graceful shutdown ---
// After shutdown, acquire should fail. Existing workers should be killed.
#[tokio::test]
#[serial]
async fn wp_i04_graceful_shutdown() {
    let pool = Arc::new(WorkerPool::new(pool_config()));
    let exec = make_executor(pool.clone());
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(EchoDispatcher);

    // Execute once to populate the pool with an idle worker
    let code = r#"async () => { return "warmup"; }"#;
    let _ = exec
        .execute_code(code, dispatcher.clone(), None, None)
        .await
        .unwrap();

    // Shutdown the pool
    pool.shutdown().await;

    // Next execution should fall back to fresh process (pool acquire fails)
    let code = r#"async () => { return "after_shutdown"; }"#;
    let result = exec.execute_code(code, dispatcher, None, None).await;
    // Either succeeds via fallback, or fails with shutdown error
    // The executor has a fallback to fresh process when pool acquire fails
    match result {
        Ok(v) => assert_eq!(v, "after_shutdown"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("shutting down"),
                "expected shutdown error, got: {msg}"
            );
        }
    }
}

// --- WP-I05: Context isolation ---
// Execute code that sets a global variable, then verify the next execution
// on the same worker cannot see it. This is the most critical security test.
#[tokio::test]
#[serial]
async fn wp_i05_context_isolation() {
    let pool = Arc::new(WorkerPool::new(PoolConfig {
        max_workers: 1, // Force reuse of the same worker
        ..pool_config()
    }));
    let exec = make_executor(pool.clone());
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(EchoDispatcher);

    // First execution: set a "global" via closure scope trick
    let code1 = r#"async () => {
        // Try to leak state through various mechanisms
        globalThis.__leaked_secret = "SENSITIVE_DATA";
        return "planted";
    }"#;
    let r1 = exec
        .execute_code(code1, dispatcher.clone(), None, None)
        .await
        .unwrap();
    assert_eq!(r1, "planted");

    // Second execution: attempt to read the leaked state
    let code2 = r#"async () => {
        return {
            leaked: typeof globalThis.__leaked_secret !== "undefined"
                ? globalThis.__leaked_secret
                : null,
            hasGlobalThis: typeof globalThis !== "undefined",
        };
    }"#;
    let r2 = exec
        .execute_code(code2, dispatcher, None, None)
        .await
        .unwrap();

    // The leaked secret MUST NOT be visible
    assert_eq!(
        r2["leaked"],
        serde_json::Value::Null,
        "globalThis state MUST NOT leak between executions"
    );

    let metrics = pool.metrics();
    assert_eq!(
        metrics.reused.load(Ordering::Relaxed),
        1,
        "second execution should have reused the worker (proving isolation is worker-level, not process-level)"
    );

    pool.shutdown().await;
}

// --- WP-I06: max_uses recycling ---
// Set max_uses=2, execute 3 times. After the 2nd execution, the worker
// should be recycled (killed_max_uses > 0). The 3rd should spawn a new one.
#[tokio::test]
#[serial]
async fn wp_i06_max_uses_recycling() {
    let pool = Arc::new(WorkerPool::new(PoolConfig {
        max_workers: 1,
        max_uses: 2,
        ..pool_config()
    }));
    let exec = make_executor(pool.clone());
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(EchoDispatcher);

    for i in 0..3 {
        let code = format!(r#"async () => {{ return {{ iter: {} }}; }}"#, i);
        let result = exec
            .execute_code(&code, dispatcher.clone(), None, None)
            .await
            .unwrap();
        assert_eq!(result["iter"], i);
    }

    let metrics = pool.metrics();
    assert!(
        metrics.killed_max_uses.load(Ordering::Relaxed) >= 1,
        "worker should be recycled after max_uses executions"
    );
    assert!(
        metrics.spawned.load(Ordering::Relaxed) >= 2,
        "should have spawned at least 2 workers (1 recycled, 1 fresh)"
    );

    pool.shutdown().await;
}

// --- WP-I07: Tool calls work through pooled workers ---
// Verify that tool calls route correctly through IPC when using pooled workers.
#[tokio::test]
#[serial]
async fn wp_i07_tool_calls_through_pool() {
    let pool = Arc::new(WorkerPool::new(pool_config()));
    let exec = make_executor(pool.clone());
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(EchoDispatcher);

    let code = r#"async () => {
        const r1 = await forge.callTool("server-a", "tool.one", { key: "val1" });
        const r2 = await forge.callTool("server-b", "tool.two", { key: "val2" });
        return { r1, r2 };
    }"#;

    let result = exec
        .execute_code(code, dispatcher, None, None)
        .await
        .unwrap();
    assert_eq!(result["r1"]["server"], "server-a");
    assert_eq!(result["r1"]["tool"], "tool.one");
    assert_eq!(result["r1"]["args"]["key"], "val1");
    assert_eq!(result["r2"]["server"], "server-b");
    assert_eq!(result["r2"]["tool"], "tool.two");
    assert_eq!(result["r2"]["args"]["key"], "val2");

    pool.shutdown().await;
}
