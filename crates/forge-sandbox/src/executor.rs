//! Sandbox executor — creates fresh V8 isolates and runs LLM-generated code.
//!
//! Each execution gets a brand new runtime. No state leaks between calls.
//!
//! V8 isolates are `!Send`, so all JsRuntime operations run on a dedicated
//! thread with its own single-threaded tokio runtime. The public API is
//! fully async and `Send`-safe.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use deno_core::{v8, JsRuntime, PollEventLoopOptions, RuntimeOptions};
use serde_json::Value;
use tokio::sync::Semaphore;

use crate::audit::{
    AuditEntryBuilder, AuditLogger, AuditOperation, AuditingDispatcher, NoopAuditLogger,
    ToolCallAudit,
};
use crate::error::SandboxError;
use crate::ops::{forge_ext, ExecutionResult, ToolCallLimits};
use crate::validator::validate_code;
use crate::ToolDispatcher;

/// How the sandbox executes code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Run V8 in-process on a dedicated thread (default, suitable for tests).
    #[default]
    InProcess,
    /// Spawn an isolated child process per execution (production security mode).
    ChildProcess,
}

/// Configuration for the sandbox executor.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum execution time before the sandbox is terminated.
    pub timeout: Duration,
    /// Maximum size of LLM-generated code in bytes.
    pub max_code_size: usize,
    /// Maximum size of the JSON result in bytes.
    pub max_output_size: usize,
    /// V8 heap limit in bytes.
    pub max_heap_size: usize,
    /// Maximum concurrent sandbox executions.
    pub max_concurrent: usize,
    /// Maximum tool calls per execution.
    pub max_tool_calls: usize,
    /// Maximum size of tool call arguments in bytes.
    pub max_tool_call_args_size: usize,
    /// Execution mode: in-process or child-process isolation.
    pub execution_mode: ExecutionMode,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_code_size: 64 * 1024,        // 64 KB
            max_output_size: 1024 * 1024,    // 1 MB
            max_heap_size: 64 * 1024 * 1024, // 64 MB
            max_concurrent: 8,
            max_tool_calls: 50,
            max_tool_call_args_size: 1024 * 1024, // 1 MB
            execution_mode: ExecutionMode::default(),
        }
    }
}

/// The sandbox executor. Creates fresh V8 isolates for each execution.
///
/// This is `Send + Sync` safe — all V8 operations are dispatched to a
/// dedicated thread internally. A concurrency semaphore limits the number
/// of simultaneous V8 isolates.
pub struct SandboxExecutor {
    config: SandboxConfig,
    semaphore: Arc<Semaphore>,
    audit_logger: Arc<dyn AuditLogger>,
}

impl SandboxExecutor {
    /// Create a new sandbox executor with the given configuration.
    pub fn new(config: SandboxConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self {
            config,
            semaphore,
            audit_logger: Arc::new(NoopAuditLogger),
        }
    }

    /// Create a new sandbox executor with an audit logger.
    pub fn with_audit_logger(config: SandboxConfig, logger: Arc<dyn AuditLogger>) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self {
            config,
            semaphore,
            audit_logger: logger,
        }
    }

    /// Execute a `search()` call — runs code against the capability manifest.
    ///
    /// The manifest is injected as `globalThis.manifest` in the sandbox.
    /// The LLM's code is an async arrow function that queries it.
    /// Search always runs in-process (read-only, no credential exposure risk).
    pub async fn execute_search(
        &self,
        code: &str,
        manifest: &Value,
    ) -> Result<Value, SandboxError> {
        tracing::info!(code_len = code.len(), "execute_search: starting");

        let audit_builder = AuditEntryBuilder::new(code, AuditOperation::Search);

        validate_code(code, Some(self.config.max_code_size))?;

        let _permit = self.semaphore.clone().try_acquire_owned().map_err(|_| {
            SandboxError::ConcurrencyLimit {
                max: self.config.max_concurrent,
            }
        })?;

        let code = code.to_string();
        let manifest = manifest.clone();
        let config = self.config.clone();

        // V8 isolates are !Send — run everything on a dedicated thread
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    if tx.send(Err(SandboxError::Execution(e.into()))).is_err() {
                        tracing::warn!("sandbox result receiver dropped");
                    }
                    return;
                }
            };
            let result = rt.block_on(run_search(&config, &code, &manifest));
            if tx.send(result).is_err() {
                tracing::warn!("sandbox result receiver dropped before result was sent");
            }
        });

        let result = rx
            .await
            .map_err(|_| SandboxError::Execution(anyhow::anyhow!("sandbox thread panicked")))?;

        // Emit audit entry
        let entry = audit_builder.finish(&result);
        self.audit_logger.log(&entry).await;

        match &result {
            Ok(_) => tracing::info!("execute_search: complete"),
            Err(e) => tracing::warn!(error = %e, "execute_search: failed"),
        }

        result
    }

    /// Execute an `execute()` call — runs code against the tool API.
    ///
    /// Tool calls go through `forge.callTool(server, tool, args)` which
    /// dispatches to the Rust-side ToolDispatcher via `op_forge_call_tool`.
    ///
    /// In `ChildProcess` mode, spawns an isolated worker process. In `InProcess`
    /// mode (default), runs V8 on a dedicated thread in the current process.
    pub async fn execute_code(
        &self,
        code: &str,
        dispatcher: Arc<dyn ToolDispatcher>,
    ) -> Result<Value, SandboxError> {
        tracing::info!(
            code_len = code.len(),
            mode = ?self.config.execution_mode,
            "execute_code: starting"
        );

        let mut audit_builder = AuditEntryBuilder::new(code, AuditOperation::Execute);

        validate_code(code, Some(self.config.max_code_size))?;

        let _permit = self.semaphore.clone().try_acquire_owned().map_err(|_| {
            SandboxError::ConcurrencyLimit {
                max: self.config.max_concurrent,
            }
        })?;

        // Wrap dispatcher with audit tracking
        let (audit_tx, mut audit_rx) = tokio::sync::mpsc::unbounded_channel::<ToolCallAudit>();
        let auditing_dispatcher: Arc<dyn ToolDispatcher> =
            Arc::new(AuditingDispatcher::new(dispatcher, audit_tx));

        let result = match self.config.execution_mode {
            ExecutionMode::ChildProcess => {
                crate::host::SandboxHost::execute_in_child(code, &self.config, auditing_dispatcher)
                    .await
            }
            ExecutionMode::InProcess => {
                self.execute_code_in_process(code, auditing_dispatcher)
                    .await
            }
        };

        // Collect tool call audits
        while let Ok(tool_audit) = audit_rx.try_recv() {
            audit_builder.record_tool_call(tool_audit);
        }

        // Emit audit entry
        let entry = audit_builder.finish(&result);
        self.audit_logger.log(&entry).await;

        match &result {
            Ok(_) => tracing::info!("execute_code: complete"),
            Err(e) => tracing::warn!(error = %e, "execute_code: failed"),
        }

        result
    }

    /// In-process execution: spawn a dedicated thread with its own V8 isolate.
    async fn execute_code_in_process(
        &self,
        code: &str,
        dispatcher: Arc<dyn ToolDispatcher>,
    ) -> Result<Value, SandboxError> {
        let code = code.to_string();
        let config = self.config.clone();

        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    if tx.send(Err(SandboxError::Execution(e.into()))).is_err() {
                        tracing::warn!("sandbox result receiver dropped");
                    }
                    return;
                }
            };
            let result = rt.block_on(run_execute(&config, &code, dispatcher));
            if tx.send(result).is_err() {
                tracing::warn!("sandbox result receiver dropped before result was sent");
            }
        });

        rx.await
            .map_err(|_| SandboxError::Execution(anyhow::anyhow!("sandbox thread panicked")))?
    }
}

/// State for the near-heap-limit callback.
struct HeapLimitState {
    handle: v8::IsolateHandle,
    /// Whether the heap limit has been triggered. Uses AtomicBool so the callback
    /// can use a shared `&` reference instead of `&mut`, eliminating aliasing concerns.
    triggered: AtomicBool,
}

/// V8 near-heap-limit callback. Terminates execution and grants 1MB grace
/// for the termination to propagate cleanly.
extern "C" fn near_heap_limit_callback(
    data: *mut std::ffi::c_void,
    current_heap_limit: usize,
    _initial_heap_limit: usize,
) -> usize {
    // SAFETY: `data` points to `heap_state` (Box<HeapLimitState>) allocated below.
    // The Box outlives this callback because: (1) the watchdog thread is joined
    // before heap_state is dropped, and (2) V8 only invokes this callback while the
    // isolate's event loop is running, which completes before the join.
    // We use a shared `&` reference (not `&mut`) because `triggered` is AtomicBool,
    // so no aliasing concerns even if V8 were to call this callback re-entrantly.
    let state = unsafe { &*(data as *const HeapLimitState) };
    if !state.triggered.swap(true, Ordering::SeqCst) {
        state.handle.terminate_execution();
    }
    // Grant 1MB grace so the termination exception can propagate
    current_heap_limit + 1024 * 1024
}

/// Run a search operation on the current thread (must be called from a
/// dedicated thread, not the main tokio runtime).
///
/// Public for reuse in the worker binary.
pub async fn run_search(
    config: &SandboxConfig,
    code: &str,
    manifest: &Value,
) -> Result<Value, SandboxError> {
    let mut runtime = create_runtime(None, config.max_heap_size, None)?;

    // Inject the manifest as a global
    let manifest_json = serde_json::to_string(manifest)?;
    let bootstrap = format!("globalThis.manifest = {};", manifest_json);
    runtime
        .execute_script("[forge:manifest]", bootstrap)
        .map_err(|e| SandboxError::JsError {
            message: e.to_string(),
        })?;

    // Bootstrap: capture ops in closures, create minimal forge object, delete Deno,
    // and remove dangerous code generation primitives.
    runtime
        .execute_script(
            "[forge:bootstrap]",
            r#"
                ((ops) => {
                    const setResult = (json) => ops.op_forge_set_result(json);
                    const log = (msg) => ops.op_forge_log(String(msg));
                    globalThis.forge = Object.freeze({
                        __setResult: setResult,
                        log: log,
                    });
                    delete globalThis.Deno;

                    // Remove code generation primitives to prevent prototype chain attacks.
                    // Even with the validator banning eval( and Function(, an attacker could
                    // reach Function via forge.log.constructor or similar prototype chain access.
                    delete globalThis.eval;
                    const AsyncFunction = (async function(){}).constructor;
                    const GeneratorFunction = (function*(){}).constructor;
                    Object.defineProperty(Function.prototype, 'constructor', {
                        value: undefined, configurable: false, writable: false
                    });
                    Object.defineProperty(AsyncFunction.prototype, 'constructor', {
                        value: undefined, configurable: false, writable: false
                    });
                    Object.defineProperty(GeneratorFunction.prototype, 'constructor', {
                        value: undefined, configurable: false, writable: false
                    });
                })(Deno.core.ops);
            "#,
        )
        .map_err(|e| SandboxError::JsError {
            message: e.to_string(),
        })?;

    run_user_code(&mut runtime, code, config).await
}

/// Run an execute operation on the current thread.
///
/// Public for reuse in the worker binary.
pub async fn run_execute(
    config: &SandboxConfig,
    code: &str,
    dispatcher: Arc<dyn ToolDispatcher>,
) -> Result<Value, SandboxError> {
    let limits = ToolCallLimits {
        max_calls: config.max_tool_calls,
        max_args_size: config.max_tool_call_args_size,
        calls_made: 0,
    };
    let mut runtime = create_runtime(Some(dispatcher), config.max_heap_size, Some(limits))?;

    // Bootstrap: capture ops in closures, create full forge API, delete Deno,
    // and remove dangerous code generation primitives.
    // User code accesses tools via forge.callTool() or forge.server("x").cat.tool().
    runtime
        .execute_script(
            "[forge:bootstrap]",
            r#"
                ((ops) => {
                    const callToolOp = ops.op_forge_call_tool;
                    const setResult = (json) => ops.op_forge_set_result(json);
                    const log = (msg) => ops.op_forge_log(String(msg));

                    const callTool = async (server, tool, args) => {
                        const resultJson = await callToolOp(
                            server, tool, JSON.stringify(args || {})
                        );
                        return JSON.parse(resultJson);
                    };

                    globalThis.forge = Object.freeze({
                        __setResult: setResult,
                        log: log,
                        callTool: callTool,
                        server: (name) => {
                            return new Proxy({}, {
                                get(_target, category) {
                                    return new Proxy({}, {
                                        get(_target2, tool) {
                                            return async (args) => {
                                                return callTool(
                                                    name,
                                                    `${category}.${tool}`,
                                                    args || {}
                                                );
                                            };
                                        }
                                    });
                                }
                            });
                        }
                    });

                    delete globalThis.Deno;

                    // Remove code generation primitives to prevent prototype chain attacks.
                    delete globalThis.eval;
                    const AsyncFunction = (async function(){}).constructor;
                    const GeneratorFunction = (function*(){}).constructor;
                    Object.defineProperty(Function.prototype, 'constructor', {
                        value: undefined, configurable: false, writable: false
                    });
                    Object.defineProperty(AsyncFunction.prototype, 'constructor', {
                        value: undefined, configurable: false, writable: false
                    });
                    Object.defineProperty(GeneratorFunction.prototype, 'constructor', {
                        value: undefined, configurable: false, writable: false
                    });
                })(Deno.core.ops);
            "#,
        )
        .map_err(|e| SandboxError::JsError {
            message: e.to_string(),
        })?;

    run_user_code(&mut runtime, code, config).await
}

/// Create a fresh JsRuntime with the forge extension loaded and V8 heap limits set.
///
/// Public for reuse in the worker binary.
pub fn create_runtime(
    dispatcher: Option<Arc<dyn ToolDispatcher>>,
    max_heap_size: usize,
    tool_call_limits: Option<ToolCallLimits>,
) -> Result<JsRuntime, SandboxError> {
    let create_params = v8::CreateParams::default().heap_limits(0, max_heap_size);

    let runtime = JsRuntime::new(RuntimeOptions {
        extensions: vec![forge_ext::init()],
        create_params: Some(create_params),
        ..Default::default()
    });

    if let Some(d) = dispatcher {
        runtime.op_state().borrow_mut().put(d);
    }
    if let Some(limits) = tool_call_limits {
        runtime.op_state().borrow_mut().put(limits);
    }

    Ok(runtime)
}

/// Wrap the user's async arrow function, execute it, and extract the result.
///
/// Sets up a CPU watchdog thread and near-heap-limit callback before running
/// user code. The watchdog terminates V8 execution if the timeout elapses
/// (handles CPU-bound infinite loops). The heap callback terminates execution
/// if V8 approaches the heap limit (prevents OOM abort).
async fn run_user_code(
    runtime: &mut JsRuntime,
    code: &str,
    config: &SandboxConfig,
) -> Result<Value, SandboxError> {
    // --- Set up heap limit callback ---
    let heap_state = Box::new(HeapLimitState {
        handle: runtime.v8_isolate().thread_safe_handle(),
        triggered: AtomicBool::new(false),
    });
    runtime.v8_isolate().add_near_heap_limit_callback(
        near_heap_limit_callback,
        &*heap_state as *const HeapLimitState as *mut std::ffi::c_void,
    );

    // --- Set up CPU watchdog ---
    let watchdog_handle = runtime.v8_isolate().thread_safe_handle();
    let timed_out = Arc::new(AtomicBool::new(false));
    let watchdog_timed_out = timed_out.clone();
    let timeout = config.timeout;
    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();

    let watchdog = std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = cancel_rx.recv_timeout(timeout) {
            watchdog_timed_out.store(true, Ordering::SeqCst);
            watchdog_handle.terminate_execution();
        }
    });

    // --- Execute user code ---
    let wrapped = format!(
        r#"
        (async () => {{
            try {{
                const __userFn = {code};
                const __result = await __userFn();
                forge.__setResult(
                    JSON.stringify({{ ok: __result }})
                );
            }} catch (e) {{
                forge.__setResult(
                    JSON.stringify({{ error: e.message || String(e) }})
                );
            }}
        }})();
        "#
    );

    let exec_error = match runtime.execute_script("[forge:execute]", wrapped) {
        Ok(_) => {
            // Drive the event loop to resolve async operations
            match tokio::time::timeout(
                config.timeout,
                runtime.run_event_loop(PollEventLoopOptions::default()),
            )
            .await
            {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(e.to_string()),
                Err(_) => Some("async timeout".to_string()),
            }
        }
        Err(e) => Some(e.to_string()),
    };

    // --- Cleanup: cancel watchdog and wait for it to exit ---
    // This ensures the watchdog thread is done before we drop the runtime,
    // preventing use-after-free on the IsolateHandle.
    let _ = cancel_tx.send(());
    let _ = watchdog.join();

    // --- Check error causes in priority order ---
    if heap_state.triggered.load(Ordering::SeqCst) {
        return Err(SandboxError::HeapLimitExceeded);
    }

    if timed_out.load(Ordering::SeqCst) {
        return Err(SandboxError::Timeout {
            timeout_ms: config.timeout.as_millis() as u64,
        });
    }

    if let Some(err_msg) = exec_error {
        return Err(SandboxError::JsError { message: err_msg });
    }

    // --- Extract result from OpState ---
    let result_str = {
        let state = runtime.op_state();
        let state = state.borrow();
        state
            .try_borrow::<ExecutionResult>()
            .map(|r| r.0.clone())
            .ok_or_else(|| SandboxError::JsError {
                message: "no result returned from sandbox execution".into(),
            })?
    };

    if result_str.len() > config.max_output_size {
        return Err(SandboxError::OutputTooLarge {
            max: config.max_output_size,
        });
    }

    let envelope: Value = serde_json::from_str(&result_str)?;

    if let Some(error) = envelope.get("error") {
        return Err(SandboxError::JsError {
            message: error.as_str().unwrap_or("unknown error").to_string(),
        });
    }

    Ok(envelope.get("ok").cloned().unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executor() -> SandboxExecutor {
        SandboxExecutor::new(SandboxConfig::default())
    }

    /// Test dispatcher that echoes back the server/tool/args.
    struct TestDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for TestDispatcher {
        async fn call_tool(
            &self,
            server: &str,
            tool: &str,
            args: serde_json::Value,
        ) -> Result<serde_json::Value, anyhow::Error> {
            Ok(serde_json::json!({
                "server": server,
                "tool": tool,
                "args": args,
                "status": "ok"
            }))
        }
    }

    #[tokio::test]
    async fn search_returns_manifest_data() {
        let exec = executor();
        let manifest = serde_json::json!({
            "tools": [
                {"name": "parse_ast", "category": "ast"},
                {"name": "find_symbols", "category": "symbols"},
            ]
        });

        let code = r#"async () => {
            return manifest.tools.filter(t => t.category === "ast");
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        let tools = result.as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "parse_ast");
    }

    #[tokio::test]
    async fn search_handles_complex_queries() {
        let exec = executor();
        let manifest = serde_json::json!({
            "servers": [
                {
                    "name": "narsil",
                    "categories": {
                        "ast": { "tools": ["parse", "query", "walk"] },
                        "symbols": { "tools": ["find", "references"] }
                    }
                }
            ]
        });

        let code = r#"async () => {
            return manifest.servers
                .map(s => ({ name: s.name, categories: Object.keys(s.categories) }));
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        let servers = result.as_array().unwrap();
        assert_eq!(servers[0]["name"], "narsil");
    }

    #[tokio::test]
    async fn timeout_is_enforced() {
        let exec = SandboxExecutor::new(SandboxConfig {
            timeout: Duration::from_millis(200),
            ..Default::default()
        });
        let manifest = serde_json::json!({});

        // A never-resolving promise should trigger a timeout
        let code = r#"async () => {
            await new Promise(() => {});
        }"#;

        let start = std::time::Instant::now();
        let err = exec.execute_search(code, &manifest).await.unwrap_err();
        let elapsed = start.elapsed();

        // Should be a timeout or a "no result" error (the event loop completes
        // when there are no more pending ops, even if the promise is unresolved)
        match &err {
            SandboxError::Timeout { .. } => {}
            SandboxError::JsError { message } if message.contains("no result") => {
                // deno_core's event loop exits when there are no pending ops,
                // so the never-resolving promise doesn't actually block
            }
            other => panic!("unexpected error: {other:?}, elapsed: {elapsed:?}"),
        }
    }

    #[tokio::test]
    async fn js_errors_are_captured() {
        let exec = executor();
        let manifest = serde_json::json!({});

        let code = r#"async () => {
            throw new Error("intentional test error");
        }"#;

        let err = exec.execute_search(code, &manifest).await.unwrap_err();
        assert!(matches!(err, SandboxError::JsError { .. }));
        let msg = err.to_string();
        assert!(msg.contains("intentional test error"));
    }

    #[tokio::test]
    async fn no_filesystem_access() {
        let exec = executor();
        let manifest = serde_json::json!({});

        // require() is a banned pattern — caught by validator
        let code = r#"async () => {
            const fs = require("fs");
            return "ESCAPED";
        }"#;

        let err = exec.execute_search(code, &manifest).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn no_network_access() {
        let exec = executor();
        let manifest = serde_json::json!({});

        let code = r#"async () => {
            try {
                await fetch("https://example.com");
                return "ESCAPED";
            } catch(e) {
                return "CONTAINED";
            }
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(result, "CONTAINED");
    }

    // --- WU4 new tests ---

    #[tokio::test]
    async fn cpu_bound_infinite_loop_is_terminated() {
        let exec = SandboxExecutor::new(SandboxConfig {
            timeout: Duration::from_millis(500),
            ..Default::default()
        });
        let manifest = serde_json::json!({});

        let code = r#"async () => {
            while(true) {}
        }"#;

        let start = std::time::Instant::now();
        let err = exec.execute_search(code, &manifest).await.unwrap_err();
        let elapsed = start.elapsed();

        assert!(
            matches!(err, SandboxError::Timeout { .. }),
            "expected timeout, got: {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "should complete reasonably fast, took: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn heap_limit_prevents_oom() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_heap_size: 10 * 1024 * 1024,  // 10 MB
            timeout: Duration::from_secs(30), // Long timeout so heap fills first
            ..Default::default()
        });
        let manifest = serde_json::json!({});

        // Rapidly allocate memory to exceed the heap limit
        let code = r#"async () => {
            const arr = [];
            while(true) {
                arr.push(new Array(100000).fill("x"));
            }
        }"#;

        let err = exec.execute_search(code, &manifest).await.unwrap_err();
        assert!(
            matches!(
                err,
                SandboxError::HeapLimitExceeded | SandboxError::JsError { .. }
            ),
            "expected heap limit or JS error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn concurrency_limit_enforced() {
        // Use max_concurrent=0 so no executions are allowed (deterministic test)
        let exec = SandboxExecutor::new(SandboxConfig {
            max_concurrent: 0,
            ..Default::default()
        });

        let code = r#"async () => { return 1; }"#;
        let err = exec
            .execute_search(code, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::ConcurrencyLimit { max: 0 }),
            "expected concurrency limit, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn deno_global_is_not_accessible() {
        let exec = executor();
        let manifest = serde_json::json!({});

        let code = r#"async () => {
            const props = Object.getOwnPropertyNames(globalThis);
            return !props.includes("Deno");
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn forge_object_is_frozen() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            return Object.isFrozen(forge);
        }"#;

        let result = exec.execute_code(code, dispatcher).await.unwrap();
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn tool_call_rate_limit() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_tool_calls: 2,
            ..Default::default()
        });
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            await forge.callTool("test", "tool1", {});
            await forge.callTool("test", "tool2", {});
            try {
                await forge.callTool("test", "tool3", {});
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;

        let result = exec.execute_code(code, dispatcher).await.unwrap();
        assert!(
            result
                .as_str()
                .unwrap()
                .contains("tool call limit exceeded"),
            "expected tool call limit message, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn tool_call_args_size_limit() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_tool_call_args_size: 100,
            ..Default::default()
        });
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            try {
                await forge.callTool("test", "tool", { data: "x".repeat(200) });
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;

        let result = exec.execute_code(code, dispatcher).await.unwrap();
        assert!(
            result.as_str().unwrap().contains("too large"),
            "expected args too large message, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn forge_log_works() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            forge.log("test message from sandbox");
            return "ok";
        }"#;

        let result = exec.execute_code(code, dispatcher).await.unwrap();
        assert_eq!(result, "ok");
    }

    #[tokio::test]
    async fn forge_server_proxy_calls_tool() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            const result = await forge.server("narsil").ast.parse({ file: "test.rs" });
            return result;
        }"#;

        let result = exec.execute_code(code, dispatcher).await.unwrap();
        assert_eq!(result["server"], "narsil");
        assert_eq!(result["tool"], "ast.parse");
        assert_eq!(result["status"], "ok");
    }

    #[tokio::test]
    async fn multiple_tool_calls_in_single_execution() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            const r1 = await forge.callTool("server1", "tool1", {});
            const r2 = await forge.callTool("server2", "tool2", {});
            return [r1, r2];
        }"#;

        let result = exec.execute_code(code, dispatcher).await.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["server"], "server1");
        assert_eq!(arr[1]["server"], "server2");
    }

    #[tokio::test]
    async fn eval_is_not_accessible() {
        let exec = executor();
        let manifest = serde_json::json!({});

        let code = r#"async () => {
            return typeof globalThis.eval;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(result, "undefined");
    }

    #[tokio::test]
    async fn function_constructor_is_blocked() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Try to access Function via prototype chain — should get undefined
        let code = r#"async () => {
            const ctor = forge.log.constructor;
            return String(ctor);
        }"#;

        let result = exec.execute_code(code, dispatcher).await.unwrap();
        assert_eq!(result, "undefined");
    }

    #[tokio::test]
    async fn async_function_constructor_is_blocked() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Try to access AsyncFunction via prototype chain
        let code = r#"async () => {
            const fn1 = async () => {};
            const ctor = fn1.constructor;
            return String(ctor);
        }"#;

        let result = exec.execute_code(code, dispatcher).await.unwrap();
        assert_eq!(result, "undefined");
    }

    #[tokio::test]
    async fn large_output_is_rejected() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_output_size: 100,
            ..Default::default()
        });
        let manifest = serde_json::json!({});

        let code = r#"async () => {
            return "x".repeat(1000);
        }"#;

        let err = exec.execute_search(code, &manifest).await.unwrap_err();
        assert!(
            matches!(err, SandboxError::OutputTooLarge { .. }),
            "expected output too large, got: {err:?}"
        );
    }
}
