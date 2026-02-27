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
    AuditEntryBuilder, AuditLogger, AuditOperation, AuditingDispatcher, AuditingResourceDispatcher,
    AuditingStashDispatcher, NoopAuditLogger, ResourceReadAudit, StashOperationAudit,
    ToolCallAudit,
};
use crate::error::SandboxError;
use crate::ops::{
    forge_ext, CurrentGroup, ExecutionResult, KnownServers, MaxResourceSize, ToolCallLimits,
};
use crate::validator::validate_code;
use crate::{ResourceDispatcher, StashDispatcher, ToolDispatcher};

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
    /// Maximum resource content size in bytes (default: 64 MB).
    pub max_resource_size: usize,
    /// Maximum concurrent calls in forge.parallel() (default: 8).
    pub max_parallel: usize,
    /// Maximum IPC message size in bytes (default: 8 MB).
    pub max_ipc_message_size: usize,
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
            max_resource_size: 64 * 1024 * 1024, // 64 MB
            max_parallel: 8,
            max_ipc_message_size: crate::ipc::DEFAULT_MAX_IPC_MESSAGE_SIZE,
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
    /// Resource reads go through `forge.readResource(server, uri)` which
    /// dispatches to the Rust-side ResourceDispatcher via `op_forge_read_resource`.
    ///
    /// In `ChildProcess` mode, spawns an isolated worker process. In `InProcess`
    /// mode (default), runs V8 on a dedicated thread in the current process.
    pub async fn execute_code(
        &self,
        code: &str,
        dispatcher: Arc<dyn ToolDispatcher>,
        resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
        stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
    ) -> Result<Value, SandboxError> {
        self.execute_code_with_options(
            code,
            dispatcher,
            resource_dispatcher,
            stash_dispatcher,
            None,
        )
        .await
    }

    /// Execute code with additional options (known servers for SR-R6 validation).
    pub async fn execute_code_with_options(
        &self,
        code: &str,
        dispatcher: Arc<dyn ToolDispatcher>,
        resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
        stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
        known_servers: Option<std::collections::HashSet<String>>,
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

        // Wrap resource dispatcher with audit tracking
        let (resource_audit_tx, mut resource_audit_rx) =
            tokio::sync::mpsc::unbounded_channel::<ResourceReadAudit>();
        let auditing_resource_dispatcher = resource_dispatcher.map(|rd| {
            Arc::new(AuditingResourceDispatcher::new(rd, resource_audit_tx))
                as Arc<dyn ResourceDispatcher>
        });

        // Wrap stash dispatcher with audit tracking
        let (stash_audit_tx, mut stash_audit_rx) =
            tokio::sync::mpsc::unbounded_channel::<StashOperationAudit>();
        let auditing_stash_dispatcher = stash_dispatcher.map(|sd| {
            Arc::new(AuditingStashDispatcher::new(sd, stash_audit_tx)) as Arc<dyn StashDispatcher>
        });

        let result = match self.config.execution_mode {
            ExecutionMode::ChildProcess => {
                crate::host::SandboxHost::execute_in_child(
                    code,
                    &self.config,
                    auditing_dispatcher,
                    auditing_resource_dispatcher,
                    auditing_stash_dispatcher,
                )
                .await
            }
            ExecutionMode::InProcess => {
                self.execute_code_in_process(
                    code,
                    auditing_dispatcher,
                    auditing_resource_dispatcher,
                    auditing_stash_dispatcher,
                    known_servers,
                )
                .await
            }
        };

        // Collect tool call audits
        while let Ok(tool_audit) = audit_rx.try_recv() {
            audit_builder.record_tool_call(tool_audit);
        }

        // Collect resource read audits
        while let Ok(resource_audit) = resource_audit_rx.try_recv() {
            audit_builder.record_resource_read(resource_audit);
        }

        // Collect stash operation audits
        while let Ok(stash_audit) = stash_audit_rx.try_recv() {
            audit_builder.record_stash_op(stash_audit);
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
        resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
        stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
        known_servers: Option<std::collections::HashSet<String>>,
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
            let result = rt.block_on(run_execute_with_known_servers(
                &config,
                &code,
                dispatcher,
                resource_dispatcher,
                stash_dispatcher,
                known_servers,
            ));
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
    let mut runtime = create_runtime(None, None, config.max_heap_size, None, None, None, None)?;

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
    resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
) -> Result<Value, SandboxError> {
    run_execute_with_known_servers(
        config,
        code,
        dispatcher,
        resource_dispatcher,
        stash_dispatcher,
        None,
    )
    .await
}

/// Run an execute operation with an optional set of known server names for SR-R6 validation.
pub async fn run_execute_with_known_servers(
    config: &SandboxConfig,
    code: &str,
    dispatcher: Arc<dyn ToolDispatcher>,
    resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
    known_servers: Option<std::collections::HashSet<String>>,
) -> Result<Value, SandboxError> {
    let limits = ToolCallLimits {
        max_calls: config.max_tool_calls,
        max_args_size: config.max_tool_call_args_size,
        calls_made: 0,
    };
    let mut runtime = create_runtime(
        Some(dispatcher),
        resource_dispatcher.clone(),
        config.max_heap_size,
        Some(limits),
        Some(config.max_resource_size),
        stash_dispatcher.clone(),
        known_servers,
    )?;

    // Determine which capabilities are available
    let has_resource_dispatcher = resource_dispatcher.is_some();
    let has_stash_dispatcher = stash_dispatcher.is_some();

    // Bootstrap: capture ops in closures, create full forge API, delete Deno,
    // and remove dangerous code generation primitives.
    // User code accesses tools via forge.callTool() or forge.server("x").cat.tool().
    // Conditionally includes readResource and stash based on available dispatchers.
    let bootstrap = build_execute_bootstrap(
        has_resource_dispatcher,
        has_stash_dispatcher,
        config.max_parallel,
    );

    runtime
        .execute_script("[forge:bootstrap]", bootstrap)
        .map_err(|e| SandboxError::JsError {
            message: e.to_string(),
        })?;

    run_user_code(&mut runtime, code, config).await
}

/// Build the bootstrap JavaScript for execute mode.
///
/// Conditionally includes `readResource` and `stash` APIs based on which
/// dispatchers are available.
fn build_execute_bootstrap(has_resource: bool, has_stash: bool, max_parallel: usize) -> String {
    let mut parts = Vec::new();

    // Always available ops + frozen concurrency cap
    parts.push(format!(
        r#"((ops) => {{
                    const callToolOp = ops.op_forge_call_tool;
                    const setResult = (json) => ops.op_forge_set_result(json);
                    const log = (msg) => ops.op_forge_log(String(msg));
                    const __MAX_PARALLEL = Object.freeze({max_parallel});

                    const callTool = async (server, tool, args) => {{
                        const resultJson = await callToolOp(
                            server, tool, JSON.stringify(args || {{}})
                        );
                        return JSON.parse(resultJson);
                    }};"#
    ));

    // readResource binding (conditional)
    if has_resource {
        parts.push(
            r#"
                    const readResourceOp = ops.op_forge_read_resource;
                    const readResource = async (server, uri) => {
                        const resultJson = await readResourceOp(server, uri);
                        return JSON.parse(resultJson);
                    };"#
            .to_string(),
        );
    }

    // stash bindings (conditional)
    if has_stash {
        parts.push(
            r#"
                    const stashPutOp = ops.op_forge_stash_put;
                    const stashGetOp = ops.op_forge_stash_get;
                    const stashDeleteOp = ops.op_forge_stash_delete;
                    const stashKeysOp = ops.op_forge_stash_keys;"#
                .to_string(),
        );
    }

    // Build the forge object properties
    let mut forge_props = vec![
        "                        __setResult: setResult".to_string(),
        "                        log: log".to_string(),
        "                        callTool: callTool".to_string(),
    ];

    if has_resource {
        forge_props.push("                        readResource: readResource".to_string());
    }

    if has_stash {
        forge_props.push(
            r#"                        stash: Object.freeze({
                            put: async (key, value, opts) => {
                                const ttl = (opts && opts.ttl) ? opts.ttl : 0;
                                const resultJson = await stashPutOp(key, JSON.stringify(value), ttl);
                                return JSON.parse(resultJson);
                            },
                            get: async (key) => {
                                const resultJson = await stashGetOp(key);
                                return JSON.parse(resultJson);
                            },
                            delete: async (key) => {
                                const resultJson = await stashDeleteOp(key);
                                return JSON.parse(resultJson);
                            },
                            keys: async () => {
                                const resultJson = await stashKeysOp();
                                return JSON.parse(resultJson);
                            }
                        })"#
            .to_string(),
        );
    }

    // server proxy is always included
    forge_props.push(
        r#"                        server: (name) => {
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
                        }"#
        .to_string(),
    );

    // forge.parallel() — bounded concurrency wrapper over callTool/readResource
    forge_props.push(
        r#"                        parallel: async (calls, opts) => {
                            opts = opts || {};
                            const concurrency = Math.min(
                                opts.concurrency || __MAX_PARALLEL,
                                __MAX_PARALLEL
                            );
                            const failFast = opts.failFast || false;
                            const results = new Array(calls.length).fill(null);
                            const errors = [];
                            let aborted = false;

                            for (let i = 0; i < calls.length && !aborted; i += concurrency) {
                                const batch = calls.slice(i, i + concurrency);
                                await Promise.allSettled(
                                    batch.map((fn, idx) => fn().then(
                                        val => { results[i + idx] = val; },
                                        err => {
                                            errors.push({ index: i + idx, error: err.message || String(err) });
                                            if (failFast) aborted = true;
                                        }
                                    ))
                                );
                            }

                            return { results, errors, aborted };
                        }"#
        .to_string(),
    );

    let forge_obj = format!(
        r#"
                    globalThis.forge = Object.freeze({{
{}
                    }});"#,
        forge_props.join(",\n")
    );
    parts.push(forge_obj);

    // Security: remove dangerous globals
    parts.push(
        r#"
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
                })(Deno.core.ops);"#
            .to_string(),
    );

    parts.join("\n")
}

/// Create a fresh JsRuntime with the forge extension loaded and V8 heap limits set.
pub(crate) fn create_runtime(
    dispatcher: Option<Arc<dyn ToolDispatcher>>,
    resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    max_heap_size: usize,
    tool_call_limits: Option<ToolCallLimits>,
    max_resource_size: Option<usize>,
    stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
    known_servers: Option<std::collections::HashSet<String>>,
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
    if let Some(rd) = resource_dispatcher {
        runtime.op_state().borrow_mut().put(rd);
    }
    if let Some(limits) = tool_call_limits {
        runtime.op_state().borrow_mut().put(limits);
    }
    if let Some(size) = max_resource_size {
        runtime.op_state().borrow_mut().put(MaxResourceSize(size));
    }
    if let Some(sd) = stash_dispatcher {
        runtime.op_state().borrow_mut().put(sd);
        // CurrentGroup defaults to None; the ForgeServer level sets the actual group
        runtime.op_state().borrow_mut().put(CurrentGroup(None));
    }
    if let Some(servers) = known_servers {
        runtime.op_state().borrow_mut().put(KnownServers(servers));
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

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
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

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
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

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
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

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
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

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
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

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
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

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
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

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(result, "undefined");
    }

    // --- v0.2 Resource read test dispatchers ---

    /// Resource dispatcher that echoes back server/uri.
    struct TestResourceDispatcher;

    #[async_trait::async_trait]
    impl ResourceDispatcher for TestResourceDispatcher {
        async fn read_resource(
            &self,
            server: &str,
            uri: &str,
        ) -> Result<serde_json::Value, anyhow::Error> {
            Ok(serde_json::json!({
                "server": server,
                "uri": uri,
                "content": "test resource content"
            }))
        }
    }

    /// Resource dispatcher that returns a large payload.
    struct LargeResourceDispatcher {
        content_size: usize,
    }

    #[async_trait::async_trait]
    impl ResourceDispatcher for LargeResourceDispatcher {
        async fn read_resource(
            &self,
            _server: &str,
            _uri: &str,
        ) -> Result<serde_json::Value, anyhow::Error> {
            Ok(serde_json::json!({
                "data": "x".repeat(self.content_size)
            }))
        }
    }

    /// Resource dispatcher that always fails with a configurable error.
    struct FailingResourceDispatcher {
        error_msg: String,
    }

    #[async_trait::async_trait]
    impl ResourceDispatcher for FailingResourceDispatcher {
        async fn read_resource(
            &self,
            _server: &str,
            _uri: &str,
        ) -> Result<serde_json::Value, anyhow::Error> {
            Err(anyhow::anyhow!("{}", self.error_msg))
        }
    }

    // --- RS-U01: readResource routes to correct server ---
    #[tokio::test]
    async fn rs_u01_read_resource_routes_to_correct_server() {
        let exec = executor();
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(TestResourceDispatcher));

        let code = r#"async () => {
            const result = await forge.readResource("my-server", "file:///logs/app.log");
            return result;
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        assert_eq!(result["server"], "my-server");
        assert_eq!(result["uri"], "file:///logs/app.log");
        assert_eq!(result["content"], "test resource content");
    }

    // --- RS-U02: readResource increments ToolCallLimits.calls_made ---
    #[tokio::test]
    async fn rs_u02_read_resource_shares_rate_limit_with_tool_calls() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_tool_calls: 3,
            ..Default::default()
        });
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(TestResourceDispatcher));

        // 1 tool call + 2 resource reads = 3 (limit), then 4th fails
        let code = r#"async () => {
            await forge.callTool("s", "t", {});
            await forge.readResource("s", "file:///a");
            await forge.readResource("s", "file:///b");
            try {
                await forge.readResource("s", "file:///c");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        assert!(
            result
                .as_str()
                .unwrap()
                .contains("tool call limit exceeded"),
            "expected rate limit message, got: {result:?}"
        );
    }

    // --- RS-U03: readResource rejects when limits exhausted ---
    #[tokio::test]
    async fn rs_u03_read_resource_rejects_when_limits_exhausted() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_tool_calls: 1,
            ..Default::default()
        });
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(TestResourceDispatcher));

        let code = r#"async () => {
            await forge.readResource("s", "file:///a");
            try {
                await forge.readResource("s", "file:///b");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        assert!(
            result
                .as_str()
                .unwrap()
                .contains("tool call limit exceeded"),
            "expected rate limit error, got: {result:?}"
        );
    }

    // --- RS-U08: truncates response at max_resource_size ---
    #[tokio::test]
    async fn rs_u08_read_resource_truncates_at_max_resource_size() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_resource_size: 100, // very small limit
            ..Default::default()
        });
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(LargeResourceDispatcher { content_size: 500 }));

        // Large resource truncated → JSON.parse fails in bootstrap
        let code = r#"async () => {
            try {
                await forge.readResource("s", "file:///big");
                return "no truncation";
            } catch(e) {
                return "truncated";
            }
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        assert_eq!(result, "truncated", "large resource should be truncated");
    }

    // --- RS-U09: errors redacted through redact_error_for_llm ---
    #[tokio::test]
    async fn rs_u09_read_resource_redacts_errors() {
        let exec = executor();
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(FailingResourceDispatcher {
                error_msg: "connection refused: http://internal.corp:9876/secret/path".into(),
            }));

        let code = r#"async () => {
            try {
                await forge.readResource("my-server", "file:///logs/secret.log");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        let msg = result.as_str().unwrap();
        assert!(
            !msg.contains("internal.corp"),
            "should not leak internal URL: {msg}"
        );
        assert!(!msg.contains("9876"), "should not leak port: {msg}");
        assert!(
            msg.contains("my-server"),
            "should mention server name: {msg}"
        );
    }

    // --- RS-U10: binary content (base64 encoding) ---
    #[tokio::test]
    async fn rs_u10_read_resource_handles_binary_content() {
        struct Base64ResourceDispatcher;

        #[async_trait::async_trait]
        impl ResourceDispatcher for Base64ResourceDispatcher {
            async fn read_resource(
                &self,
                _server: &str,
                _uri: &str,
            ) -> Result<serde_json::Value, anyhow::Error> {
                Ok(serde_json::json!({
                    "content": "SGVsbG8gV29ybGQ=",
                    "_encoding": "base64"
                }))
            }
        }

        let exec = executor();
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(Base64ResourceDispatcher));

        let code = r#"async () => {
            const result = await forge.readResource("s", "file:///binary");
            return result;
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        assert_eq!(result["_encoding"], "base64");
        assert_eq!(result["content"], "SGVsbG8gV29ybGQ=");
    }

    // --- RS-U11: error for nonexistent resource ---
    #[tokio::test]
    async fn rs_u11_read_resource_error_for_nonexistent() {
        let exec = executor();
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(FailingResourceDispatcher {
                error_msg: "resource not found".into(),
            }));

        let code = r#"async () => {
            try {
                await forge.readResource("s", "file:///nonexistent");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        let msg = result.as_str().unwrap();
        assert!(
            msg.contains("failed"),
            "should indicate failure: {result:?}"
        );
    }

    // --- RS-U12: handles large (>1MB) content ---
    #[tokio::test]
    async fn rs_u12_read_resource_handles_large_content() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_resource_size: 2 * 1024 * 1024, // 2 MB
            timeout: Duration::from_secs(10),
            ..Default::default()
        });
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(LargeResourceDispatcher {
                content_size: 1_100_000,
            }));

        let code = r#"async () => {
            const result = await forge.readResource("s", "file:///large");
            return result.data.length;
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        assert_eq!(result, 1_100_000);
    }

    // --- RS-S05: URI for non-file-server — error redacted, no path leakage ---
    #[tokio::test]
    async fn rs_s05_error_on_invalid_resource_uri_for_server() {
        let exec = executor();
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(FailingResourceDispatcher {
                error_msg: "unknown resource URI: file:///etc/shadow".into(),
            }));

        let code = r#"async () => {
            try {
                await forge.readResource("postgres-server", "file:///etc/shadow");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        let msg = result.as_str().unwrap();
        // SR-R5: Error should use "readResource" not the raw URI
        assert!(
            !msg.contains("/etc/shadow"),
            "should not leak file path: {msg}"
        );
        // Should still mention server for context
        assert!(
            msg.contains("postgres-server"),
            "should mention server: {msg}"
        );
        assert!(
            msg.contains("readResource"),
            "should use safe identifier: {msg}"
        );
    }

    // --- RS-S06: error message does not leak full URI path ---
    #[tokio::test]
    async fn rs_s06_error_message_does_not_leak_full_uri() {
        let exec = executor();
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(FailingResourceDispatcher {
                error_msg: "file not found: /var/secrets/database/credentials.json".into(),
            }));

        let code = r#"async () => {
            try {
                await forge.readResource("server", "file:///var/secrets/database/credentials.json");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        let msg = result.as_str().unwrap();
        // Paths are redacted by redact_error_message
        assert!(!msg.contains("/var/secrets"), "should not leak path: {msg}");
        assert!(
            !msg.contains("credentials.json"),
            "should not leak filename: {msg}"
        );
        // URI itself should not appear in error (SR-R5)
        assert!(
            !msg.contains("file:///var/secrets"),
            "should not leak URI: {msg}"
        );
    }

    // --- RS-S07: large content truncated, not OOM ---
    #[tokio::test]
    async fn rs_s07_large_content_truncated_not_oom() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_resource_size: 1024, // 1 KB limit
            timeout: Duration::from_secs(10),
            ..Default::default()
        });
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(LargeResourceDispatcher {
                content_size: 1_000_000, // 1 MB, far exceeds 1 KB limit
            }));

        let code = r#"async () => {
            try {
                const result = await forge.readResource("s", "file:///huge");
                return "got result without truncation";
            } catch(e) {
                return "safely truncated";
            }
        }"#;

        // Must complete without OOM
        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await;
        assert!(result.is_ok(), "should complete without OOM: {result:?}");
        assert_eq!(result.unwrap(), "safely truncated");
    }

    // --- RS-S08: many resource reads hit rate limit ---
    #[tokio::test]
    async fn rs_s08_many_reads_hit_rate_limit() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_tool_calls: 5,
            ..Default::default()
        });
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(TestResourceDispatcher));

        let code = r#"async () => {
            let count = 0;
            for (let i = 0; i < 1000; i++) {
                try {
                    await forge.readResource("s", "file:///r" + i);
                    count++;
                } catch(e) {
                    return { count, error: e.message };
                }
            }
            return { count, error: null };
        }"#;

        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        assert_eq!(
            result["count"], 5,
            "should allow exactly max_tool_calls reads"
        );
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("tool call limit exceeded"));
    }

    // --- RS-S09: search mode blocks resource read ---
    #[tokio::test]
    async fn rs_s09_search_mode_blocks_resource_read() {
        let exec = executor();
        let manifest = serde_json::json!({"servers": []});

        // In search mode, forge.readResource should not exist
        let code = r#"async () => {
            return typeof forge.readResource;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(
            result, "undefined",
            "readResource should not exist in search mode"
        );
    }

    // --- SR-R6: unknown server rejected at op level ---
    #[tokio::test]
    async fn sr_r6_unknown_server_rejected_at_op_level() {
        let exec = executor();
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(TestResourceDispatcher));

        // Use execute_code_with_options to set known servers
        let mut known = std::collections::HashSet::new();
        known.insert("allowed-server".to_string());

        let code = r#"async () => {
            try {
                await forge.readResource("nonexistent_server", "file:///x");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;

        let result = exec
            .execute_code_with_options(
                code,
                tool_dispatcher,
                resource_dispatcher,
                None,
                Some(known),
            )
            .await
            .unwrap();
        let msg = result.as_str().unwrap();
        assert!(
            msg.contains("unknown server"),
            "expected 'unknown server' error, got: {msg}"
        );
        assert!(
            msg.contains("nonexistent_server"),
            "should mention the server name: {msg}"
        );
    }

    // --- RS-S10: audit log records resource reads with URI hash ---
    #[tokio::test]
    async fn rs_s10_audit_records_resource_reads_with_uri_hash() {
        struct CapturingAuditLogger {
            entries: std::sync::Mutex<Vec<crate::audit::AuditEntry>>,
        }

        #[async_trait::async_trait]
        impl crate::audit::AuditLogger for CapturingAuditLogger {
            async fn log(&self, entry: &crate::audit::AuditEntry) {
                self.entries.lock().unwrap().push(entry.clone());
            }
        }

        let logger = Arc::new(CapturingAuditLogger {
            entries: std::sync::Mutex::new(Vec::new()),
        });
        let exec = SandboxExecutor::with_audit_logger(SandboxConfig::default(), logger.clone());
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(TestResourceDispatcher));

        let code = r#"async () => {
            await forge.readResource("my-server", "file:///logs/app.log");
            return "done";
        }"#;

        let _ = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, None)
            .await
            .unwrap();

        let entries = logger.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.resource_reads.len(), 1);

        let read = &entry.resource_reads[0];
        assert_eq!(read.server, "my-server");
        assert!(read.success);
        // URI should be hashed, not raw
        assert_ne!(
            read.uri_hash, "file:///logs/app.log",
            "URI should be hashed, not stored raw"
        );
        // Verify it's a valid SHA-256 hex string
        assert_eq!(read.uri_hash.len(), 64, "should be SHA-256 hex");
        assert!(read.uri_hash.chars().all(|c| c.is_ascii_hexdigit()));
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

    // --- Stash test infrastructure ---

    /// Direct stash dispatcher wrapping an Arc<tokio::sync::Mutex<SessionStash>>.
    /// Used by integration/security tests without going through IPC.
    struct DirectStashDispatcher {
        stash: Arc<tokio::sync::Mutex<crate::stash::SessionStash>>,
        current_group: Option<String>,
    }

    #[async_trait::async_trait]
    impl crate::StashDispatcher for DirectStashDispatcher {
        async fn put(
            &self,
            key: &str,
            value: serde_json::Value,
            ttl_secs: Option<u32>,
            _current_group: Option<String>,
        ) -> Result<serde_json::Value, anyhow::Error> {
            let ttl = ttl_secs
                .filter(|&s| s > 0)
                .map(|s| std::time::Duration::from_secs(s as u64));
            let mut stash = self.stash.lock().await;
            stash.put(key, value, ttl, self.current_group.as_deref())?;
            Ok(serde_json::json!({"ok": true}))
        }

        async fn get(
            &self,
            key: &str,
            _current_group: Option<String>,
        ) -> Result<serde_json::Value, anyhow::Error> {
            let stash = self.stash.lock().await;
            match stash.get(key, self.current_group.as_deref())? {
                Some(v) => Ok(v.clone()),
                None => Ok(serde_json::Value::Null),
            }
        }

        async fn delete(
            &self,
            key: &str,
            _current_group: Option<String>,
        ) -> Result<serde_json::Value, anyhow::Error> {
            let mut stash = self.stash.lock().await;
            let deleted = stash.delete(key, self.current_group.as_deref())?;
            Ok(serde_json::json!({"deleted": deleted}))
        }

        async fn keys(
            &self,
            _current_group: Option<String>,
        ) -> Result<serde_json::Value, anyhow::Error> {
            let stash = self.stash.lock().await;
            let keys: Vec<&str> = stash.keys(self.current_group.as_deref());
            Ok(serde_json::json!(keys))
        }
    }

    fn make_stash(
        config: crate::stash::StashConfig,
    ) -> Arc<tokio::sync::Mutex<crate::stash::SessionStash>> {
        Arc::new(tokio::sync::Mutex::new(crate::stash::SessionStash::new(
            config,
        )))
    }

    fn make_stash_dispatcher(
        stash: Arc<tokio::sync::Mutex<crate::stash::SessionStash>>,
        group: Option<&str>,
    ) -> Arc<dyn crate::StashDispatcher> {
        Arc::new(DirectStashDispatcher {
            stash,
            current_group: group.map(str::to_string),
        })
    }

    // --- ST-I01: Two execute_code calls sharing stash (put in first, get in second) ---
    #[tokio::test]
    async fn st_i01_stash_shared_across_executions() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let sd = make_stash_dispatcher(stash.clone(), None);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // First execution: put a value
        let code1 = r#"async () => {
            await forge.stash.put("shared-key", { value: 42 });
            return "stored";
        }"#;
        let result1 = exec
            .execute_code(code1, dispatcher.clone(), None, Some(sd.clone()))
            .await
            .unwrap();
        assert_eq!(result1, "stored");

        // Second execution: get the value
        let sd2 = make_stash_dispatcher(stash, None);
        let code2 = r#"async () => {
            const v = await forge.stash.get("shared-key");
            return v;
        }"#;
        let result2 = exec
            .execute_code(code2, dispatcher, None, Some(sd2))
            .await
            .unwrap();
        assert_eq!(result2["value"], 42);
    }

    // --- ST-I02: Stash put + get within single execution ---
    #[tokio::test]
    async fn st_i02_stash_put_get_single_execution() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let sd = make_stash_dispatcher(stash, None);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            await forge.stash.put("key", "hello");
            const v = await forge.stash.get("key");
            return v;
        }"#;
        let result = exec
            .execute_code(code, dispatcher, None, Some(sd))
            .await
            .unwrap();
        assert_eq!(result, "hello");
    }

    // --- ST-I03: Stash group isolation (put with group A, get with group B fails) ---
    #[tokio::test]
    async fn st_i03_stash_group_isolation() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Put with group A
        let sd_a = make_stash_dispatcher(stash.clone(), Some("group-a"));
        let code1 = r#"async () => {
            await forge.stash.put("secret", "group-a-data");
            return "stored";
        }"#;
        exec.execute_code(code1, dispatcher.clone(), None, Some(sd_a))
            .await
            .unwrap();

        // Get with group B should fail
        let sd_b = make_stash_dispatcher(stash, Some("group-b"));
        let code2 = r#"async () => {
            try {
                await forge.stash.get("secret");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;
        let result = exec
            .execute_code(code2, dispatcher, None, Some(sd_b))
            .await
            .unwrap();
        assert!(
            result.as_str().unwrap().contains("cross-group"),
            "expected cross-group error, got: {result:?}"
        );
    }

    // --- ST-I05: Stash combined with callTool + readResource ---
    #[tokio::test]
    async fn st_i05_stash_combined_with_tool_and_resource() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let sd = make_stash_dispatcher(stash, None);
        let tool_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(TestResourceDispatcher));

        let code = r#"async () => {
            // Call a tool
            const toolResult = await forge.callTool("s", "t", {});

            // Read a resource
            const resource = await forge.readResource("s", "file:///data");

            // Store combined result in stash
            await forge.stash.put("combined", {
                tool: toolResult.server,
                resource: resource.content
            });

            // Read it back
            const v = await forge.stash.get("combined");
            return v;
        }"#;
        let result = exec
            .execute_code(code, tool_dispatcher, resource_dispatcher, Some(sd))
            .await
            .unwrap();
        assert_eq!(result["tool"], "s");
        assert_eq!(result["resource"], "test resource content");
    }

    // --- ST-I06: Stash key limit produces clear error ---
    #[tokio::test]
    async fn st_i06_stash_key_limit_error() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig {
            max_keys: 2,
            ..Default::default()
        });
        let sd = make_stash_dispatcher(stash, None);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            await forge.stash.put("k1", 1);
            await forge.stash.put("k2", 2);
            try {
                await forge.stash.put("k3", 3);
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;
        let result = exec
            .execute_code(code, dispatcher, None, Some(sd))
            .await
            .unwrap();
        assert!(
            result.as_str().unwrap().contains("key limit"),
            "expected key limit error, got: {result:?}"
        );
    }

    // --- ST-I07: Stash value size limit produces clear error ---
    #[tokio::test]
    async fn st_i07_stash_value_size_limit_error() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig {
            max_value_size: 50,
            ..Default::default()
        });
        let sd = make_stash_dispatcher(stash, None);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            try {
                await forge.stash.put("k", "x".repeat(100));
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;
        let result = exec
            .execute_code(code, dispatcher, None, Some(sd))
            .await
            .unwrap();
        assert!(
            result.as_str().unwrap().contains("too large"),
            "expected value too large error, got: {result:?}"
        );
    }

    // --- ST-I08: Stash keys() returns correct subset for group context ---
    #[tokio::test]
    async fn st_i08_stash_keys_group_subset() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Put a public key and a group-A key
        let sd_none = make_stash_dispatcher(stash.clone(), None);
        let code1 = r#"async () => {
            await forge.stash.put("public-key", "pub");
            return "ok";
        }"#;
        exec.execute_code(code1, dispatcher.clone(), None, Some(sd_none))
            .await
            .unwrap();

        let sd_a = make_stash_dispatcher(stash.clone(), Some("group-a"));
        let code2 = r#"async () => {
            await forge.stash.put("group-a-key", "secret");
            return "ok";
        }"#;
        exec.execute_code(code2, dispatcher.clone(), None, Some(sd_a))
            .await
            .unwrap();

        // List keys from group-a perspective: should see both
        let sd_a2 = make_stash_dispatcher(stash.clone(), Some("group-a"));
        let code3 = r#"async () => {
            const k = await forge.stash.keys();
            k.sort();
            return k;
        }"#;
        let result = exec
            .execute_code(code3, dispatcher.clone(), None, Some(sd_a2))
            .await
            .unwrap();
        let keys = result.as_array().unwrap();
        assert_eq!(keys.len(), 2);

        // List keys from ungrouped: should only see public
        let sd_none2 = make_stash_dispatcher(stash, None);
        let code4 = r#"async () => {
            const k = await forge.stash.keys();
            return k;
        }"#;
        let result2 = exec
            .execute_code(code4, dispatcher, None, Some(sd_none2))
            .await
            .unwrap();
        let keys2 = result2.as_array().unwrap();
        assert_eq!(keys2.len(), 1);
        assert_eq!(keys2[0], "public-key");
    }

    // --- Security Tests ---

    // --- ST-S01: Stash key with path traversal characters rejected ---
    #[tokio::test]
    async fn st_s01_stash_key_path_traversal_rejected() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let sd = make_stash_dispatcher(stash, None);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            try {
                await forge.stash.put("../../etc/passwd", "evil");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;
        let result = exec
            .execute_code(code, dispatcher, None, Some(sd))
            .await
            .unwrap();
        assert!(
            result.as_str().unwrap().contains("invalid"),
            "expected invalid key error, got: {result:?}"
        );
    }

    // --- ST-S02: Stash key with script injection (<script>) rejected ---
    #[tokio::test]
    async fn st_s02_stash_key_script_injection_rejected() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let sd = make_stash_dispatcher(stash, None);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            try {
                await forge.stash.put("<script>alert(1)</script>", "evil");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;
        let result = exec
            .execute_code(code, dispatcher, None, Some(sd))
            .await
            .unwrap();
        assert!(
            result.as_str().unwrap().contains("invalid"),
            "expected invalid key error, got: {result:?}"
        );
    }

    // --- ST-S03: Stash value containing JS code stored as inert data ---
    #[tokio::test]
    async fn st_s03_stash_value_js_code_is_inert() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let sd = make_stash_dispatcher(stash, None);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Store a string that looks like executable JS code.
        // We build it from parts to avoid triggering the banned-pattern validator.
        let code = r#"async () => {
            const part1 = "function() { return ";
            const part2 = "globalThis.secret; }";
            const malicious = part1 + part2;
            await forge.stash.put("code-value", malicious);
            const v = await forge.stash.get("code-value");
            // The value should be a plain string, not executed
            return typeof v === "string" && v.includes("globalThis");
        }"#;
        let result = exec
            .execute_code(code, dispatcher, None, Some(sd))
            .await
            .unwrap();
        assert_eq!(result, true, "JS code in stash values should be inert data");
    }

    // --- ST-S04: Stash put from group A, get from group B → error ---
    #[tokio::test]
    async fn st_s04_stash_cross_group_get_error() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Put with group A
        let sd_a = make_stash_dispatcher(stash.clone(), Some("team-alpha"));
        let code1 = r#"async () => {
            await forge.stash.put("alpha-secret", "classified");
            return "stored";
        }"#;
        exec.execute_code(code1, dispatcher.clone(), None, Some(sd_a))
            .await
            .unwrap();

        // Get with group B should error
        let sd_b = make_stash_dispatcher(stash, Some("team-beta"));
        let code2 = r#"async () => {
            try {
                await forge.stash.get("alpha-secret");
                return "leaked";
            } catch(e) {
                return e.message;
            }
        }"#;
        let result = exec
            .execute_code(code2, dispatcher, None, Some(sd_b))
            .await
            .unwrap();
        assert!(
            result.as_str().unwrap().contains("cross-group"),
            "expected cross-group error, got: {result:?}"
        );
    }

    // --- ST-S05: Stash put from group A, get from ungrouped → error ---
    #[tokio::test]
    async fn st_s05_stash_grouped_entry_inaccessible_to_ungrouped() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Put with group A
        let sd_a = make_stash_dispatcher(stash.clone(), Some("group-x"));
        let code1 = r#"async () => {
            await forge.stash.put("gx-data", 999);
            return "stored";
        }"#;
        exec.execute_code(code1, dispatcher.clone(), None, Some(sd_a))
            .await
            .unwrap();

        // Get from ungrouped should error
        let sd_none = make_stash_dispatcher(stash, None);
        let code2 = r#"async () => {
            try {
                await forge.stash.get("gx-data");
                return "leaked";
            } catch(e) {
                return e.message;
            }
        }"#;
        let result = exec
            .execute_code(code2, dispatcher, None, Some(sd_none))
            .await
            .unwrap();
        assert!(
            result.as_str().unwrap().contains("cross-group"),
            "expected cross-group error, got: {result:?}"
        );
    }

    // --- ST-S06: Stash total size limit prevents OOM (many puts) ---
    #[tokio::test]
    async fn st_s06_stash_total_size_limit_prevents_oom() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig {
            max_total_size: 200,
            max_value_size: 1024,
            max_keys: 1000,
            ..Default::default()
        });
        let sd = make_stash_dispatcher(stash, None);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            let count = 0;
            for (let i = 0; i < 100; i++) {
                try {
                    await forge.stash.put("k" + i, "x".repeat(50));
                    count++;
                } catch(e) {
                    return { count, error: e.message };
                }
            }
            return { count, error: null };
        }"#;
        let result = exec
            .execute_code(code, dispatcher, None, Some(sd))
            .await
            .unwrap();
        // Should have been stopped before 100 puts due to total_size=200
        let count = result["count"].as_i64().unwrap();
        assert!(
            count < 100,
            "total size limit should prevent all 100 puts, but {count} succeeded"
        );
        assert!(
            result["error"].as_str().unwrap().contains("total size"),
            "expected total size error, got: {:?}",
            result["error"]
        );
    }

    // --- ST-S07: Stash ops in search() mode blocked ---
    #[tokio::test]
    async fn st_s07_stash_ops_blocked_in_search_mode() {
        let exec = executor();
        let manifest = serde_json::json!({"servers": []});

        // In search mode, forge.stash should not exist
        let code = r#"async () => {
            return typeof forge.stash;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(result, "undefined", "stash should not exist in search mode");
    }

    // --- ST-S09: Error messages from stash ops don't leak other keys/values ---
    #[tokio::test]
    async fn st_s09_stash_error_messages_dont_leak_data() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Put a secret value with group-a
        let sd_a = make_stash_dispatcher(stash.clone(), Some("group-a"));
        let code1 = r#"async () => {
            await forge.stash.put("secret-key", "top-secret-value-12345");
            return "stored";
        }"#;
        exec.execute_code(code1, dispatcher.clone(), None, Some(sd_a))
            .await
            .unwrap();

        // Try to access from group-b — error should not contain the value
        let sd_b = make_stash_dispatcher(stash, Some("group-b"));
        let code2 = r#"async () => {
            try {
                await forge.stash.get("secret-key");
                return "should not reach here";
            } catch(e) {
                return e.message;
            }
        }"#;
        let result = exec
            .execute_code(code2, dispatcher, None, Some(sd_b))
            .await
            .unwrap();
        let msg = result.as_str().unwrap();
        assert!(
            !msg.contains("top-secret-value-12345"),
            "error should not leak value: {msg}"
        );
        assert!(
            !msg.contains("secret-key"),
            "error should not leak key names: {msg}"
        );
    }

    // --- ST-S10: TTL expiry enforced ---
    #[tokio::test]
    async fn st_s10_stash_ttl_expiry_enforced() {
        let exec = executor();
        let stash = make_stash(crate::stash::StashConfig::default());
        let sd = make_stash_dispatcher(stash.clone(), None);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Put with 1-second TTL
        let code1 = r#"async () => {
            await forge.stash.put("ttl-key", "ephemeral", {ttl: 1});
            const v = await forge.stash.get("ttl-key");
            return v;
        }"#;
        let result1 = exec
            .execute_code(code1, dispatcher.clone(), None, Some(sd))
            .await
            .unwrap();
        assert_eq!(result1, "ephemeral", "should be readable immediately");

        // Wait for TTL to expire
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        // Get after expiry should return null
        let sd2 = make_stash_dispatcher(stash, None);
        let code2 = r#"async () => {
            const v = await forge.stash.get("ttl-key");
            return v;
        }"#;
        let result2 = exec
            .execute_code(code2, dispatcher, None, Some(sd2))
            .await
            .unwrap();
        assert_eq!(
            result2,
            serde_json::Value::Null,
            "expired key should return null"
        );
    }

    // =========================================================================
    // Phase 7: forge.parallel() tests (PL-U01..PL-U09, PL-S01..PL-S05)
    // =========================================================================

    // --- PL-U01: parallel with 3 successful calls returns all results ---
    #[tokio::test]
    async fn pl_u01_parallel_three_successful_calls() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            const result = await forge.parallel([
                () => forge.callTool("s1", "t1", { id: 1 }),
                () => forge.callTool("s2", "t2", { id: 2 }),
                () => forge.callTool("s3", "t3", { id: 3 }),
            ]);
            return result;
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        let results = result["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["server"], "s1");
        assert_eq!(results[1]["server"], "s2");
        assert_eq!(results[2]["server"], "s3");
        assert_eq!(result["errors"].as_array().unwrap().len(), 0);
        assert_eq!(result["aborted"], false);
    }

    // --- PL-U02: parallel with 1 failure returns partial results + error ---
    #[tokio::test]
    async fn pl_u02_parallel_partial_failure() {
        struct PartialFailDispatcher;

        #[async_trait::async_trait]
        impl ToolDispatcher for PartialFailDispatcher {
            async fn call_tool(
                &self,
                _server: &str,
                tool: &str,
                _args: serde_json::Value,
            ) -> Result<serde_json::Value, anyhow::Error> {
                if tool == "fail" {
                    Err(anyhow::anyhow!("deliberate failure"))
                } else {
                    Ok(serde_json::json!({"tool": tool, "ok": true}))
                }
            }
        }

        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(PartialFailDispatcher);

        let code = r#"async () => {
            return await forge.parallel([
                () => forge.callTool("s", "ok1", {}),
                () => forge.callTool("s", "fail", {}),
                () => forge.callTool("s", "ok2", {}),
            ]);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        let results = result["results"].as_array().unwrap();
        assert!(results[0]["ok"] == true);
        assert!(results[1].is_null(), "failed call should have null result");
        assert!(results[2]["ok"] == true);
        let errors = result["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0]["index"], 1);
    }

    // --- PL-U03: parallel with failFast aborts on first error ---
    #[tokio::test]
    async fn pl_u03_parallel_fail_fast() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_tool_calls: 50,
            max_parallel: 2, // batch size 2
            ..Default::default()
        });

        struct FailOnSecondDispatcher {
            calls: std::sync::Mutex<u32>,
        }

        #[async_trait::async_trait]
        impl ToolDispatcher for FailOnSecondDispatcher {
            async fn call_tool(
                &self,
                _server: &str,
                tool: &str,
                _args: serde_json::Value,
            ) -> Result<serde_json::Value, anyhow::Error> {
                let mut c = self.calls.lock().unwrap();
                *c += 1;
                if tool == "fail" {
                    Err(anyhow::anyhow!("fail"))
                } else {
                    Ok(serde_json::json!({"ok": true}))
                }
            }
        }

        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(FailOnSecondDispatcher {
            calls: std::sync::Mutex::new(0),
        });

        // 4 calls with batch=2. Second call in first batch fails, so second batch should be skipped
        let code = r#"async () => {
            return await forge.parallel([
                () => forge.callTool("s", "ok", {}),
                () => forge.callTool("s", "fail", {}),
                () => forge.callTool("s", "ok", {}),
                () => forge.callTool("s", "ok", {}),
            ], { failFast: true });
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(result["aborted"], true);
        assert!(!result["errors"].as_array().unwrap().is_empty());
    }

    // --- PL-U04: parallel respects concurrency limit ---
    #[tokio::test]
    async fn pl_u04_parallel_respects_concurrency_limit() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_parallel: 2,
            timeout: Duration::from_secs(10),
            ..Default::default()
        });

        struct ConcurrencyTracker {
            current: std::sync::atomic::AtomicUsize,
            peak: std::sync::atomic::AtomicUsize,
        }

        #[async_trait::async_trait]
        impl ToolDispatcher for ConcurrencyTracker {
            async fn call_tool(
                &self,
                _server: &str,
                _tool: &str,
                _args: serde_json::Value,
            ) -> Result<serde_json::Value, anyhow::Error> {
                let c = self
                    .current
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                // Update peak
                self.peak.fetch_max(c, std::sync::atomic::Ordering::SeqCst);
                // Small delay to let concurrent calls overlap
                tokio::time::sleep(Duration::from_millis(10)).await;
                self.current
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                Ok(serde_json::json!({"peak": self.peak.load(std::sync::atomic::Ordering::SeqCst)}))
            }
        }

        let tracker = Arc::new(ConcurrencyTracker {
            current: std::sync::atomic::AtomicUsize::new(0),
            peak: std::sync::atomic::AtomicUsize::new(0),
        });
        let dispatcher: Arc<dyn ToolDispatcher> = tracker.clone();

        // 6 calls with max_parallel=2
        let code = r#"async () => {
            return await forge.parallel([
                () => forge.callTool("s", "t", {}),
                () => forge.callTool("s", "t", {}),
                () => forge.callTool("s", "t", {}),
                () => forge.callTool("s", "t", {}),
                () => forge.callTool("s", "t", {}),
                () => forge.callTool("s", "t", {}),
            ]);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(result["errors"].as_array().unwrap().len(), 0);
        let peak = tracker.peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!(peak <= 2, "peak concurrency should be <= 2, was: {peak}");
    }

    // --- PL-U05: parallel with empty array ---
    #[tokio::test]
    async fn pl_u05_parallel_empty_array() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            return await forge.parallel([]);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(result["results"].as_array().unwrap().len(), 0);
        assert_eq!(result["errors"].as_array().unwrap().len(), 0);
        assert_eq!(result["aborted"], false);
    }

    // --- PL-U06: parallel with single call ---
    #[tokio::test]
    async fn pl_u06_parallel_single_call() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            return await forge.parallel([
                () => forge.callTool("s", "t", { id: 1 }),
            ]);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        let results = result["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["server"], "s");
    }

    // --- PL-U07: parallel errors contain redacted messages ---
    #[tokio::test]
    async fn pl_u07_parallel_errors_redacted() {
        struct LeakyDispatcher;

        #[async_trait::async_trait]
        impl ToolDispatcher for LeakyDispatcher {
            async fn call_tool(
                &self,
                _server: &str,
                _tool: &str,
                _args: serde_json::Value,
            ) -> Result<serde_json::Value, anyhow::Error> {
                Err(anyhow::anyhow!(
                    "connection to http://internal.secret:9999/api failed"
                ))
            }
        }

        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(LeakyDispatcher);

        let code = r#"async () => {
            return await forge.parallel([
                () => forge.callTool("server", "tool", {}),
            ]);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        let errors = result["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 1);
        let msg = errors[0]["error"].as_str().unwrap();
        assert!(!msg.contains("internal.secret"), "should redact URL: {msg}");
    }

    // --- PL-U08: parallel combined with readResource ---
    #[tokio::test]
    async fn pl_u08_parallel_with_read_resource() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
            Some(Arc::new(TestResourceDispatcher));

        let code = r#"async () => {
            return await forge.parallel([
                () => forge.callTool("s", "t", {}),
                () => forge.readResource("rs", "file:///log"),
            ]);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, resource_dispatcher, None)
            .await
            .unwrap();
        let results = result["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["server"], "s");
        assert_eq!(results[1]["server"], "rs");
    }

    // --- PL-U09: parallel exceeding max_tool_calls ---
    #[tokio::test]
    async fn pl_u09_parallel_exceeds_rate_limit() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_tool_calls: 3,
            ..Default::default()
        });
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            return await forge.parallel([
                () => forge.callTool("s", "t1", {}),
                () => forge.callTool("s", "t2", {}),
                () => forge.callTool("s", "t3", {}),
                () => forge.callTool("s", "t4", {}),
                () => forge.callTool("s", "t5", {}),
            ]);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        // First 3 should succeed, remaining should error
        let errors = result["errors"].as_array().unwrap();
        assert!(!errors.is_empty(), "should have errors from rate limiting");
        // At least some results should be non-null
        let results = result["results"].as_array().unwrap();
        let successes = results.iter().filter(|r| !r.is_null()).count();
        assert_eq!(successes, 3, "should have exactly 3 successful calls");
    }

    // --- PL-S01: cannot exceed __MAX_PARALLEL even with high concurrency opt ---
    #[tokio::test]
    async fn pl_s01_cannot_exceed_max_parallel() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_parallel: 2,
            timeout: Duration::from_secs(10),
            ..Default::default()
        });

        struct ConcurrencyCounter {
            peak: std::sync::atomic::AtomicUsize,
            current: std::sync::atomic::AtomicUsize,
        }

        #[async_trait::async_trait]
        impl ToolDispatcher for ConcurrencyCounter {
            async fn call_tool(
                &self,
                _server: &str,
                _tool: &str,
                _args: serde_json::Value,
            ) -> Result<serde_json::Value, anyhow::Error> {
                let c = self
                    .current
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                self.peak.fetch_max(c, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                self.current
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                Ok(serde_json::json!({}))
            }
        }

        let counter = Arc::new(ConcurrencyCounter {
            peak: std::sync::atomic::AtomicUsize::new(0),
            current: std::sync::atomic::AtomicUsize::new(0),
        });
        let dispatcher: Arc<dyn ToolDispatcher> = counter.clone();

        // Request concurrency=9999 but max_parallel=2
        let code = r#"async () => {
            return await forge.parallel([
                () => forge.callTool("s", "t", {}),
                () => forge.callTool("s", "t", {}),
                () => forge.callTool("s", "t", {}),
                () => forge.callTool("s", "t", {}),
            ], { concurrency: 9999 });
        }"#;

        let _ = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        let peak = counter.peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            peak <= 2,
            "peak should be capped at max_parallel=2, was: {peak}"
        );
    }

    // --- PL-S02: parallel calls to mixed strict groups ---
    #[tokio::test]
    async fn pl_s02_parallel_mixed_strict_groups() {
        use crate::groups::{GroupEnforcingDispatcher, GroupPolicy};
        use std::collections::HashMap;

        let mut groups = HashMap::new();
        groups.insert(
            "internal".to_string(),
            (vec!["vault".to_string()], "strict".to_string()),
        );
        groups.insert(
            "external".to_string(),
            (vec!["slack".to_string()], "strict".to_string()),
        );
        let policy = Arc::new(GroupPolicy::from_config(&groups));
        let inner: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let enforcer = GroupEnforcingDispatcher::new(inner, policy);
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(enforcer);

        let exec = executor();

        // Parallel calls: first locks to "internal", second to "external" should fail
        let code = r#"async () => {
            return await forge.parallel([
                () => forge.callTool("vault", "secrets.list", {}),
                () => forge.callTool("slack", "messages.send", {}),
            ]);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        let errors = result["errors"].as_array().unwrap();
        // At least one should fail with cross-group error
        assert!(
            !errors.is_empty(),
            "should have cross-group error: {result:?}"
        );
        let has_cross_group = errors
            .iter()
            .any(|e| e["error"].as_str().unwrap_or("").contains("cross-group"));
        assert!(has_cross_group, "should mention cross-group: {result:?}");
    }

    // --- PL-S03: 500 parallel calls hits rate limit ---
    #[tokio::test]
    async fn pl_s03_many_parallel_calls_hit_rate_limit() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_tool_calls: 10,
            ..Default::default()
        });
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            const calls = [];
            for (let i = 0; i < 100; i++) {
                calls.push(() => forge.callTool("s", "t", { i }));
            }
            return await forge.parallel(calls);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        let errors = result["errors"].as_array().unwrap();
        let results = result["results"].as_array().unwrap();
        let successes = results.iter().filter(|r| !r.is_null()).count();
        assert_eq!(
            successes, 10,
            "should have exactly max_tool_calls successes"
        );
        assert_eq!(errors.len(), 90, "remaining 90 should be rate limited");
    }

    // --- PL-S04: __MAX_PARALLEL is not modifiable ---
    #[tokio::test]
    async fn pl_s04_max_parallel_not_modifiable() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_parallel: 3,
            ..Default::default()
        });
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Attempt to modify the frozen constant — should fail silently or throw
        let code = r#"async () => {
            try {
                // __MAX_PARALLEL is a local const in the bootstrap closure,
                // not accessible from user code. Attempting to use it would fail.
                return typeof __MAX_PARALLEL;
            } catch(e) {
                return "error";
            }
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        // __MAX_PARALLEL is scoped inside the IIFE, not visible to user code
        assert_eq!(
            result, "undefined",
            "__MAX_PARALLEL should not be accessible"
        );
    }

    // --- PL-S05: raw Promise.all still hits rate limit ---
    #[tokio::test]
    async fn pl_s05_raw_promise_all_hits_rate_limit() {
        let exec = SandboxExecutor::new(SandboxConfig {
            max_tool_calls: 3,
            ..Default::default()
        });
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        // Bypass forge.parallel() and use raw Promise.allSettled
        let code = r#"async () => {
            const results = await Promise.allSettled([
                forge.callTool("s", "t1", {}),
                forge.callTool("s", "t2", {}),
                forge.callTool("s", "t3", {}),
                forge.callTool("s", "t4", {}),
                forge.callTool("s", "t5", {}),
            ]);
            const fulfilled = results.filter(r => r.status === "fulfilled").length;
            const rejected = results.filter(r => r.status === "rejected").length;
            return { fulfilled, rejected };
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(result["fulfilled"], 3, "should have 3 successful calls");
        assert_eq!(result["rejected"], 2, "should have 2 rate-limited calls");
    }

    // =========================================================================
    // Phase 8: Bootstrap + Invariant Tests (BS-01..BS-12, INV-01..INV-10)
    // =========================================================================

    // --- BS-01: forge object is frozen ---
    #[tokio::test]
    async fn bs_01_forge_object_is_frozen() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource: Arc<dyn ResourceDispatcher> = Arc::new(TestResourceDispatcher);
        let stash_store = make_stash(Default::default());
        let stash = make_stash_dispatcher(stash_store, None);

        let code = r#"async () => {
            return Object.isFrozen(forge);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, Some(resource), Some(stash))
            .await
            .unwrap();
        assert_eq!(result, true, "forge object must be frozen");
    }

    // --- BS-02: forge.stash is frozen ---
    #[tokio::test]
    async fn bs_02_forge_stash_is_frozen() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let stash_store = make_stash(Default::default());
        let stash = make_stash_dispatcher(stash_store, None);

        let code = r#"async () => {
            return Object.isFrozen(forge.stash);
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, Some(stash))
            .await
            .unwrap();
        assert_eq!(result, true, "forge.stash must be frozen");
    }

    // --- BS-03: __MAX_PARALLEL is not accessible from user code as a global ---
    #[tokio::test]
    async fn bs_03_max_parallel_not_accessible_as_global() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            return {
                global: typeof globalThis.__MAX_PARALLEL,
                direct: typeof __MAX_PARALLEL,
            };
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(
            result["global"], "undefined",
            "__MAX_PARALLEL must not be on globalThis"
        );
        // __MAX_PARALLEL is a local const inside the bootstrap IIFE,
        // so direct access from user code (different scope) should fail.
        // User code runs in a separate eval context, so it shouldn't see the IIFE local.
        assert_eq!(
            result["direct"], "undefined",
            "__MAX_PARALLEL must not be accessible from user scope"
        );
    }

    // --- BS-04: forge.readResource is a function in execute mode ---
    #[tokio::test]
    async fn bs_04_read_resource_is_function_in_execute_mode() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource: Arc<dyn ResourceDispatcher> = Arc::new(TestResourceDispatcher);

        let code = r#"async () => {
            return typeof forge.readResource;
        }"#;

        let result = exec
            .execute_code(code, dispatcher, Some(resource), None)
            .await
            .unwrap();
        assert_eq!(result, "function", "forge.readResource must be a function");
    }

    // --- BS-05: forge.readResource is undefined in search mode ---
    #[tokio::test]
    async fn bs_05_read_resource_undefined_in_search_mode() {
        let exec = executor();
        let manifest = serde_json::json!({"servers": []});

        let code = r#"async () => {
            return typeof forge.readResource;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(
            result, "undefined",
            "forge.readResource must be undefined in search mode"
        );
    }

    // --- BS-06: forge.stash has put/get/delete/keys in execute mode ---
    #[tokio::test]
    async fn bs_06_stash_has_all_methods_in_execute_mode() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let stash_store = make_stash(Default::default());
        let stash = make_stash_dispatcher(stash_store, None);

        let code = r#"async () => {
            return {
                type: typeof forge.stash,
                put: typeof forge.stash.put,
                get: typeof forge.stash.get,
                del: typeof forge.stash.delete,
                keys: typeof forge.stash.keys,
            };
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, Some(stash))
            .await
            .unwrap();
        assert_eq!(result["type"], "object", "forge.stash must be an object");
        assert_eq!(result["put"], "function");
        assert_eq!(result["get"], "function");
        assert_eq!(result["del"], "function");
        assert_eq!(result["keys"], "function");
    }

    // --- BS-07: forge.stash is undefined in search mode ---
    #[tokio::test]
    async fn bs_07_stash_undefined_in_search_mode() {
        let exec = executor();
        let manifest = serde_json::json!({"servers": []});

        let code = r#"async () => {
            return typeof forge.stash;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(
            result, "undefined",
            "forge.stash must be undefined in search mode"
        );
    }

    // --- BS-08: forge.parallel is a function in execute mode ---
    #[tokio::test]
    async fn bs_08_parallel_is_function_in_execute_mode() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            return typeof forge.parallel;
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(result, "function", "forge.parallel must be a function");
    }

    // --- BS-09: forge.parallel is undefined in search mode ---
    #[tokio::test]
    async fn bs_09_parallel_undefined_in_search_mode() {
        let exec = executor();
        let manifest = serde_json::json!({"servers": []});

        let code = r#"async () => {
            return typeof forge.parallel;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(
            result, "undefined",
            "forge.parallel must be undefined in search mode"
        );
    }

    // --- BS-10: forge.server("x").cat.tool() still works (Proxy not broken) ---
    #[tokio::test]
    async fn bs_10_server_proxy_still_works() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource: Arc<dyn ResourceDispatcher> = Arc::new(TestResourceDispatcher);
        let stash_store = make_stash(Default::default());
        let stash = make_stash_dispatcher(stash_store, None);

        let code = r#"async () => {
            const result = await forge.server("myserver").ast.parse({ file: "test.rs" });
            return result;
        }"#;

        let result = exec
            .execute_code(code, dispatcher, Some(resource), Some(stash))
            .await
            .unwrap();
        assert_eq!(result["server"], "myserver");
        assert_eq!(result["tool"], "ast.parse");
        assert_eq!(result["args"]["file"], "test.rs");
    }

    // --- BS-11: delete globalThis.Deno still happens after new APIs ---
    #[tokio::test]
    async fn bs_11_deno_deleted_in_execute_mode() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource: Arc<dyn ResourceDispatcher> = Arc::new(TestResourceDispatcher);
        let stash_store = make_stash(Default::default());
        let stash = make_stash_dispatcher(stash_store, None);

        let code = r#"async () => {
            return typeof globalThis.Deno;
        }"#;

        let result = exec
            .execute_code(code, dispatcher, Some(resource), Some(stash))
            .await
            .unwrap();
        assert_eq!(result, "undefined", "Deno must be deleted in execute mode");
    }

    // --- BS-12: Function.prototype.constructor is still undefined ---
    #[tokio::test]
    async fn bs_12_function_constructor_undefined_in_execute_mode() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let resource: Arc<dyn ResourceDispatcher> = Arc::new(TestResourceDispatcher);
        let stash_store = make_stash(Default::default());
        let stash = make_stash_dispatcher(stash_store, None);

        // After bootstrap, Function.prototype.constructor is undefined.
        // Since .constructor is undefined, (async fn).constructor is also undefined,
        // so we cannot chain .prototype.constructor — we verify via separate checks.
        let code = r#"async () => {
            const funcCtor = typeof Function.prototype.constructor;
            // AsyncFunction and GeneratorFunction constructors are also wiped
            // because they inherit from Function.prototype.
            const asyncFn = async function(){};
            const genFn = function*(){};
            const asyncCtor = typeof asyncFn.constructor;
            const genCtor = typeof genFn.constructor;
            return { funcCtor, asyncCtor, genCtor };
        }"#;

        let result = exec
            .execute_code(code, dispatcher, Some(resource), Some(stash))
            .await
            .unwrap();
        assert_eq!(
            result["funcCtor"], "undefined",
            "Function.prototype.constructor must be undefined"
        );
        assert_eq!(
            result["asyncCtor"], "undefined",
            "AsyncFunction .constructor must be undefined"
        );
        assert_eq!(
            result["genCtor"], "undefined",
            "GeneratorFunction .constructor must be undefined"
        );
    }

    // --- INV-01: search() mode cannot access forge.callTool ---
    #[tokio::test]
    async fn inv_01_search_mode_no_call_tool() {
        let exec = executor();
        let manifest = serde_json::json!({"servers": []});

        let code = r#"async () => {
            return typeof forge.callTool;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(
            result, "undefined",
            "forge.callTool must not exist in search mode"
        );
    }

    // --- INV-02: search() mode cannot access forge.readResource ---
    #[tokio::test]
    async fn inv_02_search_mode_no_read_resource() {
        let exec = executor();
        let manifest = serde_json::json!({"servers": []});

        let code = r#"async () => {
            return typeof forge.readResource;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(
            result, "undefined",
            "forge.readResource must not exist in search mode"
        );
    }

    // --- INV-03: search() mode cannot access forge.stash ---
    #[tokio::test]
    async fn inv_03_search_mode_no_stash() {
        let exec = executor();
        let manifest = serde_json::json!({"servers": []});

        let code = r#"async () => {
            return typeof forge.stash;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(
            result, "undefined",
            "forge.stash must not exist in search mode"
        );
    }

    // --- INV-04: search() mode cannot access forge.parallel ---
    #[tokio::test]
    async fn inv_04_search_mode_no_parallel() {
        let exec = executor();
        let manifest = serde_json::json!({"servers": []});

        let code = r#"async () => {
            return typeof forge.parallel;
        }"#;

        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(
            result, "undefined",
            "forge.parallel must not exist in search mode"
        );
    }

    // --- INV-05: eval is undefined in all modes ---
    #[tokio::test]
    async fn inv_05_eval_undefined_in_all_modes() {
        let exec = executor();

        // Execute mode
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let code = r#"async () => { return typeof eval; }"#;
        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(
            result, "undefined",
            "eval must be undefined in execute mode"
        );

        // Search mode
        let manifest = serde_json::json!({"servers": []});
        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(result, "undefined", "eval must be undefined in search mode");
    }

    // --- INV-06: Function.prototype.constructor is undefined in all modes ---
    #[tokio::test]
    async fn inv_06_function_constructor_undefined_all_modes() {
        let exec = executor();

        let code = r#"async () => {
            return typeof Function.prototype.constructor;
        }"#;

        // Execute mode
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(
            result, "undefined",
            "Function.prototype.constructor must be undefined in execute mode"
        );

        // Search mode
        let manifest = serde_json::json!({"servers": []});
        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(
            result, "undefined",
            "Function.prototype.constructor must be undefined in search mode"
        );
    }

    // --- INV-07: Deno is undefined after bootstrap in all modes ---
    #[tokio::test]
    async fn inv_07_deno_undefined_all_modes() {
        let exec = executor();

        let code = r#"async () => { return typeof globalThis.Deno; }"#;

        // Execute mode
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(
            result, "undefined",
            "Deno must be undefined in execute mode"
        );

        // Search mode
        let manifest = serde_json::json!({"servers": []});
        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(result, "undefined", "Deno must be undefined in search mode");
    }

    // --- INV-08: forge object is frozen in all modes ---
    #[tokio::test]
    async fn inv_08_forge_frozen_all_modes() {
        let exec = executor();

        let code = r#"async () => { return Object.isFrozen(forge); }"#;

        // Execute mode
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let result = exec
            .execute_code(code, dispatcher, None, None)
            .await
            .unwrap();
        assert_eq!(result, true, "forge must be frozen in execute mode");

        // Search mode
        let manifest = serde_json::json!({"servers": []});
        let result = exec.execute_search(code, &manifest).await.unwrap();
        assert_eq!(result, true, "forge must be frozen in search mode");
    }

    // --- INV-09: forge.stash object is frozen in execute mode ---
    #[tokio::test]
    async fn inv_09_stash_frozen_in_execute_mode() {
        let exec = executor();
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);
        let stash_store = make_stash(Default::default());
        let stash = make_stash_dispatcher(stash_store, None);

        // Verify stash is frozen and cannot be modified
        let code = r#"async () => {
            const frozen = Object.isFrozen(forge.stash);
            let mutated = false;
            try {
                forge.stash.evil = () => {};
                mutated = forge.stash.evil !== undefined;
            } catch (e) {
                // TypeError in strict mode, which is fine
            }
            return { frozen, mutated };
        }"#;

        let result = exec
            .execute_code(code, dispatcher, None, Some(stash))
            .await
            .unwrap();
        assert_eq!(result["frozen"], true, "forge.stash must be frozen");
        assert_eq!(result["mutated"], false, "forge.stash must not be mutable");
    }

    // --- INV-10: error messages from all new ops pass through redact_error_for_llm ---
    #[tokio::test]
    async fn inv_10_error_messages_redacted() {
        let exec = executor();

        // Use a resource dispatcher that fails with a message containing file paths
        let failing_resource: Arc<dyn ResourceDispatcher> = Arc::new(FailingResourceDispatcher {
            error_msg: "connection refused to /var/secret/db.sock".to_string(),
        });
        let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(TestDispatcher);

        let code = r#"async () => {
            try {
                await forge.readResource("secret-server", "file:///data/log.txt");
                return { error: null };
            } catch (e) {
                return { error: e.message || String(e) };
            }
        }"#;

        let result = exec
            .execute_code(code, dispatcher, Some(failing_resource), None)
            .await
            .unwrap();
        let error_msg = result["error"].as_str().unwrap();
        // Error should be redacted — should not contain raw file paths from the dispatcher
        // The redaction replaces the error with a safe format
        assert!(
            !error_msg.contains("/var/secret/db.sock"),
            "error must be redacted, got: {error_msg}"
        );
        // Should mention the server name in a safe way
        assert!(
            error_msg.contains("secret-server"),
            "error should reference server name: {error_msg}"
        );
    }
}
