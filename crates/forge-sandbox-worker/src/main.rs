//! Forge sandbox worker — isolated child process for V8 execution.
//!
//! This binary is spawned by [`forge_sandbox::host::SandboxHost`] in the parent process.
//! It receives code and configuration over stdin, executes it in a V8 isolate,
//! and sends results back over stdout. Tool calls are proxied through the parent
//! via the IPC protocol.
//!
//! **Security**: This process runs with a clean environment — no credentials,
//! no inherited file descriptors, no access to MCP connections.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use forge_error::DispatchError;
use forge_sandbox::error::SandboxError;
use forge_sandbox::ipc::{
    read_message, read_message_with_limit, write_message, ChildMessage, ErrorKind, ParentMessage,
};
use forge_sandbox::{ResourceDispatcher, StashDispatcher, ToolDispatcher};
use tokio::io::{self, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

/// Tool dispatcher that proxies tool calls through IPC to the parent process.
///
/// When sandbox code calls `forge.callTool()`, this sends a `ToolCallRequest`
/// to the parent and waits for the `ToolCallResult` response.
struct IpcToolBridge {
    /// Sender for outgoing child messages (tool requests, logs).
    tx: mpsc::UnboundedSender<ChildMessage>,
    /// Sender for registering response waiters, keyed by request_id.
    waiter_tx: mpsc::UnboundedSender<(u64, oneshot::Sender<Result<serde_json::Value, String>>)>,
    /// Atomic counter for generating unique request IDs (shared with other bridges).
    next_id: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolDispatcher for IpcToolBridge {
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let request_id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // Register a waiter for the response
        let (resp_tx, resp_rx) = oneshot::channel();
        self.waiter_tx
            .send((request_id, resp_tx))
            .map_err(|_| anyhow::anyhow!("IPC waiter channel closed"))?;

        // Send the tool call request to the parent
        self.tx
            .send(ChildMessage::ToolCallRequest {
                request_id,
                server: server.to_string(),
                tool: tool.to_string(),
                args,
            })
            .map_err(|_| anyhow::anyhow!("IPC send channel closed"))?;

        // Wait for the parent's response
        let result = resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("IPC response channel closed"))?;

        result.map_err(|e| DispatchError::Internal(anyhow::anyhow!("{}", e)))
    }
}

/// Resource dispatcher that proxies resource reads through IPC to the parent process.
///
/// When sandbox code calls `forge.readResource()`, this sends a `ResourceReadRequest`
/// to the parent and waits for the `ResourceReadResult` response.
struct IpcResourceBridge {
    /// Sender for outgoing child messages.
    tx: mpsc::UnboundedSender<ChildMessage>,
    /// Sender for registering response waiters, keyed by request_id.
    waiter_tx: mpsc::UnboundedSender<(u64, oneshot::Sender<Result<serde_json::Value, String>>)>,
    /// Atomic counter for generating unique request IDs.
    next_id: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ResourceDispatcher for IpcResourceBridge {
    async fn read_resource(
        &self,
        server: &str,
        uri: &str,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let request_id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let (resp_tx, resp_rx) = oneshot::channel();
        self.waiter_tx
            .send((request_id, resp_tx))
            .map_err(|_| anyhow::anyhow!("IPC waiter channel closed"))?;

        self.tx
            .send(ChildMessage::ResourceReadRequest {
                request_id,
                server: server.to_string(),
                uri: uri.to_string(),
            })
            .map_err(|_| anyhow::anyhow!("IPC send channel closed"))?;

        let result = resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("IPC response channel closed"))?;

        result.map_err(|e| DispatchError::Internal(anyhow::anyhow!("{}", e)))
    }
}

/// Stash dispatcher that proxies stash operations through IPC to the parent process.
///
/// When sandbox code calls `forge.stash.put/get/delete/keys()`, this sends the
/// corresponding stash message to the parent and waits for the `StashResult` response.
struct IpcStashBridge {
    /// Sender for outgoing child messages.
    tx: mpsc::UnboundedSender<ChildMessage>,
    /// Sender for registering response waiters, keyed by request_id.
    waiter_tx: mpsc::UnboundedSender<(u64, oneshot::Sender<Result<serde_json::Value, String>>)>,
    /// Atomic counter for generating unique request IDs.
    next_id: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl StashDispatcher for IpcStashBridge {
    async fn put(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: Option<u32>,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let request_id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let (resp_tx, resp_rx) = oneshot::channel();
        self.waiter_tx
            .send((request_id, resp_tx))
            .map_err(|_| anyhow::anyhow!("IPC waiter channel closed"))?;

        self.tx
            .send(ChildMessage::StashPut {
                request_id,
                key: key.to_string(),
                value,
                ttl_secs,
                group: current_group,
            })
            .map_err(|_| anyhow::anyhow!("IPC send channel closed"))?;

        let result = resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("IPC response channel closed"))?;

        result.map_err(|e| DispatchError::Internal(anyhow::anyhow!("{}", e)))
    }

    async fn get(
        &self,
        key: &str,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let request_id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let (resp_tx, resp_rx) = oneshot::channel();
        self.waiter_tx
            .send((request_id, resp_tx))
            .map_err(|_| anyhow::anyhow!("IPC waiter channel closed"))?;

        self.tx
            .send(ChildMessage::StashGet {
                request_id,
                key: key.to_string(),
                group: current_group,
            })
            .map_err(|_| anyhow::anyhow!("IPC send channel closed"))?;

        let result = resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("IPC response channel closed"))?;

        result.map_err(|e| DispatchError::Internal(anyhow::anyhow!("{}", e)))
    }

    async fn delete(
        &self,
        key: &str,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let request_id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let (resp_tx, resp_rx) = oneshot::channel();
        self.waiter_tx
            .send((request_id, resp_tx))
            .map_err(|_| anyhow::anyhow!("IPC waiter channel closed"))?;

        self.tx
            .send(ChildMessage::StashDelete {
                request_id,
                key: key.to_string(),
                group: current_group,
            })
            .map_err(|_| anyhow::anyhow!("IPC send channel closed"))?;

        let result = resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("IPC response channel closed"))?;

        result.map_err(|e| DispatchError::Internal(anyhow::anyhow!("{}", e)))
    }

    async fn keys(
        &self,
        current_group: Option<String>,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        let request_id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let (resp_tx, resp_rx) = oneshot::channel();
        self.waiter_tx
            .send((request_id, resp_tx))
            .map_err(|_| anyhow::anyhow!("IPC waiter channel closed"))?;

        self.tx
            .send(ChildMessage::StashKeys {
                request_id,
                group: current_group,
            })
            .map_err(|_| anyhow::anyhow!("IPC send channel closed"))?;

        let result = resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("IPC response channel closed"))?;

        result.map_err(|e| DispatchError::Internal(anyhow::anyhow!("{}", e)))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Clean environment: remove all env vars for security isolation
    let env_keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    for key in env_keys {
        std::env::remove_var(&key);
    }

    // Set up minimal logging to stderr (parent captures this)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .init();

    let mut stdin = BufReader::new(io::stdin());
    let mut stdout = io::stdout();

    // Multi-execution loop: the first message determines the mode.
    //
    // - Execute: single-execution mode (backward compatible with v0.2).
    //   Run the execution, then exit.
    // - Reset: pool mode. Send ResetComplete, then wait for Execute.
    //   After execution completes, wait for another Reset or EOF.
    loop {
        let msg: ParentMessage = match read_message(&mut stdin).await {
            Ok(Some(msg)) => msg,
            Ok(None) => break, // Parent closed stdin — clean exit
            Err(e) => {
                anyhow::bail!("failed to read message from parent: {}", e);
            }
        };

        match msg {
            ParentMessage::Reset { config: _ } => {
                // Pool mode: acknowledge the reset and wait for Execute
                write_message(&mut stdout, &ChildMessage::ResetComplete).await?;
                stdout.flush().await?;
                continue;
            }
            ParentMessage::Execute {
                code,
                manifest: _,
                config,
            } => {
                run_single_execution(&mut stdin, &mut stdout, &code, config).await?;
                // After execution, continue the loop to handle Reset or EOF
                continue;
            }
            other => {
                anyhow::bail!("expected Execute or Reset message, got: {:?}", other);
            }
        }
    }

    Ok(())
}

/// Run a single V8 execution, handling the full IPC lifecycle.
///
/// This function sets up IPC channels, spawns the V8 thread, runs the
/// IPC event loop, and waits for completion.
async fn run_single_execution(
    stdin: &mut BufReader<io::Stdin>,
    stdout: &mut io::Stdout,
    code: &str,
    config: forge_sandbox::ipc::WorkerConfig,
) -> Result<()> {
    let sandbox_config = config.to_sandbox_config();
    let max_ipc_size = config.max_ipc_message_size;
    let known_tools = config.known_tools;
    let known_servers = config.known_servers;

    // Set up IPC channels
    let (tx, mut rx) = mpsc::unbounded_channel::<ChildMessage>();
    let (waiter_tx, mut waiter_rx) =
        mpsc::unbounded_channel::<(u64, oneshot::Sender<Result<serde_json::Value, String>>)>();

    let shared_next_id = Arc::new(AtomicU64::new(1));

    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(IpcToolBridge {
        tx: tx.clone(),
        waiter_tx: waiter_tx.clone(),
        next_id: shared_next_id.clone(),
    });

    let resource_dispatcher: Option<Arc<dyn ResourceDispatcher>> =
        Some(Arc::new(IpcResourceBridge {
            tx: tx.clone(),
            waiter_tx: waiter_tx.clone(),
            next_id: shared_next_id.clone(),
        }));

    let stash_dispatcher: Option<Arc<dyn StashDispatcher>> = Some(Arc::new(IpcStashBridge {
        tx: tx.clone(),
        waiter_tx,
        next_id: shared_next_id,
    }));

    // Spawn the V8 execution on a dedicated thread (V8 isolates are !Send)
    let code_owned = code.to_string();
    let exec_tx = tx.clone();
    let exec_handle = std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = exec_tx.send(ChildMessage::ExecutionComplete {
                    result: Err(format!("failed to create tokio runtime: {}", e)),
                    error_kind: Some(ErrorKind::Execution),
                    timeout_ms: None,
                });
                return;
            }
        };

        let result = rt.block_on(forge_sandbox::executor::run_execute_with_known_servers(
            &sandbox_config,
            &code_owned,
            dispatcher,
            resource_dispatcher,
            stash_dispatcher,
            known_servers,
            known_tools,
        ));

        let child_result = match result {
            Ok(value) => ChildMessage::ExecutionComplete {
                result: Ok(value),
                error_kind: None,
                timeout_ms: None,
            },
            Err(ref e) => {
                let (kind, structured_timeout_ms) = match e {
                    SandboxError::Timeout { timeout_ms } => (ErrorKind::Timeout, Some(*timeout_ms)),
                    SandboxError::HeapLimitExceeded => (ErrorKind::HeapLimit, None),
                    SandboxError::JsError { .. } => (ErrorKind::JsError, None),
                    _ => (ErrorKind::Execution, None),
                };
                ChildMessage::ExecutionComplete {
                    result: Err(e.to_string()),
                    error_kind: Some(kind),
                    timeout_ms: structured_timeout_ms,
                }
            }
        };

        let _ = exec_tx.send(child_result);
    });

    // IPC event loop
    let mut pending_waiters: std::collections::HashMap<
        u64,
        oneshot::Sender<Result<serde_json::Value, String>>,
    > = std::collections::HashMap::new();
    let mut execution_done = false;

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(child_msg) => {
                        let is_complete = matches!(child_msg, ChildMessage::ExecutionComplete { .. });
                        write_message(stdout, &child_msg).await
                            .context("failed to write message to parent")?;
                        stdout.flush().await?;
                        if is_complete {
                            execution_done = true;
                            if pending_waiters.is_empty() {
                                break;
                            }
                        }
                    }
                    None => {
                        if !execution_done {
                            let msg = ChildMessage::ExecutionComplete {
                                result: Err("worker thread exited unexpectedly".into()),
                                error_kind: Some(ErrorKind::Execution),
                                timeout_ms: None,
                            };
                            write_message(stdout, &msg).await.ok();
                        }
                        break;
                    }
                }
            }

            result = read_message_with_limit::<ParentMessage, _>(stdin, max_ipc_size) => {
                match result {
                    Ok(Some(ParentMessage::ToolCallResult { request_id, result })) => {
                        if let Some(waiter) = pending_waiters.remove(&request_id) {
                            let _ = waiter.send(result);
                        }
                        if execution_done && pending_waiters.is_empty() {
                            break;
                        }
                    }
                    Ok(Some(ParentMessage::ResourceReadResult { request_id, result })) => {
                        if let Some(waiter) = pending_waiters.remove(&request_id) {
                            let _ = waiter.send(result);
                        }
                        if execution_done && pending_waiters.is_empty() {
                            break;
                        }
                    }
                    Ok(Some(ParentMessage::StashResult { request_id, result })) => {
                        if let Some(waiter) = pending_waiters.remove(&request_id) {
                            let _ = waiter.send(result);
                        }
                        if execution_done && pending_waiters.is_empty() {
                            break;
                        }
                    }
                    Ok(Some(_)) => {
                        tracing::warn!("unexpected message type from parent");
                    }
                    Ok(None) => {
                        break;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read from parent");
                        break;
                    }
                }
            }

            waiter = waiter_rx.recv() => {
                if let Some((id, sender)) = waiter {
                    pending_waiters.insert(id, sender);
                }
            }
        }
    }

    // Wait for the V8 thread to finish
    let _ = exec_handle.join();

    Ok(())
}
