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
use forge_sandbox::ipc::{read_message, read_message_with_limit, write_message, ChildMessage, ParentMessage};
use forge_sandbox::ToolDispatcher;
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
    /// Atomic counter for generating unique request IDs.
    next_id: AtomicU64,
}

#[async_trait::async_trait]
impl ToolDispatcher for IpcToolBridge {
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, anyhow::Error> {
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

        result.map_err(|e| anyhow::anyhow!("{}", e))
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

    // Read the Execute message from stdin
    let mut stdin = BufReader::new(io::stdin());
    let mut stdout = io::stdout();

    let msg: ParentMessage = read_message(&mut stdin)
        .await
        .context("failed to read initial message from parent")?
        .context("parent closed stdin before sending Execute")?;

    let (code, config) = match msg {
        ParentMessage::Execute {
            code,
            manifest: _,
            config,
        } => (code, config),
        other => {
            anyhow::bail!("expected Execute message, got: {:?}", other);
        }
    };

    let sandbox_config = config.to_sandbox_config();
    let max_ipc_size = config.max_ipc_message_size;

    // Set up IPC channels
    // tx: child messages to send to parent (tool requests, logs)
    // waiter_tx: register response waiters for tool call results
    let (tx, mut rx) = mpsc::unbounded_channel::<ChildMessage>();
    let (waiter_tx, mut waiter_rx) =
        mpsc::unbounded_channel::<(u64, oneshot::Sender<Result<serde_json::Value, String>>)>();

    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(IpcToolBridge {
        tx: tx.clone(),
        waiter_tx,
        next_id: AtomicU64::new(1),
    });

    // Spawn the V8 execution on a dedicated thread (V8 isolates are !Send)
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
                });
                return;
            }
        };

        let result = rt.block_on(forge_sandbox::executor::run_execute(
            &sandbox_config,
            &code,
            dispatcher,
        ));

        let child_result = match result {
            Ok(value) => ChildMessage::ExecutionComplete { result: Ok(value) },
            Err(e) => ChildMessage::ExecutionComplete {
                result: Err(e.to_string()),
            },
        };

        let _ = exec_tx.send(child_result);
    });

    // IPC event loop: multiplex between
    // 1. Outgoing messages from the V8 thread (tool requests, completion)
    // 2. Incoming responses from the parent (tool call results)
    // 3. Registering new response waiters
    let mut pending_waiters: std::collections::HashMap<
        u64,
        oneshot::Sender<Result<serde_json::Value, String>>,
    > = std::collections::HashMap::new();
    let mut execution_done = false;

    loop {
        tokio::select! {
            // Outgoing: V8 thread wants to send a message to the parent
            msg = rx.recv() => {
                match msg {
                    Some(child_msg) => {
                        let is_complete = matches!(child_msg, ChildMessage::ExecutionComplete { .. });
                        write_message(&mut stdout, &child_msg).await
                            .context("failed to write message to parent")?;
                        stdout.flush().await?;
                        if is_complete {
                            execution_done = true;
                            // Drain any remaining waiters
                            if pending_waiters.is_empty() {
                                break;
                            }
                        }
                    }
                    None => {
                        // Channel closed — V8 thread exited
                        if !execution_done {
                            let msg = ChildMessage::ExecutionComplete {
                                result: Err("worker thread exited unexpectedly".into()),
                            };
                            write_message(&mut stdout, &msg).await.ok();
                        }
                        break;
                    }
                }
            }

            // Incoming: parent sends a tool call result
            result = read_message_with_limit::<ParentMessage, _>(&mut stdin, max_ipc_size) => {
                match result {
                    Ok(Some(ParentMessage::ToolCallResult { request_id, result })) => {
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
                        // Parent closed stdin — abort
                        break;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read from parent");
                        break;
                    }
                }
            }

            // Register new response waiters from the IpcToolBridge
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
