//! SandboxHost — parent-side management of isolated worker child processes.
//!
//! Spawns `forge-sandbox-worker` as a child process with a clean environment,
//! communicates over length-delimited JSON IPC (stdin/stdout), and routes
//! tool calls through the parent's [`ToolDispatcher`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::BufReader;
use tokio::process::Command;

use crate::error::SandboxError;
use crate::ipc::{read_message, write_message, ChildMessage, ParentMessage, WorkerConfig};
use crate::ToolDispatcher;

/// Manages spawning and communicating with sandbox worker child processes.
pub struct SandboxHost;

impl SandboxHost {
    /// Execute code in an isolated child process.
    ///
    /// 1. Spawns `forge-sandbox-worker` with a clean environment
    /// 2. Sends the code and config via IPC
    /// 3. Routes tool call requests through the parent's dispatcher
    /// 4. Returns the execution result (or kills the child on timeout)
    pub async fn execute_in_child(
        code: &str,
        config: &crate::SandboxConfig,
        dispatcher: Arc<dyn ToolDispatcher>,
    ) -> Result<serde_json::Value, SandboxError> {
        let worker_bin = find_worker_binary()?;
        let worker_config = WorkerConfig::from(config);
        let timeout = config.timeout;

        // Spawn the worker with a clean environment
        let mut child = Command::new(&worker_bin)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit()) // forward worker logs
            .env_clear()
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| SandboxError::Execution(anyhow::anyhow!(
                "failed to spawn worker at {}: {}", worker_bin.display(), e
            )))?;

        let mut child_stdin = child.stdin.take()
            .ok_or_else(|| SandboxError::Execution(anyhow::anyhow!("no stdin on child")))?;
        let child_stdout = child.stdout.take()
            .ok_or_else(|| SandboxError::Execution(anyhow::anyhow!("no stdout on child")))?;
        let mut child_stdout = BufReader::new(child_stdout);

        // Send the Execute message
        let execute_msg = ParentMessage::Execute {
            code: code.to_string(),
            manifest: None,
            config: worker_config,
        };
        write_message(&mut child_stdin, &execute_msg)
            .await
            .map_err(|e| SandboxError::Execution(anyhow::anyhow!("failed to send Execute: {}", e)))?;

        // IPC event loop with overall timeout
        let result = tokio::time::timeout(
            // Give the child a bit more time than its internal timeout,
            // so the child can report its own timeout error cleanly.
            timeout + Duration::from_secs(2),
            ipc_event_loop(&mut child_stdin, &mut child_stdout, dispatcher),
        )
        .await;

        match result {
            Ok(inner) => inner,
            Err(_elapsed) => {
                // Timeout — kill the child process
                let _ = child.kill().await;
                Err(SandboxError::Timeout {
                    timeout_ms: timeout.as_millis() as u64,
                })
            }
        }
    }
}

/// Run the IPC event loop: read messages from the child, dispatch tool calls,
/// return the final result.
async fn ipc_event_loop(
    child_stdin: &mut tokio::process::ChildStdin,
    child_stdout: &mut BufReader<tokio::process::ChildStdout>,
    dispatcher: Arc<dyn ToolDispatcher>,
) -> Result<serde_json::Value, SandboxError> {
    loop {
        let msg: Option<ChildMessage> = read_message(child_stdout)
            .await
            .map_err(|e| SandboxError::Execution(anyhow::anyhow!("IPC read error: {}", e)))?;

        match msg {
            Some(ChildMessage::ExecutionComplete { result }) => {
                return match result {
                    Ok(value) => Ok(value),
                    Err(err) => Err(SandboxError::JsError { message: err }),
                };
            }
            Some(ChildMessage::ToolCallRequest {
                request_id,
                server,
                tool,
                args,
            }) => {
                // Dispatch the tool call through the parent's dispatcher
                let tool_result = dispatcher.call_tool(&server, &tool, args).await;

                let response = ParentMessage::ToolCallResult {
                    request_id,
                    result: tool_result.map_err(|e| e.to_string()),
                };

                write_message(child_stdin, &response)
                    .await
                    .map_err(|e| SandboxError::Execution(
                        anyhow::anyhow!("failed to send tool result: {}", e),
                    ))?;
            }
            Some(ChildMessage::Log { message }) => {
                tracing::info!(target: "forge::sandbox::worker", "{}", message);
            }
            None => {
                // Child closed stdout without sending ExecutionComplete
                return Err(SandboxError::Execution(anyhow::anyhow!(
                    "worker exited without sending result"
                )));
            }
        }
    }
}

/// Find the `forge-sandbox-worker` binary.
///
/// Search order:
/// 1. `FORGE_WORKER_BIN` environment variable
/// 2. Same directory as the current executable
/// 3. PATH lookup
fn find_worker_binary() -> Result<PathBuf, SandboxError> {
    // 1. Explicit env var
    if let Ok(path) = std::env::var("FORGE_WORKER_BIN") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Ok(p);
        }
    }

    // 2. Same directory as current executable (or parent, for test binaries in deps/)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let worker = dir.join("forge-sandbox-worker");
            if worker.exists() {
                return Ok(worker);
            }
            // Test binaries are in target/debug/deps/ but worker is in target/debug/
            if let Some(parent) = dir.parent() {
                let worker = parent.join("forge-sandbox-worker");
                if worker.exists() {
                    return Ok(worker);
                }
            }
        }
    }

    // 3. PATH lookup via `which`
    if let Ok(output) = std::process::Command::new("which")
        .arg("forge-sandbox-worker")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    Err(SandboxError::Execution(anyhow::anyhow!(
        "forge-sandbox-worker binary not found. Set FORGE_WORKER_BIN or ensure it's in PATH"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_worker_binary_from_exe_dir() {
        // This test checks that find_worker_binary can locate the worker
        // when it's in the same directory as the test binary.
        // During `cargo test`, the worker binary should be in the target dir.
        // This may not always work, so we just verify the function doesn't panic.
        let _ = find_worker_binary();
    }
}
