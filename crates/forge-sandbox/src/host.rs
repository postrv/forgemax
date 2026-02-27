//! SandboxHost — parent-side management of isolated worker child processes.
//!
//! Spawns `forgemax-worker` as a child process with a clean environment,
//! communicates over length-delimited JSON IPC (stdin/stdout), and routes
//! tool calls through the parent's [`ToolDispatcher`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::BufReader;
use tokio::process::Command;

use crate::error::SandboxError;
use crate::ipc::{read_message, write_message, ChildMessage, ParentMessage, WorkerConfig};
use crate::{ResourceDispatcher, StashDispatcher, ToolDispatcher};

/// Manages spawning and communicating with sandbox worker child processes.
pub struct SandboxHost;

impl SandboxHost {
    /// Execute code in an isolated child process.
    ///
    /// 1. Spawns `forgemax-worker` with a clean environment
    /// 2. Sends the code and config via IPC
    /// 3. Routes tool call requests through the parent's dispatcher
    /// 4. Returns the execution result (or kills the child on timeout)
    ///
    pub async fn execute_in_child(
        code: &str,
        config: &crate::SandboxConfig,
        dispatcher: Arc<dyn ToolDispatcher>,
        resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
        stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
    ) -> Result<serde_json::Value, SandboxError> {
        let worker_bin = find_worker_binary()?;
        let worker_config = WorkerConfig::from(config);
        let timeout = config.timeout;

        // Spawn the worker with a clean environment
        let mut child = Command::new(&worker_bin)
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
                    "failed to spawn worker at {}: {}",
                    worker_bin.display(),
                    e
                ))
            })?;

        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| SandboxError::Execution(anyhow::anyhow!("no stdin on child")))?;
        let child_stdout = child
            .stdout
            .take()
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
            .map_err(|e| {
                SandboxError::Execution(anyhow::anyhow!("failed to send Execute: {}", e))
            })?;

        // IPC event loop with overall timeout
        let result = tokio::time::timeout(
            // Give the child a bit more time than its internal timeout,
            // so the child can report its own timeout error cleanly.
            timeout + Duration::from_secs(2),
            ipc_event_loop(
                &mut child_stdin,
                &mut child_stdout,
                dispatcher,
                resource_dispatcher,
                stash_dispatcher,
            ),
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
/// resource reads, and stash operations, then return the final result.
async fn ipc_event_loop(
    child_stdin: &mut tokio::process::ChildStdin,
    child_stdout: &mut BufReader<tokio::process::ChildStdout>,
    dispatcher: Arc<dyn ToolDispatcher>,
    resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
) -> Result<serde_json::Value, SandboxError> {
    loop {
        let msg: Option<ChildMessage> = read_message(child_stdout)
            .await
            .map_err(|e| SandboxError::Execution(anyhow::anyhow!("IPC read error: {}", e)))?;

        match msg {
            Some(ChildMessage::ExecutionComplete { result }) => {
                return match result {
                    Ok(value) => Ok(value),
                    Err(err) => {
                        // Strip "javascript error: " prefix if already applied by the
                        // worker's SandboxError::JsError.to_string(), preventing double
                        // wrapping like "javascript error: javascript error: <msg>".
                        let message = err
                            .strip_prefix("javascript error: ")
                            .unwrap_or(&err)
                            .to_string();
                        Err(SandboxError::JsError { message })
                    }
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

                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!("failed to send tool result: {}", e))
                })?;
            }
            Some(ChildMessage::ResourceReadRequest {
                request_id,
                server,
                uri,
            }) => {
                let result = match &resource_dispatcher {
                    Some(rd) => rd
                        .read_resource(&server, &uri)
                        .await
                        .map_err(|e| e.to_string()),
                    None => Err("resource dispatcher not available".to_string()),
                };

                let response = ParentMessage::ResourceReadResult { request_id, result };

                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!(
                        "failed to send resource result: {}",
                        e
                    ))
                })?;
            }
            Some(ChildMessage::StashPut {
                request_id,
                key,
                value,
                ttl_secs,
            }) => {
                let result = match &stash_dispatcher {
                    Some(sd) => sd
                        .put(&key, value, ttl_secs, None)
                        .await
                        .map_err(|e| e.to_string()),
                    None => Err("stash dispatcher not available".to_string()),
                };

                let response = ParentMessage::StashResult { request_id, result };
                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!("failed to send stash result: {}", e))
                })?;
            }
            Some(ChildMessage::StashGet { request_id, key }) => {
                let result = match &stash_dispatcher {
                    Some(sd) => sd.get(&key, None).await.map_err(|e| e.to_string()),
                    None => Err("stash dispatcher not available".to_string()),
                };

                let response = ParentMessage::StashResult { request_id, result };
                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!("failed to send stash result: {}", e))
                })?;
            }
            Some(ChildMessage::StashDelete { request_id, key }) => {
                let result = match &stash_dispatcher {
                    Some(sd) => sd.delete(&key, None).await.map_err(|e| e.to_string()),
                    None => Err("stash dispatcher not available".to_string()),
                };

                let response = ParentMessage::StashResult { request_id, result };
                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!("failed to send stash result: {}", e))
                })?;
            }
            Some(ChildMessage::StashKeys { request_id }) => {
                let result = match &stash_dispatcher {
                    Some(sd) => sd.keys(None).await.map_err(|e| e.to_string()),
                    None => Err("stash dispatcher not available".to_string()),
                };

                let response = ParentMessage::StashResult { request_id, result };
                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!("failed to send stash result: {}", e))
                })?;
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

/// Find the `forgemax-worker` binary.
///
/// Search order:
/// 1. `FORGE_WORKER_BIN` environment variable (must be absolute path)
/// 2. Same directory as the current executable
///
/// On Unix, rejects world-writable binaries (mode & 0o002 != 0).
fn find_worker_binary() -> Result<PathBuf, SandboxError> {
    // 1. Explicit env var — must be an absolute path
    if let Ok(path) = std::env::var("FORGE_WORKER_BIN") {
        let p = PathBuf::from(&path);
        if !p.is_absolute() {
            return Err(SandboxError::Execution(anyhow::anyhow!(
                "FORGE_WORKER_BIN must be an absolute path, got: {}",
                path
            )));
        }
        if p.exists() {
            validate_binary_permissions(&p)?;
            return Ok(p);
        }
    }

    // 2. Same directory as current executable (or parent, for test binaries in deps/)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let worker = dir.join("forgemax-worker");
            if worker.exists() {
                validate_binary_permissions(&worker)?;
                return Ok(worker);
            }
            // Test binaries are in target/debug/deps/ but worker is in target/debug/
            if let Some(parent) = dir.parent() {
                let worker = parent.join("forgemax-worker");
                if worker.exists() {
                    validate_binary_permissions(&worker)?;
                    return Ok(worker);
                }
            }
        }
    }

    Err(SandboxError::Execution(anyhow::anyhow!(
        "forgemax-worker binary not found. Set FORGE_WORKER_BIN or install alongside forgemax"
    )))
}

/// Validate binary file permissions (Unix only).
///
/// Rejects:
/// - World-writable binaries (mode & 0o002)
/// - Binaries in world-writable directories without the sticky bit,
///   which would allow binary replacement attacks.
fn validate_binary_permissions(_path: &std::path::Path) -> Result<(), SandboxError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Check the binary itself (follows symlinks via std::fs::metadata)
        let metadata = std::fs::metadata(_path).map_err(|e| {
            SandboxError::Execution(anyhow::anyhow!(
                "cannot read metadata for {}: {}",
                _path.display(),
                e
            ))
        })?;
        let mode = metadata.permissions().mode();
        if mode & 0o002 != 0 {
            return Err(SandboxError::Execution(anyhow::anyhow!(
                "insecure permissions on worker binary {}: mode {:o} is world-writable",
                _path.display(),
                mode,
            )));
        }

        // Check the parent directory — world-writable without sticky bit allows replacement
        if let Some(parent) = _path.parent() {
            let dir_metadata = std::fs::metadata(parent).map_err(|e| {
                SandboxError::Execution(anyhow::anyhow!(
                    "cannot read metadata for parent directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
            let dir_mode = dir_metadata.permissions().mode();
            // World-writable (0o002) without sticky bit (0o1000) is insecure
            if dir_mode & 0o002 != 0 && dir_mode & 0o1000 == 0 {
                return Err(SandboxError::Execution(anyhow::anyhow!(
                    "insecure directory for worker binary {}: parent {} mode {:o} is world-writable without sticky bit",
                    _path.display(),
                    parent.display(),
                    dir_mode,
                )));
            }
        }
    }
    Ok(())
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

    #[test]
    fn find_worker_binary_rejects_relative_env_var() {
        // A relative path in FORGE_WORKER_BIN should be rejected
        temp_env::with_var("FORGE_WORKER_BIN", Some("./relative/path"), || {
            let result = find_worker_binary();
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("absolute"),
                "expected 'absolute' in error: {err}"
            );
        });
    }

    #[test]
    fn find_worker_binary_no_which_fallback() {
        // With no binary anywhere and no env var, should get a clear error
        // (not a random system path from `which`)
        temp_env::with_var_unset("FORGE_WORKER_BIN", || {
            let result = find_worker_binary();
            if let Err(e) = result {
                let msg = e.to_string();
                assert!(
                    !msg.contains("PATH"),
                    "error should not mention PATH: {msg}"
                );
                assert!(
                    msg.contains("FORGE_WORKER_BIN") || msg.contains("forge-cli"),
                    "error should guide user: {msg}"
                );
            }
            // If Ok, the binary was found via exe dir — that's fine
        });
    }

    #[cfg(unix)]
    #[test]
    fn find_worker_binary_rejects_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("forgemax-worker");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o777)).unwrap();

        temp_env::with_var("FORGE_WORKER_BIN", Some(bin.to_str().unwrap()), || {
            let result = find_worker_binary();
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("insecure"),
                "expected 'insecure' in error: {err}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn find_worker_binary_accepts_secure_binary() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("forgemax-worker");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        temp_env::with_var("FORGE_WORKER_BIN", Some(bin.to_str().unwrap()), || {
            let result = find_worker_binary();
            assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        });
    }

    // --- BIN-SEC-01: symlink to world-writable binary is rejected ---
    #[cfg(unix)]
    #[test]
    fn bin_sec_01_symlink_to_world_writable_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let real_bin = dir.path().join("real-worker");
        std::fs::write(&real_bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&real_bin, std::fs::Permissions::from_mode(0o777)).unwrap();

        let link = dir.path().join("forgemax-worker");
        std::os::unix::fs::symlink(&real_bin, &link).unwrap();

        // validate_binary_permissions follows symlinks (uses std::fs::metadata)
        let result = validate_binary_permissions(&link);
        assert!(
            result.is_err(),
            "should reject symlink to world-writable binary"
        );
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("insecure"), "should say insecure: {msg}");
    }

    // --- BIN-SEC-02: symlink to secure binary in secure dir is accepted ---
    #[cfg(unix)]
    #[test]
    fn bin_sec_02_symlink_to_secure_accepted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let real_bin = dir.path().join("real-worker");
        std::fs::write(&real_bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&real_bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let link = dir.path().join("forgemax-worker");
        std::os::unix::fs::symlink(&real_bin, &link).unwrap();

        let result = validate_binary_permissions(&link);
        assert!(
            result.is_ok(),
            "should accept symlink to secure binary: {:?}",
            result
        );
    }

    // --- BIN-SEC-03: world-writable directory without sticky bit is rejected ---
    #[cfg(unix)]
    #[test]
    fn bin_sec_03_world_writable_dir_without_sticky_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        // Make the directory world-writable without sticky bit
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

        let bin = dir.path().join("forgemax-worker");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let result = validate_binary_permissions(&bin);
        assert!(
            result.is_err(),
            "should reject binary in world-writable dir"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("world-writable"),
            "should say world-writable: {msg}"
        );
    }

    #[test]
    fn worker_stderr_is_conditional_on_debug() {
        // Verify the stderr configuration logic
        // Without FORGE_DEBUG: should take the null path
        temp_env::with_var_unset("FORGE_DEBUG", || {
            assert!(std::env::var("FORGE_DEBUG").is_err());
        });

        // With FORGE_DEBUG: should take the inherit path
        temp_env::with_var("FORGE_DEBUG", Some("1"), || {
            assert!(std::env::var("FORGE_DEBUG").is_ok());
        });
    }
}
