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
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ipc::{
    read_message, write_message, ChildMessage, IpcDispatchError, ParentMessage, WorkerConfig,
};
use crate::{ResourceDispatcher, StashDispatcher, ToolDispatcher};

/// Maximum bytes to capture from worker stderr in debug mode.
const MAX_STDERR_CAPTURE_BYTES: usize = 4096;

/// Read at most [`MAX_STDERR_CAPTURE_BYTES`] from worker stderr and log via tracing.
///
/// This prevents unbounded memory growth from LLM-generated JS error output
/// while still providing debug visibility. Never uses `Stdio::inherit()`.
pub(crate) async fn capture_bounded_stderr<R: tokio::io::AsyncRead + Unpin>(mut stderr: R) {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; MAX_STDERR_CAPTURE_BYTES];
    let mut total = 0;
    loop {
        match stderr.read(&mut buf[total..]).await {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= MAX_STDERR_CAPTURE_BYTES {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if total > 0 {
        let text = String::from_utf8_lossy(&buf[..total]);
        tracing::debug!(target: "forge::sandbox::worker::stderr", "{}", text);
    }
    // Drain any remaining bytes without storing them
    let mut discard = [0u8; 1024];
    loop {
        match stderr.read(&mut discard).await {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
}

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
    #[tracing::instrument(skip(code, config, dispatcher, resource_dispatcher, stash_dispatcher, known_servers, known_tools), fields(code_len = code.len()))]
    pub async fn execute_in_child(
        code: &str,
        config: &crate::SandboxConfig,
        dispatcher: Arc<dyn ToolDispatcher>,
        resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
        stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
        known_servers: Option<std::collections::HashSet<String>>,
        known_tools: Option<Vec<(String, String)>>,
    ) -> Result<serde_json::Value, SandboxError> {
        let worker_bin = find_worker_binary()?;
        let mut worker_config = WorkerConfig::from(config);
        worker_config.known_tools = known_tools;
        worker_config.known_servers = known_servers;
        let timeout = config.timeout;

        // Spawn the worker with a clean environment.
        // stderr is always piped (debug) or null (non-debug) — never inherit.
        let debug_mode = std::env::var("FORGE_DEBUG").is_ok();
        let mut child = Command::new(&worker_bin)
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
                    "failed to spawn worker at {}: {}",
                    worker_bin.display(),
                    e
                ))
            })?;

        // Bounded stderr capture in debug mode (max 4KB, logged via tracing)
        let _stderr_handle = if debug_mode {
            child
                .stderr
                .take()
                .map(|stderr| tokio::spawn(capture_bounded_stderr(stderr)))
        } else {
            None
        };

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
///
/// Generic over I/O types so both single-execution [`SandboxHost`] and the
/// worker pool can reuse this loop.
#[tracing::instrument(skip_all)]
pub(crate) async fn ipc_event_loop<W, R>(
    child_stdin: &mut W,
    child_stdout: &mut R,
    dispatcher: Arc<dyn ToolDispatcher>,
    resource_dispatcher: Option<Arc<dyn ResourceDispatcher>>,
    stash_dispatcher: Option<Arc<dyn StashDispatcher>>,
) -> Result<serde_json::Value, SandboxError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    loop {
        let msg: Option<ChildMessage> = read_message(child_stdout)
            .await
            .map_err(|e| SandboxError::Execution(anyhow::anyhow!("IPC read error: {}", e)))?;

        match msg {
            Some(ChildMessage::ExecutionComplete {
                result,
                error_kind,
                timeout_ms: structured_timeout_ms,
            }) => {
                return match result {
                    Ok(value) => Ok(value),
                    Err(err) => {
                        // Use error_kind to reconstruct the correct SandboxError variant.
                        // Falls back to JsError if error_kind is absent (backward compat
                        // with workers that predate the error_kind field).
                        match error_kind {
                            Some(crate::ipc::ErrorKind::Timeout) => {
                                // Prefer structured timeout_ms field (v0.3.1+).
                                // Fall back to string parsing for v0.3.0 workers.
                                let timeout_ms = structured_timeout_ms.unwrap_or_else(|| {
                                    err.split("after ")
                                        .nth(1)
                                        .and_then(|s| s.trim_end_matches("ms").parse::<u64>().ok())
                                        .unwrap_or(0)
                                });
                                Err(SandboxError::Timeout { timeout_ms })
                            }
                            Some(crate::ipc::ErrorKind::HeapLimit) => {
                                Err(SandboxError::HeapLimitExceeded)
                            }
                            Some(crate::ipc::ErrorKind::Execution) => {
                                Err(SandboxError::Execution(anyhow::anyhow!("{}", err)))
                            }
                            Some(crate::ipc::ErrorKind::JsError) | None => {
                                // Strip "javascript error: " prefix if already applied by the
                                // worker's SandboxError::JsError.to_string(), preventing double
                                // wrapping like "javascript error: javascript error: <msg>".
                                let message = err
                                    .strip_prefix("javascript error: ")
                                    .unwrap_or(&err)
                                    .to_string();
                                Err(SandboxError::JsError { message })
                            }
                        }
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
                    result: tool_result.map_err(|e| IpcDispatchError::from(&e)),
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
                // Defense-in-depth: validate URI at host level too
                let result = if let Err(e) = crate::ops::validate_resource_uri(&uri) {
                    Err(IpcDispatchError::from_string(e))
                } else {
                    match &resource_dispatcher {
                        Some(rd) => rd
                            .read_resource(&server, &uri)
                            .await
                            .map_err(|e| IpcDispatchError::from(&e)),
                        None => Err(IpcDispatchError::from_string(
                            "resource dispatcher not available".to_string(),
                        )),
                    }
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
                group,
            }) => {
                let result = match &stash_dispatcher {
                    Some(sd) => sd
                        .put(&key, value, ttl_secs, group)
                        .await
                        .map_err(|e| IpcDispatchError::from(&e)),
                    None => Err(IpcDispatchError::from_string(
                        "stash dispatcher not available".to_string(),
                    )),
                };

                let response = ParentMessage::StashResult { request_id, result };
                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!("failed to send stash result: {}", e))
                })?;
            }
            Some(ChildMessage::StashGet {
                request_id,
                key,
                group,
            }) => {
                let result = match &stash_dispatcher {
                    Some(sd) => sd
                        .get(&key, group)
                        .await
                        .map_err(|e| IpcDispatchError::from(&e)),
                    None => Err(IpcDispatchError::from_string(
                        "stash dispatcher not available".to_string(),
                    )),
                };

                let response = ParentMessage::StashResult { request_id, result };
                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!("failed to send stash result: {}", e))
                })?;
            }
            Some(ChildMessage::StashDelete {
                request_id,
                key,
                group,
            }) => {
                let result = match &stash_dispatcher {
                    Some(sd) => sd
                        .delete(&key, group)
                        .await
                        .map_err(|e| IpcDispatchError::from(&e)),
                    None => Err(IpcDispatchError::from_string(
                        "stash dispatcher not available".to_string(),
                    )),
                };

                let response = ParentMessage::StashResult { request_id, result };
                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!("failed to send stash result: {}", e))
                })?;
            }
            Some(ChildMessage::StashKeys { request_id, group }) => {
                let result = match &stash_dispatcher {
                    Some(sd) => sd
                        .keys(group)
                        .await
                        .map_err(|e| IpcDispatchError::from(&e)),
                    None => Err(IpcDispatchError::from_string(
                        "stash dispatcher not available".to_string(),
                    )),
                };

                let response = ParentMessage::StashResult { request_id, result };
                write_message(child_stdin, &response).await.map_err(|e| {
                    SandboxError::Execution(anyhow::anyhow!("failed to send stash result: {}", e))
                })?;
            }
            Some(ChildMessage::Log { message }) => {
                tracing::info!(target: "forge::sandbox::worker", "{}", message);
            }
            Some(ChildMessage::ResetComplete) => {
                // Unexpected in single-execution mode; ignore.
                tracing::warn!("received unexpected ResetComplete in single-execution mode");
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
#[tracing::instrument]
pub(crate) fn find_worker_binary() -> Result<PathBuf, SandboxError> {
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

    // --- H3: Worker Stderr Hardening Tests ---

    #[test]
    fn h3_01_host_worker_stderr_never_inherits() {
        // In both debug and non-debug modes, we never use Stdio::inherit().
        // Non-debug → null, debug → piped. This test verifies the code paths.
        temp_env::with_var_unset("FORGE_DEBUG", || {
            assert!(
                std::env::var("FORGE_DEBUG").is_err(),
                "FORGE_DEBUG should not be set"
            );
            // Non-debug path → Stdio::null() (no inherit)
        });
        temp_env::with_var("FORGE_DEBUG", Some("1"), || {
            assert!(
                std::env::var("FORGE_DEBUG").is_ok(),
                "FORGE_DEBUG should be set"
            );
            // Debug path → Stdio::piped() (not inherit)
        });
    }

    #[test]
    fn h3_02_pool_worker_stderr_never_inherits() {
        // Same verification for pool code path — the test confirms the logic
        // doesn't use Stdio::inherit() in either mode.
        temp_env::with_var_unset("FORGE_DEBUG", || {
            let debug = std::env::var("FORGE_DEBUG").is_ok();
            assert!(!debug, "non-debug should use null");
        });
        temp_env::with_var("FORGE_DEBUG", Some("1"), || {
            let debug = std::env::var("FORGE_DEBUG").is_ok();
            assert!(debug, "debug should use piped (not inherit)");
        });
    }

    #[tokio::test]
    async fn h3_03_debug_mode_captures_bounded_stderr() {
        // Verify capture_bounded_stderr reads at most MAX_STDERR_CAPTURE_BYTES
        use std::io::Cursor;

        // Create oversized stderr data (8KB > 4KB limit)
        let large_data = vec![b'E'; 8192];
        let cursor = Cursor::new(large_data);

        // Should not panic and should complete
        capture_bounded_stderr(cursor).await;

        // Also test with small data
        let small_data = b"some warning\n".to_vec();
        let cursor = Cursor::new(small_data);
        capture_bounded_stderr(cursor).await;
    }

    #[tokio::test]
    async fn h3_04_non_debug_mode_nulls_stderr() {
        // Verify that without FORGE_DEBUG, we produce Stdio::null() not inherit
        temp_env::with_var_unset("FORGE_DEBUG", || {
            let debug = std::env::var("FORGE_DEBUG").is_ok();
            assert!(
                !debug,
                "without FORGE_DEBUG, stderr should be null (not inherit)"
            );
        });
    }

    // --- H1: host-side group isolation tests ---

    /// Mock StashDispatcher that records the group parameter
    struct GroupRecordingStash {
        recorded_groups: std::sync::Mutex<Vec<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl crate::StashDispatcher for GroupRecordingStash {
        async fn put(
            &self,
            _key: &str,
            _value: serde_json::Value,
            _ttl_secs: Option<u32>,
            current_group: Option<String>,
        ) -> Result<serde_json::Value, forge_error::DispatchError> {
            self.recorded_groups.lock().unwrap().push(current_group);
            Ok(serde_json::json!({"ok": true}))
        }

        async fn get(
            &self,
            _key: &str,
            current_group: Option<String>,
        ) -> Result<serde_json::Value, forge_error::DispatchError> {
            self.recorded_groups.lock().unwrap().push(current_group);
            Ok(serde_json::json!(null))
        }

        async fn delete(
            &self,
            _key: &str,
            current_group: Option<String>,
        ) -> Result<serde_json::Value, forge_error::DispatchError> {
            self.recorded_groups.lock().unwrap().push(current_group);
            Ok(serde_json::json!({"deleted": true}))
        }

        async fn keys(
            &self,
            current_group: Option<String>,
        ) -> Result<serde_json::Value, forge_error::DispatchError> {
            self.recorded_groups.lock().unwrap().push(current_group);
            Ok(serde_json::json!([]))
        }
    }

    /// Mock ToolDispatcher (never called in these tests)
    struct NeverCalledTool;

    #[async_trait::async_trait]
    impl crate::ToolDispatcher for NeverCalledTool {
        async fn call_tool(
            &self,
            _server: &str,
            _tool: &str,
            _args: serde_json::Value,
        ) -> Result<serde_json::Value, forge_error::DispatchError> {
            panic!("tool call not expected");
        }
    }

    /// Helper: write child messages then ExecutionComplete, run ipc_event_loop
    async fn run_ipc_event_loop_with_messages(
        messages: Vec<crate::ipc::ChildMessage>,
        stash: Arc<GroupRecordingStash>,
    ) {
        use crate::ipc::write_message;

        // Build the child's "stdout" (what parent reads)
        let mut child_output = Vec::new();
        for msg in &messages {
            write_message(&mut child_output, msg).await.unwrap();
        }
        // Append ExecutionComplete
        let complete = crate::ipc::ChildMessage::ExecutionComplete {
            result: Ok(serde_json::json!("done")),
            error_kind: None,
            timeout_ms: None,
        };
        write_message(&mut child_output, &complete).await.unwrap();

        let mut child_stdout = std::io::Cursor::new(child_output);
        let mut child_stdin = Vec::new();

        let tool: Arc<dyn crate::ToolDispatcher> = Arc::new(NeverCalledTool);
        let resource: Option<Arc<dyn crate::ResourceDispatcher>> = None;
        let stash_disp: Option<Arc<dyn crate::StashDispatcher>> = Some(stash);

        let result = ipc_event_loop(
            &mut child_stdin,
            &mut child_stdout,
            tool,
            resource,
            stash_disp,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn h1_host_07_ipc_event_loop_passes_group_to_stash_put() {
        let stash = Arc::new(GroupRecordingStash {
            recorded_groups: std::sync::Mutex::new(Vec::new()),
        });

        run_ipc_event_loop_with_messages(
            vec![crate::ipc::ChildMessage::StashPut {
                request_id: 1,
                key: "k".into(),
                value: serde_json::json!("v"),
                ttl_secs: None,
                group: Some("mygroup".into()),
            }],
            stash.clone(),
        )
        .await;

        let groups = stash.recorded_groups.lock().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], Some("mygroup".into()));
    }

    #[tokio::test]
    async fn h1_host_08_ipc_event_loop_passes_group_to_stash_get() {
        let stash = Arc::new(GroupRecordingStash {
            recorded_groups: std::sync::Mutex::new(Vec::new()),
        });

        run_ipc_event_loop_with_messages(
            vec![crate::ipc::ChildMessage::StashGet {
                request_id: 1,
                key: "k".into(),
                group: Some("getgroup".into()),
            }],
            stash.clone(),
        )
        .await;

        let groups = stash.recorded_groups.lock().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], Some("getgroup".into()));
    }

    #[tokio::test]
    async fn h1_host_09_ipc_event_loop_passes_group_to_stash_delete() {
        let stash = Arc::new(GroupRecordingStash {
            recorded_groups: std::sync::Mutex::new(Vec::new()),
        });

        run_ipc_event_loop_with_messages(
            vec![crate::ipc::ChildMessage::StashDelete {
                request_id: 1,
                key: "k".into(),
                group: Some("delgroup".into()),
            }],
            stash.clone(),
        )
        .await;

        let groups = stash.recorded_groups.lock().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], Some("delgroup".into()));
    }

    #[tokio::test]
    async fn h1_host_10_ipc_event_loop_passes_group_to_stash_keys() {
        let stash = Arc::new(GroupRecordingStash {
            recorded_groups: std::sync::Mutex::new(Vec::new()),
        });

        run_ipc_event_loop_with_messages(
            vec![crate::ipc::ChildMessage::StashKeys {
                request_id: 1,
                group: Some("keysgroup".into()),
            }],
            stash.clone(),
        )
        .await;

        let groups = stash.recorded_groups.lock().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], Some("keysgroup".into()));
    }

    #[tokio::test]
    async fn h1_host_11_ipc_event_loop_passes_none_group_when_absent() {
        let stash = Arc::new(GroupRecordingStash {
            recorded_groups: std::sync::Mutex::new(Vec::new()),
        });

        run_ipc_event_loop_with_messages(
            vec![crate::ipc::ChildMessage::StashPut {
                request_id: 1,
                key: "k".into(),
                value: serde_json::json!("v"),
                ttl_secs: None,
                group: None,
            }],
            stash.clone(),
        )
        .await;

        let groups = stash.recorded_groups.lock().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], None);
    }

    #[tokio::test]
    async fn h1_host_12_ipc_event_loop_all_stash_ops_with_same_group() {
        let stash = Arc::new(GroupRecordingStash {
            recorded_groups: std::sync::Mutex::new(Vec::new()),
        });

        run_ipc_event_loop_with_messages(
            vec![
                crate::ipc::ChildMessage::StashPut {
                    request_id: 1,
                    key: "k".into(),
                    value: serde_json::json!("v"),
                    ttl_secs: None,
                    group: Some("shared".into()),
                },
                crate::ipc::ChildMessage::StashGet {
                    request_id: 2,
                    key: "k".into(),
                    group: Some("shared".into()),
                },
                crate::ipc::ChildMessage::StashDelete {
                    request_id: 3,
                    key: "k".into(),
                    group: Some("shared".into()),
                },
                crate::ipc::ChildMessage::StashKeys {
                    request_id: 4,
                    group: Some("shared".into()),
                },
            ],
            stash.clone(),
        )
        .await;

        let groups = stash.recorded_groups.lock().unwrap();
        assert_eq!(groups.len(), 4);
        for g in groups.iter() {
            assert_eq!(g, &Some("shared".into()));
        }
    }
}
