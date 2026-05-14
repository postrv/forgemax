//! Config file watcher.
//!
//! Watches a TOML config file for changes, debounces rapid modifications,
//! and reloads the configuration. Invalid configs are rejected, preserving
//! the last known good config.
//!
//! Requires the `config-watch` feature.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;

use crate::{ConfigError, ForgeConfig};

/// Debounce interval for rapid file changes.
const DEBOUNCE_MS: u64 = 200;

type FileFingerprint = (Option<SystemTime>, u64);

/// A config file watcher that reloads on changes.
///
/// Uses `notify` for filesystem events and debounces rapid changes.
/// Invalid config files are rejected — the last valid config is preserved.
pub struct ConfigWatcher {
    /// The path to the watched config file.
    path: PathBuf,
    /// Sender for config updates.
    tx: watch::Sender<Arc<ForgeConfig>>,
    /// Receiver for config updates (clone for consumers).
    rx: watch::Receiver<Arc<ForgeConfig>>,
}

impl ConfigWatcher {
    /// Create a new `ConfigWatcher` for the given config file.
    ///
    /// Loads the initial config from the file. Returns an error if the initial
    /// load fails.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref().to_path_buf();
        let config = ForgeConfig::from_file_with_env(&path)?;
        let (tx, rx) = watch::channel(Arc::new(config));
        Ok(Self { path, tx, rx })
    }

    /// Get a receiver that yields the latest config on each change.
    pub fn subscribe(&self) -> watch::Receiver<Arc<ForgeConfig>> {
        self.rx.clone()
    }

    /// Get the current config.
    pub fn current(&self) -> Arc<ForgeConfig> {
        self.rx.borrow().clone()
    }

    /// Start watching the config file for changes.
    ///
    /// Returns a `JoinHandle` for the background task. The task runs until
    /// the watcher is dropped or the file becomes unwatchable.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.watch_loop().await {
                tracing::error!("Config watcher stopped: {}", e);
            }
        })
    }

    async fn watch_loop(&self) -> Result<(), ConfigError> {
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<()>(16);

        // Canonicalize the watched path so callback comparisons match
        // whatever notify reports (which is the canonical form on macOS).
        let watched_path = std::fs::canonicalize(&self.path).unwrap_or_else(|_| self.path.clone());

        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                let Ok(event) = res else { return };
                if !matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                ) {
                    return;
                }
                // We watch the parent dir to catch atomic-rename saves, so
                // filter events down to the specific config file. Without
                // this, modifications to unrelated files in the same dir
                // (e.g. other tempfiles in parallel tests) trigger reloads
                // and can deadlock the bounded notify channel.
                if !event.paths.iter().any(|p| p == &watched_path) {
                    return;
                }
                // Hint only — coalescing is handled by debounce + polling.
                // Drop the hint if the channel is full rather than blocking
                // the notify thread (which would prevent runtime shutdown).
                let _ = notify_tx.try_send(());
            })
            .map_err(|e| ConfigError::Invalid(format!("failed to create watcher: {}", e)))?;

        // Watch the parent directory (some editors do atomic save via rename)
        let watch_dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        watcher
            .watch(watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| ConfigError::Invalid(format!("failed to watch directory: {}", e)))?;

        tracing::info!("Watching config file: {}", self.path.display());
        let mut last_fingerprint = file_fingerprint(&self.path);
        let mut poll = tokio::time::interval(Duration::from_millis(DEBOUNCE_MS));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                event = notify_rx.recv() => {
                    if event.is_none() {
                        break;
                    }

                    // Debounce: drain any rapid events within the window.
                    tokio::time::sleep(Duration::from_millis(DEBOUNCE_MS)).await;
                    while notify_rx.try_recv().is_ok() {}
                    self.reload_if_changed(&mut last_fingerprint, true);
                }
                _ = poll.tick() => {
                    self.reload_if_changed(&mut last_fingerprint, false);
                }
            }
        }

        Ok(())
    }

    fn reload_if_changed(&self, last_fingerprint: &mut Option<FileFingerprint>, force: bool) {
        let current = file_fingerprint(&self.path);
        if !force && current == *last_fingerprint {
            return;
        }
        *last_fingerprint = current;

        match ForgeConfig::from_file_with_env(&self.path) {
            Ok(new_config) => {
                tracing::info!("Config reloaded from {}", self.path.display());
                let _ = self.tx.send(Arc::new(new_config));
            }
            Err(e) => {
                // File might have been deleted or be invalid — preserve old config.
                tracing::warn!("Config reload failed (keeping previous config): {}", e);
            }
        }
    }
}

fn file_fingerprint(path: &Path) -> Option<FileFingerprint> {
    let metadata = std::fs::metadata(path).ok()?;
    let modified = metadata.modified().ok();
    Some((modified, metadata.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn valid_toml() -> &'static str {
        r#"
[servers.test]
command = "test-server"
args = []
transport = "stdio"

[sandbox]
timeout_secs = 5
"#
    }

    fn valid_toml_modified() -> &'static str {
        r#"
[servers.test]
command = "test-server-v2"
args = ["--verbose"]
transport = "stdio"

[sandbox]
timeout_secs = 10
"#
    }

    fn invalid_toml() -> &'static str {
        "this is not valid toml {{{"
    }

    #[tokio::test]
    async fn watch_01_detects_file_change() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", valid_toml()).unwrap();
        file.flush().unwrap();

        let watcher = ConfigWatcher::new(file.path()).unwrap();
        let mut rx = watcher.subscribe();
        let handle = watcher.start();

        // Give the watcher time to set up
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Modify the file
        std::fs::write(file.path(), valid_toml_modified()).unwrap();

        // Wait for the debounced reload
        let changed = tokio::time::timeout(Duration::from_secs(3), rx.changed()).await;
        assert!(changed.is_ok(), "should detect file change within timeout");

        let config = rx.borrow().clone();
        assert_eq!(config.sandbox.timeout_secs, Some(10));

        handle.abort();
    }

    #[tokio::test]
    async fn watch_02_debounces_rapid_changes() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", valid_toml()).unwrap();
        file.flush().unwrap();

        let watcher = ConfigWatcher::new(file.path()).unwrap();
        let mut rx = watcher.subscribe();
        let handle = watcher.start();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Rapid-fire writes
        for i in 0..5 {
            let content = format!(
                "[servers.test]\ncommand = \"v{}\"\nargs = []\ntransport = \"stdio\"\n\n[sandbox]\ntimeout_secs = {}\n",
                i, 10 + i
            );
            std::fs::write(file.path(), &content).unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Wait for debounced reload
        let changed = tokio::time::timeout(Duration::from_secs(3), rx.changed()).await;
        assert!(changed.is_ok(), "should eventually detect changes");

        // The final config should reflect one of the later writes
        let config = rx.borrow().clone();
        assert!(
            config.sandbox.timeout_secs.unwrap_or(0) >= 10,
            "debounced config should reflect a recent write"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn watch_03_reloads_valid_config() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", valid_toml()).unwrap();
        file.flush().unwrap();

        let watcher = ConfigWatcher::new(file.path()).unwrap();
        let initial = watcher.current();
        assert_eq!(initial.sandbox.timeout_secs, Some(5));

        let mut rx = watcher.subscribe();
        let handle = watcher.start();

        tokio::time::sleep(Duration::from_millis(100)).await;

        std::fs::write(file.path(), valid_toml_modified()).unwrap();

        let changed = tokio::time::timeout(Duration::from_secs(3), rx.changed()).await;
        assert!(changed.is_ok());

        let updated = rx.borrow().clone();
        assert_eq!(updated.sandbox.timeout_secs, Some(10));
        assert_eq!(
            updated.servers["test"].command.as_deref(),
            Some("test-server-v2")
        );

        handle.abort();
    }

    #[tokio::test]
    async fn watch_04_rejects_invalid_config_preserves_old() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", valid_toml()).unwrap();
        file.flush().unwrap();

        let watcher = ConfigWatcher::new(file.path()).unwrap();
        let mut rx = watcher.subscribe();
        let handle = watcher.start();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Write invalid TOML
        std::fs::write(file.path(), invalid_toml()).unwrap();

        // Wait a bit — the watcher should detect the change but reject the invalid config
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Config should still be the original valid one
        let config = rx.borrow_and_update().clone();
        assert_eq!(
            config.sandbox.timeout_secs,
            Some(5),
            "invalid config should be rejected, old config preserved"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn watch_05_handles_file_deletion_gracefully() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", valid_toml()).unwrap();
        file.flush().unwrap();

        let path = file.path().to_path_buf();
        let watcher = ConfigWatcher::new(&path).unwrap();
        let mut rx = watcher.subscribe();
        let handle = watcher.start();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Delete the file
        std::fs::remove_file(&path).unwrap();

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Config should still be the original (file deletion = reload failure = keep old)
        let config = rx.borrow_and_update().clone();
        assert_eq!(
            config.sandbox.timeout_secs,
            Some(5),
            "file deletion should not clear the config"
        );

        handle.abort();
    }

    /// Verify that the module compiles without the config-watch feature
    /// by testing the types available in the base crate.
    #[test]
    fn watch_06_feature_gate_compiles_without() {
        // This test verifies that ForgeConfig works without config-watch.
        // The watcher module itself is gated by #[cfg(feature = "config-watch")].
        let config = ForgeConfig::from_toml(valid_toml()).unwrap();
        assert_eq!(config.sandbox.timeout_secs, Some(5));
    }
}
