//! Lock-free live manifest for dynamic tool discovery.
//!
//! [`LiveManifest`] wraps [`arc_swap::ArcSwap`] to provide lock-free reads
//! and atomic swaps. Background tasks can call [`update()`](LiveManifest::update)
//! to refresh the manifest without blocking concurrent `search()` or `execute()`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::Manifest;

/// The discovery view and exact MCP tool names published together.
#[derive(Clone)]
pub struct ManifestSnapshot {
    /// The catalog exposed to search.
    pub manifest: Arc<Manifest>,
    /// Exact downstream tool names keyed by configured server name.
    ///
    /// The discovery view may shorten or sanitize names for display.
    pub tool_names: HashMap<String, HashSet<String>>,
}

/// A live, atomically-swappable manifest.
///
/// Readers call [`current()`](Self::current) for a lock-free snapshot.
/// Writers call [`update()`](Self::update) for an atomic swap.
///
/// ```
/// use forge_manifest::{Manifest, LiveManifest};
/// let live = LiveManifest::new(Manifest::new());
/// let snapshot = live.current();
/// assert_eq!(snapshot.total_servers(), 0);
/// ```
#[derive(Clone)]
pub struct LiveManifest {
    inner: Arc<ArcSwap<ManifestSnapshot>>,
}

impl From<Manifest> for LiveManifest {
    fn from(manifest: Manifest) -> Self {
        Self::new(manifest)
    }
}

impl LiveManifest {
    /// Create a live manifest used for discovery alone.
    pub fn new(manifest: Manifest) -> Self {
        Self::from_snapshot(ManifestSnapshot {
            manifest: Arc::new(manifest),
            tool_names: HashMap::new(),
        })
    }

    /// Create a live manifest with its exact dispatch names.
    pub fn from_snapshot(snapshot: ManifestSnapshot) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(snapshot)),
        }
    }

    /// Read the manifest and dispatch names from the same atomic snapshot.
    pub fn snapshot(&self) -> Arc<ManifestSnapshot> {
        self.inner.load_full()
    }

    /// Get a lock-free snapshot of the current manifest.
    ///
    /// This is wait-free and never blocks, even if another thread is
    /// updating the manifest concurrently.
    pub fn current(&self) -> Arc<Manifest> {
        self.inner.load().manifest.clone()
    }

    /// Atomically replace both the discovery view and the dispatch names.
    pub fn publish(&self, snapshot: ManifestSnapshot) {
        self.inner.store(Arc::new(snapshot));
    }

    /// Atomically replace a discovery-only manifest with a new version.
    ///
    /// All subsequent calls to [`current()`](Self::current) will see the
    /// new manifest. Readers holding an older `Arc<Manifest>` are unaffected.
    pub fn update(&self, new_manifest: Manifest) {
        self.publish(ManifestSnapshot {
            manifest: Arc::new(new_manifest),
            tool_names: HashMap::new(),
        });
    }

    /// Load a clone of the inner `Arc` pointer (for passing to subsystems
    /// that need their own reference).
    pub fn load_arc(&self) -> Arc<Manifest> {
        self.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ManifestBuilder, ServerBuilder};

    #[test]
    fn dm_01_new_creates_with_initial_value() {
        let live = LiveManifest::new(Manifest::new());
        assert_eq!(live.current().total_servers(), 0);
    }

    #[test]
    fn dm_02_update_swaps_atomically() {
        let live = LiveManifest::new(Manifest::new());
        assert_eq!(live.current().total_servers(), 0);

        let new_manifest = ManifestBuilder::new()
            .add_server(ServerBuilder::new("test", "Test server").build())
            .build();
        live.update(new_manifest);

        assert_eq!(live.current().total_servers(), 1);
        assert_eq!(live.current().servers[0].name, "test");
    }

    #[test]
    fn dm_03_old_snapshot_unaffected_by_update() {
        let live = LiveManifest::new(Manifest::new());
        let old_snapshot = live.current();

        let new_manifest = ManifestBuilder::new()
            .add_server(ServerBuilder::new("new", "New server").build())
            .build();
        live.update(new_manifest);

        // Old snapshot still sees 0 servers
        assert_eq!(old_snapshot.total_servers(), 0);
        // New snapshot sees 1 server
        assert_eq!(live.current().total_servers(), 1);
    }

    #[test]
    fn dm_04_clone_shares_same_underlying_data() {
        let live = LiveManifest::new(Manifest::new());
        let cloned = live.clone();

        let new_manifest = ManifestBuilder::new()
            .add_server(ServerBuilder::new("shared", "Shared server").build())
            .build();
        live.update(new_manifest);

        // Cloned reference sees the update
        assert_eq!(cloned.current().total_servers(), 1);
    }

    #[test]
    fn dm_05_concurrent_reads_during_update() {
        let live = LiveManifest::new(Manifest::new());

        // Simulate concurrent reads by taking multiple snapshots
        let snap1 = live.current();
        let snap2 = live.current();

        live.update(
            ManifestBuilder::new()
                .add_server(ServerBuilder::new("s", "S").build())
                .build(),
        );

        let snap3 = live.current();

        // Pre-update snapshots: 0 servers
        assert_eq!(snap1.total_servers(), 0);
        assert_eq!(snap2.total_servers(), 0);
        // Post-update snapshot: 1 server
        assert_eq!(snap3.total_servers(), 1);
    }

    #[test]
    fn dm_06_multiple_updates_last_wins() {
        let live = LiveManifest::new(Manifest::new());

        for i in 0..5 {
            let m = ManifestBuilder::new()
                .add_server(ServerBuilder::new(format!("s{i}"), "desc").build())
                .build();
            live.update(m);
        }

        assert_eq!(live.current().total_servers(), 1);
        assert_eq!(live.current().servers[0].name, "s4");
    }

    #[test]
    fn dm_07_load_arc_returns_same_as_current() {
        let live = LiveManifest::new(
            ManifestBuilder::new()
                .add_server(ServerBuilder::new("x", "X").build())
                .build(),
        );
        let arc1 = live.current();
        let arc2 = live.load_arc();
        assert_eq!(arc1.total_servers(), arc2.total_servers());
    }
}
