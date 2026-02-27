//! Session stash — a per-session key/value store with TTL and group isolation.
//!
//! The stash lets sandbox executions persist data across calls within the same
//! session. Entries are scoped to a server group (optional) and expire after a
//! configurable TTL.
//!
//! # Group access rules
//!
//! - `source_group = None` → readable by **any** execution (public within session)
//! - `source_group = Some("A")`, `current_group = Some("A")` → OK (same group)
//! - `source_group = Some("A")`, `current_group = Some("B")` → [`StashError::CrossGroupAccess`]
//! - `source_group = Some("A")`, `current_group = None` → [`StashError::CrossGroupAccess`]

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::Value;

/// Key validation regex: alphanumerics plus `_`, `-`, `.`, `:`, 1–256 chars.
static KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_\-.:]{1,256}$").expect("static regex is valid"));

/// Configuration for the session stash.
#[derive(Debug, Clone)]
pub struct StashConfig {
    /// Maximum number of distinct keys (default: 256).
    pub max_keys: usize,
    /// Maximum size of a single value when JSON-serialised in bytes (default: 16 MiB).
    pub max_value_size: usize,
    /// Maximum combined size of all values in bytes (default: 128 MiB).
    pub max_total_size: usize,
    /// TTL applied when a caller does not specify one (default: 1 hour).
    pub default_ttl: Duration,
    /// Hard ceiling on caller-supplied TTLs (default: 24 hours).
    pub max_ttl: Duration,
}

impl Default for StashConfig {
    fn default() -> Self {
        Self {
            max_keys: 256,
            max_value_size: 16 * 1024 * 1024,
            max_total_size: 128 * 1024 * 1024,
            default_ttl: Duration::from_secs(3600),
            max_ttl: Duration::from_secs(86400),
        }
    }
}

/// A single entry stored in the stash.
struct StashEntry {
    value: Value,
    size_bytes: usize,
    created_at: Instant,
    ttl: Duration,
    source_group: Option<String>,
}

impl StashEntry {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }
}

/// Per-session key/value store with TTL-based expiry and group isolation.
pub struct SessionStash {
    entries: HashMap<String, StashEntry>,
    total_size: usize,
    config: StashConfig,
}

/// Errors returned by [`SessionStash`] operations.
#[derive(Debug, thiserror::Error)]
pub enum StashError {
    /// The stash already holds the maximum number of keys.
    #[error("stash key limit exceeded (max {max} keys)")]
    KeyLimitExceeded {
        /// Configured maximum.
        max: usize,
    },
    /// The serialised value exceeds the per-value size limit.
    #[error("stash value too large ({size} bytes, max {max} bytes)")]
    ValueTooLarge {
        /// Actual size.
        size: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Adding the value would push total stash size past the limit.
    #[error("stash total size exceeded ({total} bytes, max {max} bytes)")]
    TotalSizeExceeded {
        /// Projected total.
        total: usize,
        /// Configured maximum.
        max: usize,
    },
    /// The key exceeds 256 characters.
    #[error("stash key too long ({len} chars, max 256)")]
    KeyTooLong {
        /// Actual length.
        len: usize,
    },
    /// The key contains characters outside `[a-zA-Z0-9_\-.:]{1,256}`.
    #[error("stash key contains invalid characters")]
    InvalidKey,
    /// The caller-supplied TTL exceeds `max_ttl`.
    #[error("stash TTL exceeds maximum ({requested_secs}s, max {max_secs}s)")]
    TtlTooLong {
        /// Requested TTL in seconds.
        requested_secs: u64,
        /// Configured maximum TTL in seconds.
        max_secs: u64,
    },
    /// The current execution belongs to a different group than the entry.
    #[error(
        "cross-group stash access denied: entry belongs to group '{entry_group}', \
         current execution is in group '{current_group}'"
    )]
    CrossGroupAccess {
        /// Group that owns the entry.
        entry_group: String,
        /// Group (or representation of ungrouped) attempting access.
        current_group: String,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate a stash key, returning an appropriate error on failure.
pub(crate) fn validate_key(key: &str) -> Result<(), StashError> {
    if key.is_empty() {
        return Err(StashError::InvalidKey);
    }
    if key.len() > 256 {
        return Err(StashError::KeyTooLong { len: key.len() });
    }
    if !KEY_RE.is_match(key) {
        return Err(StashError::InvalidKey);
    }
    Ok(())
}

/// Check whether `current_group` may access an entry owned by `source_group`.
fn check_group_read(
    source_group: &Option<String>,
    current_group: Option<&str>,
) -> Result<(), StashError> {
    match source_group {
        None => Ok(()), // public entry — anyone may read
        Some(entry_group) => match current_group {
            Some(cg) if cg == entry_group => Ok(()),
            other => Err(StashError::CrossGroupAccess {
                entry_group: entry_group.clone(),
                current_group: other.unwrap_or("<ungrouped>").to_string(),
            }),
        },
    }
}

// ---------------------------------------------------------------------------
// SessionStash implementation
// ---------------------------------------------------------------------------

impl SessionStash {
    /// Create a new stash with the given configuration.
    pub fn new(config: StashConfig) -> Self {
        Self {
            entries: HashMap::new(),
            total_size: 0,
            config,
        }
    }

    /// Store a value under `key`.
    ///
    /// If the key already exists its value is replaced and size accounting is
    /// updated accordingly. The `current_group` is recorded as the entry's
    /// owner — future reads from other groups will be denied.
    ///
    /// # Errors
    ///
    /// Returns [`StashError`] if any limit is exceeded or the key is invalid.
    pub fn put(
        &mut self,
        key: &str,
        value: Value,
        ttl: Option<Duration>,
        current_group: Option<&str>,
    ) -> Result<(), StashError> {
        // --- Key validation ---
        validate_key(key)?;

        // --- Value size ---
        let serialised = serde_json::to_vec(&value).unwrap_or_default();
        let value_size = serialised.len();
        if value_size > self.config.max_value_size {
            return Err(StashError::ValueTooLarge {
                size: value_size,
                max: self.config.max_value_size,
            });
        }

        // --- TTL validation ---
        let effective_ttl = match ttl {
            Some(d) => {
                if d.is_zero() {
                    return Err(StashError::TtlTooLong {
                        requested_secs: 0,
                        max_secs: self.config.max_ttl.as_secs(),
                    });
                }
                if d > self.config.max_ttl {
                    return Err(StashError::TtlTooLong {
                        requested_secs: d.as_secs(),
                        max_secs: self.config.max_ttl.as_secs(),
                    });
                }
                d
            }
            None => self.config.default_ttl,
        };

        // --- Replace vs. new key ---
        let is_replacement = self.entries.contains_key(key);
        if is_replacement {
            // Subtract old size before checking limits
            let old_size = self.entries[key].size_bytes;
            self.total_size -= old_size;
        } else {
            // Only check key count for brand-new keys
            if self.entries.len() >= self.config.max_keys {
                return Err(StashError::KeyLimitExceeded {
                    max: self.config.max_keys,
                });
            }
        }

        // --- Total size check ---
        let new_total = self.total_size + value_size;
        if new_total > self.config.max_total_size {
            // Roll back the subtraction we did for a replacement
            if is_replacement {
                self.total_size += self.entries[key].size_bytes;
            }
            return Err(StashError::TotalSizeExceeded {
                total: new_total,
                max: self.config.max_total_size,
            });
        }

        // --- Commit ---
        self.total_size = new_total;
        self.entries.insert(
            key.to_string(),
            StashEntry {
                value,
                size_bytes: value_size,
                created_at: Instant::now(),
                ttl: effective_ttl,
                source_group: current_group.map(str::to_string),
            },
        );
        Ok(())
    }

    /// Retrieve the value stored under `key`.
    ///
    /// Returns `Ok(None)` if the key does not exist or has expired.
    ///
    /// # Errors
    ///
    /// Returns [`StashError::CrossGroupAccess`] if the entry is owned by a
    /// different group than `current_group`.
    pub fn get(
        &self,
        key: &str,
        current_group: Option<&str>,
    ) -> Result<Option<&Value>, StashError> {
        match self.entries.get(key) {
            None => Ok(None),
            Some(entry) if entry.is_expired() => Ok(None),
            Some(entry) => {
                check_group_read(&entry.source_group, current_group)?;
                Ok(Some(&entry.value))
            }
        }
    }

    /// Remove the entry stored under `key`.
    ///
    /// Returns `Ok(true)` if the entry was present and removed, `Ok(false)` if
    /// the key did not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StashError::CrossGroupAccess`] if the entry is owned by a
    /// different group.
    pub fn delete(&mut self, key: &str, current_group: Option<&str>) -> Result<bool, StashError> {
        match self.entries.get(key) {
            None => Ok(false),
            Some(entry) => {
                check_group_read(&entry.source_group, current_group)?;
                let size = entry.size_bytes;
                self.entries.remove(key);
                self.total_size -= size;
                Ok(true)
            }
        }
    }

    /// Return the keys currently visible to `current_group`.
    ///
    /// Expired entries and entries belonging to a different strict group are
    /// excluded.
    pub fn keys(&self, current_group: Option<&str>) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(_, entry)| {
                if entry.is_expired() {
                    return false;
                }
                // Apply group visibility rules (same logic as get, but no error)
                match &entry.source_group {
                    None => true, // public entry
                    Some(eg) => match current_group {
                        Some(cg) => cg == eg,
                        None => false, // ungrouped can't see grouped entries
                    },
                }
            })
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// Remove all expired entries and return how many were removed.
    pub fn reap_expired(&mut self) -> usize {
        let before = self.entries.len();
        let to_remove: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired())
            .map(|(k, _)| k.clone())
            .collect();
        for key in &to_remove {
            if let Some(e) = self.entries.remove(key) {
                self.total_size -= e.size_bytes;
            }
        }
        before - self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;

    fn default_stash() -> SessionStash {
        SessionStash::new(StashConfig::default())
    }

    // ST-U01: put() stores value and get() retrieves it
    #[test]
    fn st_u01_put_and_get() {
        let mut stash = default_stash();
        stash
            .put("key1", json!({"hello": "world"}), None, None)
            .unwrap();
        let v = stash.get("key1", None).unwrap().unwrap();
        assert_eq!(v, &json!({"hello": "world"}));
    }

    // ST-U02: put() replaces existing key (updates size accounting)
    #[test]
    fn st_u02_put_replaces_existing_key() {
        let mut stash = default_stash();
        stash
            .put("k", json!("a big string that takes space"), None, None)
            .unwrap();
        let size_after_first = stash.total_size;
        stash.put("k", json!(1), None, None).unwrap();
        let size_after_second = stash.total_size;
        assert!(
            size_after_second < size_after_first,
            "total_size should shrink when replacing with smaller value"
        );
        let v = stash.get("k", None).unwrap().unwrap();
        assert_eq!(v, &json!(1));
    }

    // ST-U03: put() rejects key exceeding 256 chars
    #[test]
    fn st_u03_put_rejects_key_too_long() {
        let mut stash = default_stash();
        let long_key = "a".repeat(257);
        let err = stash.put(&long_key, json!(null), None, None).unwrap_err();
        assert!(matches!(err, StashError::KeyTooLong { len: 257 }));
    }

    // ST-U04: put() rejects key with invalid characters (spaces, slashes, null bytes)
    #[test]
    fn st_u04_put_rejects_invalid_key_characters() {
        let mut stash = default_stash();
        for bad in &["key with space", "key/slash", "key\0null"] {
            let err = stash.put(bad, json!(null), None, None).unwrap_err();
            assert!(
                matches!(err, StashError::InvalidKey),
                "expected InvalidKey for {:?}",
                bad
            );
        }
    }

    // Key with trailing invalid char rejected (validates $ end anchor)
    #[test]
    fn st_key_regex_rejects_trailing_invalid_char() {
        let mut stash = default_stash();
        let err = stash
            .put("valid_key!", json!(null), None, None)
            .unwrap_err();
        assert!(
            matches!(err, StashError::InvalidKey),
            "expected InvalidKey for key with trailing '!', got: {err}"
        );
    }

    // ST-U05: put() rejects value exceeding max_value_size
    #[test]
    fn st_u05_put_rejects_oversized_value() {
        let config = StashConfig {
            max_value_size: 10,
            ..Default::default()
        };
        let mut stash = SessionStash::new(config);
        // A string with 11+ chars will serialise to more than 10 bytes
        let big_value = json!("this is definitely more than ten bytes");
        let err = stash.put("k", big_value, None, None).unwrap_err();
        assert!(matches!(err, StashError::ValueTooLarge { .. }));
    }

    // ST-U06: put() rejects when total_size would exceed max_total_size
    #[test]
    fn st_u06_put_rejects_when_total_size_exceeded() {
        // max_total_size is 30 bytes, max_value_size is 100 bytes so individual
        // values pass the per-value check but the combination exceeds the total.
        let config = StashConfig {
            max_total_size: 30,
            max_value_size: 100,
            ..Default::default()
        };
        let mut stash = SessionStash::new(config);
        // First put — "12345" serialises as "\"12345\"" = 7 bytes, fits fine
        stash.put("k1", json!("12345"), None, None).unwrap();
        // Second put — "abcdefghijklmnopqrstuvwxyz" = 28 bytes serialised;
        // combined with k1 that's ~35 bytes which exceeds max_total_size=30
        let err = stash
            .put("k2", json!("abcdefghijklmnopqrstuvwxyz"), None, None)
            .unwrap_err();
        assert!(matches!(err, StashError::TotalSizeExceeded { .. }));
    }

    // ST-U07: put() rejects when key count exceeds max_keys
    #[test]
    fn st_u07_put_rejects_when_key_count_exceeded() {
        let config = StashConfig {
            max_keys: 2,
            ..Default::default()
        };
        let mut stash = SessionStash::new(config);
        stash.put("k1", json!(1), None, None).unwrap();
        stash.put("k2", json!(2), None, None).unwrap();
        let err = stash.put("k3", json!(3), None, None).unwrap_err();
        assert!(matches!(err, StashError::KeyLimitExceeded { max: 2 }));
    }

    // ST-U08: put() rejects TTL exceeding max_ttl
    #[test]
    fn st_u08_put_rejects_ttl_exceeding_max() {
        let config = StashConfig {
            max_ttl: Duration::from_secs(60),
            ..Default::default()
        };
        let mut stash = SessionStash::new(config);
        let err = stash
            .put("k", json!(1), Some(Duration::from_secs(61)), None)
            .unwrap_err();
        assert!(matches!(err, StashError::TtlTooLong { .. }));
    }

    // ST-U09: get() returns None for nonexistent key
    #[test]
    fn st_u09_get_returns_none_for_missing_key() {
        let stash = default_stash();
        assert!(stash.get("no-such-key", None).unwrap().is_none());
    }

    // ST-U10: get() returns None for expired key
    #[test]
    fn st_u10_get_returns_none_for_expired_key() {
        let mut stash = default_stash();
        stash
            .put("k", json!("v"), Some(Duration::from_millis(1)), None)
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(stash.get("k", None).unwrap().is_none());
    }

    // ST-U11: get() returns CrossGroupAccess error for different strict group
    #[test]
    fn st_u11_get_cross_group_access_denied() {
        let mut stash = default_stash();
        stash.put("k", json!(1), None, Some("group-a")).unwrap();
        let err = stash.get("k", Some("group-b")).unwrap_err();
        assert!(
            matches!(err, StashError::CrossGroupAccess { .. }),
            "unexpected error: {err}"
        );
    }

    // ST-U12: get() allows access from same strict group
    #[test]
    fn st_u12_get_same_group_allowed() {
        let mut stash = default_stash();
        stash.put("k", json!(42), None, Some("team-a")).unwrap();
        let v = stash.get("k", Some("team-a")).unwrap().unwrap();
        assert_eq!(v, &json!(42));
    }

    // ST-U13: get() allows access from ungrouped execution to ungrouped entries (open group)
    #[test]
    fn st_u13_ungrouped_entry_accessible_to_ungrouped() {
        let mut stash = default_stash();
        stash.put("k", json!("public"), None, None).unwrap();
        let v = stash.get("k", None).unwrap().unwrap();
        assert_eq!(v, &json!("public"));
    }

    // ST-U14: get() allows access from ungrouped execution to ungrouped entries
    #[test]
    fn st_u14_grouped_execution_can_read_ungrouped_entry() {
        let mut stash = default_stash();
        stash.put("k", json!("public"), None, None).unwrap();
        // A grouped execution should also be able to read a public entry
        let v = stash.get("k", Some("any-group")).unwrap().unwrap();
        assert_eq!(v, &json!("public"));
    }

    // ST-U15: delete() removes entry and updates size accounting
    #[test]
    fn st_u15_delete_removes_entry_and_updates_size() {
        let mut stash = default_stash();
        stash.put("k", json!("value"), None, None).unwrap();
        let size_before = stash.total_size;
        assert!(size_before > 0);
        let removed = stash.delete("k", None).unwrap();
        assert!(removed);
        assert_eq!(stash.total_size, 0);
        assert!(stash.get("k", None).unwrap().is_none());
    }

    // ST-U16: delete() returns false for nonexistent key
    #[test]
    fn st_u16_delete_returns_false_for_missing_key() {
        let mut stash = default_stash();
        let removed = stash.delete("no-such-key", None).unwrap();
        assert!(!removed);
    }

    // ST-U17: delete() enforces group isolation (cannot delete cross-group entries)
    #[test]
    fn st_u17_delete_cross_group_denied() {
        let mut stash = default_stash();
        stash.put("k", json!(1), None, Some("group-a")).unwrap();
        let err = stash.delete("k", Some("group-b")).unwrap_err();
        assert!(matches!(err, StashError::CrossGroupAccess { .. }));
        // Entry should still be present
        let v = stash.get("k", Some("group-a")).unwrap().unwrap();
        assert_eq!(v, &json!(1));
    }

    // ST-U18: keys() returns only keys visible to current group
    #[test]
    fn st_u18_keys_filtered_by_group() {
        let mut stash = default_stash();
        stash.put("pub", json!(1), None, None).unwrap();
        stash.put("a-key", json!(2), None, Some("group-a")).unwrap();
        stash.put("b-key", json!(3), None, Some("group-b")).unwrap();

        let mut keys_a: Vec<&str> = stash.keys(Some("group-a"));
        keys_a.sort();
        assert_eq!(keys_a, vec!["a-key", "pub"]);

        let mut keys_b: Vec<&str> = stash.keys(Some("group-b"));
        keys_b.sort();
        assert_eq!(keys_b, vec!["b-key", "pub"]);

        let keys_none: Vec<&str> = stash.keys(None);
        assert_eq!(keys_none, vec!["pub"]);
    }

    // ST-U19: keys() excludes expired keys
    #[test]
    fn st_u19_keys_excludes_expired() {
        let mut stash = default_stash();
        stash.put("alive", json!(1), None, None).unwrap();
        stash
            .put("dead", json!(2), Some(Duration::from_millis(1)), None)
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let mut keys: Vec<&str> = stash.keys(None);
        keys.sort();
        assert_eq!(keys, vec!["alive"]);
    }

    // ST-U20: reap_expired() removes all expired entries and updates total_size
    #[test]
    fn st_u20_reap_expired() {
        let mut stash = default_stash();
        stash
            .put("k1", json!("a"), Some(Duration::from_millis(1)), None)
            .unwrap();
        stash
            .put("k2", json!("b"), Some(Duration::from_millis(1)), None)
            .unwrap();
        stash.put("k3", json!("c"), None, None).unwrap();
        let size_before = stash.total_size;
        assert!(size_before > 0);

        std::thread::sleep(Duration::from_millis(10));

        let removed = stash.reap_expired();
        assert_eq!(removed, 2);
        assert_eq!(stash.entries.len(), 1);
        assert!(stash.total_size < size_before);
        assert!(stash.get("k3", None).unwrap().is_some());
    }

    // ST-U21: put() with explicit TTL=0 is rejected (must be positive)
    #[test]
    fn st_u21_put_ttl_zero_rejected() {
        let mut stash = default_stash();
        let err = stash
            .put("k", json!(1), Some(Duration::from_secs(0)), None)
            .unwrap_err();
        assert!(matches!(
            err,
            StashError::TtlTooLong {
                requested_secs: 0,
                ..
            }
        ));
    }

    // ST-U22: concurrent put/get from multiple threads (Arc<Mutex<>> safety)
    #[tokio::test]
    async fn st_u22_concurrent_put_get() {
        let stash = Arc::new(Mutex::new(default_stash()));

        let mut handles = Vec::new();
        for i in 0..8usize {
            let stash = stash.clone();
            handles.push(tokio::spawn(async move {
                let key = format!("key-{i}");
                {
                    let mut s = stash.lock().unwrap();
                    s.put(&key, json!(i), None, None).unwrap();
                }
                {
                    let s = stash.lock().unwrap();
                    let v = s.get(&key, None).unwrap().unwrap();
                    assert_eq!(v, &json!(i));
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    // ST-U23: replacing a large value with a small one correctly decrements total_size
    #[test]
    fn st_u23_replace_large_with_small_decrements_total_size() {
        let mut stash = default_stash();
        let big = json!("x".repeat(1000));
        stash.put("k", big, None, None).unwrap();
        let size_after_big = stash.total_size;

        stash.put("k", json!(1), None, None).unwrap();
        let size_after_small = stash.total_size;

        assert!(
            size_after_small < size_after_big,
            "total_size ({size_after_small}) should be less than after big insert ({size_after_big})"
        );
        // Verify the new size matches the small value's serialised length
        let expected = serde_json::to_vec(&json!(1)).unwrap().len();
        assert_eq!(stash.total_size, expected);
    }
}
