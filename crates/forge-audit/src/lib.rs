#![warn(missing_docs)]
//! Audit event types for Forge gateway observability.
//!
//! Provides [`AuditEvent`] — a structured, serializable audit record
//! for tracking gateway operations.

use jiff::Timestamp;
use serde::Serialize;

/// A structured audit event emitted by the Forge gateway.
///
/// This is a stub that will be expanded in Phase 7 (Observability).
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AuditEvent {
    /// When the event occurred.
    pub timestamp: Timestamp,
    /// The type of event.
    pub event_type: String,
    /// Human-readable description.
    pub description: String,
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(event_type: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            timestamp: Timestamp::now(),
            event_type: event_type.into(),
            description: description.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_to_json_without_panic() {
        let event = AuditEvent::new("test_event", "a test audit event");
        let json = serde_json::to_string(&event).expect("should serialize");
        assert!(json.contains("test_event"));
        assert!(json.contains("a test audit event"));
        assert!(json.contains("timestamp"));
    }

    #[test]
    fn audit_timestamp_remains_an_rfc3339_utc_string() {
        for previous in [
            "2026-11-24T22:45:00Z",
            "2026-11-24T22:45:00.120Z",
            "2026-11-24T22:45:00.123456Z",
            "2026-11-24T22:45:00.123456789Z",
        ] {
            let timestamp: Timestamp = serde_json::from_value(serde_json::json!(previous)).unwrap();
            let mut event = AuditEvent::new("fixture", "audit record");
            event.timestamp = timestamp;
            let serialized = serde_json::to_value(event).unwrap();
            let wire = serialized["timestamp"].as_str().unwrap();
            assert!(wire.ends_with('Z'), "{wire}");
            assert_eq!(wire.parse::<Timestamp>().unwrap(), timestamp);
        }
    }
}
