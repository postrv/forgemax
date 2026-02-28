//! Audit event types for Forge gateway observability.
//!
//! Provides [`AuditEvent`] — a structured, serializable audit record
//! for tracking gateway operations.

use chrono::{DateTime, Utc};
use serde::Serialize;

/// A structured audit event emitted by the Forge gateway.
///
/// This is a stub that will be expanded in Phase 7 (Observability).
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AuditEvent {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// The type of event.
    pub event_type: String,
    /// Human-readable description.
    pub description: String,
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(event_type: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
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
}
