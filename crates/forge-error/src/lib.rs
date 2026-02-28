//! Typed error types for Forge gateway dispatcher traits.
//!
//! Provides [`DispatchError`] — the canonical error type for all dispatcher
//! trait methods (`ToolDispatcher`, `ResourceDispatcher`, `StashDispatcher`).

use thiserror::Error;

/// Canonical error type for Forge dispatcher operations.
///
/// All variants are `#[non_exhaustive]` to allow future additions without
/// breaking downstream code.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DispatchError {
    /// The requested server does not exist in the router.
    #[error("server not found: {0}")]
    ServerNotFound(String),

    /// The requested tool does not exist on the specified server.
    #[error("tool not found: '{tool}' on server '{server}'")]
    ToolNotFound {
        /// The server that was queried.
        server: String,
        /// The tool name that was not found.
        tool: String,
    },

    /// The operation timed out.
    #[error("timeout after {timeout_ms}ms on server '{server}'")]
    Timeout {
        /// The server that timed out.
        server: String,
        /// The timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// The circuit breaker for this server is open.
    #[error("circuit breaker open for server: {0}")]
    CircuitOpen(String),

    /// A group isolation policy denied the operation.
    #[error("group policy denied: {reason}")]
    GroupPolicyDenied {
        /// Explanation of why the policy denied access.
        reason: String,
    },

    /// An upstream MCP server returned an error.
    #[error("upstream error from '{server}': {message}")]
    Upstream {
        /// The server that returned the error.
        server: String,
        /// The error message from the upstream server.
        message: String,
    },

    /// A rate limit was exceeded.
    #[error("rate limit exceeded: {0}")]
    RateLimit(String),

    /// An internal error (catch-all for unexpected failures).
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl DispatchError {
    /// Returns a static error code string for programmatic matching.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ServerNotFound(_) => "SERVER_NOT_FOUND",
            Self::ToolNotFound { .. } => "TOOL_NOT_FOUND",
            Self::Timeout { .. } => "TIMEOUT",
            Self::CircuitOpen(_) => "CIRCUIT_OPEN",
            Self::GroupPolicyDenied { .. } => "GROUP_POLICY_DENIED",
            Self::Upstream { .. } => "UPSTREAM_ERROR",
            Self::RateLimit(_) => "RATE_LIMIT",
            Self::Internal(_) => "INTERNAL",
        }
    }

    /// Returns whether the operation that produced this error may succeed if retried.
    pub fn retryable(&self) -> bool {
        match self {
            Self::Timeout { .. } => true,
            Self::CircuitOpen(_) => true,
            Self::RateLimit(_) => true,
            Self::Upstream { .. } => true,
            Self::ServerNotFound(_) => false,
            Self::ToolNotFound { .. } => false,
            Self::GroupPolicyDenied { .. } => false,
            Self::Internal(_) => false,
        }
    }

    /// Convert to a structured JSON error response for LLM consumption.
    ///
    /// Returns a JSON object with `error`, `code`, `message`, `retryable`,
    /// and optionally `suggested_fix` (populated by fuzzy matching when
    /// `known_tools` is provided for `ToolNotFound` errors).
    ///
    /// # Arguments
    /// * `known_tools` - Optional list of `(server, tool)` pairs for fuzzy matching.
    ///   Only used for `ToolNotFound` errors.
    pub fn to_structured_error(&self, known_tools: Option<&[(&str, &str)]>) -> serde_json::Value {
        let suggested_fix = match self {
            Self::ToolNotFound { server, tool } => {
                if let Some(tools) = known_tools {
                    find_similar_tool(server, tool, tools)
                } else {
                    None
                }
            }
            Self::ServerNotFound(name) => {
                if let Some(tools) = known_tools {
                    find_similar_server(name, tools)
                } else {
                    None
                }
            }
            Self::CircuitOpen(_) => Some("Retry after a delay".to_string()),
            Self::Timeout { .. } => Some("Retry with a simpler operation".to_string()),
            Self::RateLimit(_) => Some("Reduce request frequency".to_string()),
            _ => None,
        };

        let mut obj = serde_json::json!({
            "error": true,
            "code": self.code(),
            "message": self.to_string(),
            "retryable": self.retryable(),
        });

        if let Some(fix) = suggested_fix {
            obj["suggested_fix"] = serde_json::Value::String(fix);
        }

        obj
    }
}

/// Find the closest matching tool name using Levenshtein distance.
///
/// Returns a suggestion string if a tool within edit distance 3 is found.
fn find_similar_tool(server: &str, tool: &str, known_tools: &[(&str, &str)]) -> Option<String> {
    let full_name = format!("{server}.{tool}");
    let mut best: Option<(usize, String)> = None;

    for &(s, t) in known_tools {
        // Try matching the full "server.tool" form
        let candidate_full = format!("{s}.{t}");
        let dist = strsim::levenshtein(&full_name, &candidate_full);
        if dist <= 3 && best.as_ref().is_none_or(|(d, _)| dist < *d) {
            best = Some((dist, format!("Did you mean '{t}' on server '{s}'?")));
        }

        // Also try matching just the tool name on the same server
        if s == server {
            let dist = strsim::levenshtein(tool, t);
            if dist <= 3 && best.as_ref().is_none_or(|(d, _)| dist < *d) {
                best = Some((dist, format!("Did you mean '{t}'?")));
            }
        }
    }

    best.map(|(_, suggestion)| suggestion)
}

/// Find the closest matching server name using Levenshtein distance.
fn find_similar_server(name: &str, known_tools: &[(&str, &str)]) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    let mut best: Option<(usize, String)> = None;

    for &(s, _) in known_tools {
        if !seen.insert(s) {
            continue;
        }
        let dist = strsim::levenshtein(name, s);
        if dist <= 3 && best.as_ref().is_none_or(|(d, _)| dist < *d) {
            best = Some((dist, format!("Did you mean server '{s}'?")));
        }
    }

    best.map(|(_, suggestion)| suggestion)
}

// Compile-time assertion: DispatchError must be Send + Sync + 'static
const _: fn() = || {
    fn assert_bounds<T: Send + Sync + 'static>() {}
    assert_bounds::<DispatchError>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_server_not_found() {
        let err = DispatchError::ServerNotFound("myserver".into());
        assert_eq!(err.to_string(), "server not found: myserver");
    }

    #[test]
    fn display_tool_not_found() {
        let err = DispatchError::ToolNotFound {
            server: "srv".into(),
            tool: "hammer".into(),
        };
        assert_eq!(err.to_string(), "tool not found: 'hammer' on server 'srv'");
    }

    #[test]
    fn display_timeout() {
        let err = DispatchError::Timeout {
            server: "slow".into(),
            timeout_ms: 5000,
        };
        assert_eq!(err.to_string(), "timeout after 5000ms on server 'slow'");
    }

    #[test]
    fn display_circuit_open() {
        let err = DispatchError::CircuitOpen("broken".into());
        assert_eq!(err.to_string(), "circuit breaker open for server: broken");
    }

    #[test]
    fn display_group_policy_denied() {
        let err = DispatchError::GroupPolicyDenied {
            reason: "cross-server access denied".into(),
        };
        assert_eq!(
            err.to_string(),
            "group policy denied: cross-server access denied"
        );
    }

    #[test]
    fn display_upstream() {
        let err = DispatchError::Upstream {
            server: "remote".into(),
            message: "connection refused".into(),
        };
        assert_eq!(
            err.to_string(),
            "upstream error from 'remote': connection refused"
        );
    }

    #[test]
    fn display_rate_limit() {
        let err = DispatchError::RateLimit("too many tool calls".into());
        assert_eq!(err.to_string(), "rate limit exceeded: too many tool calls");
    }

    #[test]
    fn display_internal() {
        let err = DispatchError::Internal(anyhow::anyhow!("something broke"));
        assert_eq!(err.to_string(), "something broke");
    }

    #[test]
    fn code_exhaustive() {
        let cases: Vec<(DispatchError, &str)> = vec![
            (
                DispatchError::ServerNotFound("x".into()),
                "SERVER_NOT_FOUND",
            ),
            (
                DispatchError::ToolNotFound {
                    server: "s".into(),
                    tool: "t".into(),
                },
                "TOOL_NOT_FOUND",
            ),
            (
                DispatchError::Timeout {
                    server: "s".into(),
                    timeout_ms: 1000,
                },
                "TIMEOUT",
            ),
            (DispatchError::CircuitOpen("x".into()), "CIRCUIT_OPEN"),
            (
                DispatchError::GroupPolicyDenied { reason: "r".into() },
                "GROUP_POLICY_DENIED",
            ),
            (
                DispatchError::Upstream {
                    server: "s".into(),
                    message: "m".into(),
                },
                "UPSTREAM_ERROR",
            ),
            (DispatchError::RateLimit("x".into()), "RATE_LIMIT"),
            (DispatchError::Internal(anyhow::anyhow!("x")), "INTERNAL"),
        ];
        for (err, expected_code) in &cases {
            assert_eq!(err.code(), *expected_code, "wrong code for {err}");
        }
    }

    #[test]
    fn retryable_true_cases() {
        assert!(DispatchError::Timeout {
            server: "s".into(),
            timeout_ms: 1000
        }
        .retryable());
        assert!(DispatchError::CircuitOpen("s".into()).retryable());
        assert!(DispatchError::RateLimit("x".into()).retryable());
        assert!(DispatchError::Upstream {
            server: "s".into(),
            message: "m".into()
        }
        .retryable());
    }

    #[test]
    fn retryable_false_cases() {
        assert!(!DispatchError::ServerNotFound("x".into()).retryable());
        assert!(!DispatchError::ToolNotFound {
            server: "s".into(),
            tool: "t".into()
        }
        .retryable());
        assert!(!DispatchError::GroupPolicyDenied { reason: "r".into() }.retryable());
        assert!(!DispatchError::Internal(anyhow::anyhow!("x")).retryable());
    }

    #[test]
    fn send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<DispatchError>();
    }

    #[test]
    fn from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("test anyhow");
        let dispatch_err: DispatchError = anyhow_err.into();
        assert!(matches!(dispatch_err, DispatchError::Internal(_)));
        assert_eq!(dispatch_err.code(), "INTERNAL");
    }

    #[test]
    fn internal_is_display_transparent() {
        let inner = anyhow::anyhow!("root cause");
        let err = DispatchError::Internal(inner);
        // #[error(transparent)] means Display delegates to the inner error
        assert_eq!(err.to_string(), "root cause");
    }

    // --- Structured error tests (Phase 5B) ---

    #[test]
    fn structured_error_server_not_found() {
        let err = DispatchError::ServerNotFound("narsil".into());
        let json = err.to_structured_error(None);
        assert_eq!(json["error"], true);
        assert_eq!(json["code"], "SERVER_NOT_FOUND");
        assert_eq!(json["retryable"], false);
        assert!(json["message"].as_str().unwrap().contains("narsil"));
    }

    #[test]
    fn structured_error_tool_not_found_with_suggestion() {
        let err = DispatchError::ToolNotFound {
            server: "narsil".into(),
            tool: "fnd_symbols".into(),
        };
        let tools = vec![
            ("narsil", "find_symbols"),
            ("narsil", "parse"),
            ("github", "list_repos"),
        ];
        let json = err.to_structured_error(Some(&tools));
        assert_eq!(json["code"], "TOOL_NOT_FOUND");
        let fix = json["suggested_fix"].as_str().unwrap();
        assert!(
            fix.contains("find_symbols"),
            "expected suggestion, got: {fix}"
        );
    }

    #[test]
    fn structured_error_tool_not_found_no_match() {
        let err = DispatchError::ToolNotFound {
            server: "narsil".into(),
            tool: "completely_different".into(),
        };
        let tools = vec![("narsil", "find_symbols"), ("narsil", "parse")];
        let json = err.to_structured_error(Some(&tools));
        assert!(json.get("suggested_fix").is_none());
    }

    #[test]
    fn structured_error_server_not_found_with_suggestion() {
        let err = DispatchError::ServerNotFound("narsill".into());
        let tools = vec![("narsil", "find_symbols"), ("github", "list_repos")];
        let json = err.to_structured_error(Some(&tools));
        let fix = json["suggested_fix"].as_str().unwrap();
        assert!(
            fix.contains("narsil"),
            "expected server suggestion, got: {fix}"
        );
    }

    #[test]
    fn structured_error_timeout_has_retry_suggestion() {
        let err = DispatchError::Timeout {
            server: "slow".into(),
            timeout_ms: 5000,
        };
        let json = err.to_structured_error(None);
        assert_eq!(json["retryable"], true);
        assert!(json["suggested_fix"].as_str().is_some());
    }

    #[test]
    fn structured_error_circuit_open_has_retry_suggestion() {
        let err = DispatchError::CircuitOpen("broken".into());
        let json = err.to_structured_error(None);
        assert_eq!(json["retryable"], true);
        assert!(json["suggested_fix"].as_str().unwrap().contains("Retry"));
    }

    #[test]
    fn structured_error_internal_no_suggestion() {
        let err = DispatchError::Internal(anyhow::anyhow!("unexpected"));
        let json = err.to_structured_error(None);
        assert_eq!(json["code"], "INTERNAL");
        assert_eq!(json["retryable"], false);
        assert!(json.get("suggested_fix").is_none());
    }

    #[test]
    fn fuzzy_match_close_tool_name() {
        // "fnd" is edit distance 1 from "find"
        let result = super::find_similar_tool(
            "narsil",
            "fnd_symbols",
            &[("narsil", "find_symbols"), ("narsil", "parse")],
        );
        assert!(result.is_some());
        assert!(result.unwrap().contains("find_symbols"));
    }

    #[test]
    fn fuzzy_match_no_match_beyond_threshold() {
        let result = super::find_similar_tool(
            "narsil",
            "zzzzz",
            &[("narsil", "find_symbols"), ("narsil", "parse")],
        );
        assert!(result.is_none());
    }

    #[test]
    fn fuzzy_match_server_name() {
        let result = super::find_similar_server(
            "narsill",
            &[("narsil", "find_symbols"), ("github", "list_repos")],
        );
        assert!(result.is_some());
        assert!(result.unwrap().contains("narsil"));
    }
}
