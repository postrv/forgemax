//! Error redaction for preventing information leakage to LLMs.
//!
//! Strips sensitive details (URLs, IPs, file paths, credentials, stack traces)
//! from error messages before they reach the LLM, while preserving actionable
//! information like tool names, validation errors, and "not found" messages.

use std::sync::LazyLock;

use regex::Regex;

// --- Compiled regex patterns (initialized once) ---

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^\s'")\]}>]+"#).unwrap()
});

static IP_PORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?").unwrap()
});

static UNIX_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(/[\w.\-]+){2,}").unwrap()
});

static WINDOWS_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Z]:\\[\w.\\\-]+").unwrap()
});

static CREDENTIAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(Bearer\s+\S+|api_key\s*=\s*\S+|token\s*=\s*\S+|password\s*=\s*\S+|secret\s*=\s*\S+)").unwrap()
});

static STACK_TRACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(at\s+.+|Caused by:.*|[\w.$]+Exception.*|\.{3}\s*\d+\s*more)$").unwrap()
});

/// Redact an error message for a specific tool call before exposing it to the LLM.
///
/// The output preserves the server and tool names for routing retries, and keeps
/// validation/type errors intact. Connection details, file paths, credentials,
/// and stack traces are stripped.
pub fn redact_error_for_llm(server: &str, tool: &str, error: &str) -> String {
    let redacted = redact_error_message(error);
    format!("tool '{}' on server '{}' failed: {}", tool, server, redacted)
}

/// Redact sensitive patterns from an error message.
///
/// This is the general-purpose redactor used for both tool-call errors and
/// sandbox-level errors. It strips:
///
/// - URLs and connection strings → `[url]`
/// - IP:port addresses → `[addr]`
/// - Unix/Windows file paths → `[path]`
/// - Credentials (Bearer tokens, api_key=, etc.) → `[REDACTED]`
/// - Stack trace lines → removed entirely
pub fn redact_error_message(error: &str) -> String {
    let mut msg = error.to_string();

    // Order matters: strip credentials before URLs (credentials may contain URLs)
    msg = CREDENTIAL_RE.replace_all(&msg, "[REDACTED]").to_string();
    msg = URL_RE.replace_all(&msg, "[url]").to_string();
    msg = IP_PORT_RE.replace_all(&msg, "[addr]").to_string();
    msg = WINDOWS_PATH_RE.replace_all(&msg, "[path]").to_string();
    msg = UNIX_PATH_RE.replace_all(&msg, "[path]").to_string();
    msg = STACK_TRACE_RE.replace_all(&msg, "").to_string();

    // Clean up blank lines left by stack trace removal
    let lines: Vec<&str> = msg
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- redact_error_for_llm ---

    #[test]
    fn tool_error_format() {
        let result = redact_error_for_llm("narsil", "symbols.find", "something failed");
        assert!(result.contains("tool 'symbols.find'"));
        assert!(result.contains("server 'narsil'"));
        assert!(result.contains("something failed"));
    }

    // --- URL redaction ---

    #[test]
    fn redacts_http_urls() {
        let msg = "connection refused: http://internal.corp:9876/api/v2";
        let result = redact_error_message(msg);
        assert!(result.contains("[url]"), "should redact URL: {result}");
        assert!(
            !result.contains("internal.corp"),
            "should not contain hostname: {result}"
        );
    }

    #[test]
    fn redacts_https_urls() {
        let msg = "failed to connect to https://mcp.secret.io/sse?token=abc123";
        let result = redact_error_message(msg);
        assert!(result.contains("[url]"));
        assert!(!result.contains("secret.io"));
    }

    // --- IP:port redaction ---

    #[test]
    fn redacts_ip_port() {
        let msg = "connection refused: 192.168.1.100:5432";
        let result = redact_error_message(msg);
        assert!(result.contains("[addr]"), "should redact IP: {result}");
        assert!(!result.contains("192.168"), "should not contain IP: {result}");
    }

    // --- File path redaction ---

    #[test]
    fn redacts_unix_paths() {
        let msg = "file not found: /home/user/.config/forge/certs/ca.pem";
        let result = redact_error_message(msg);
        assert!(result.contains("[path]"), "should redact path: {result}");
        assert!(
            !result.contains("/home/user"),
            "should not contain path: {result}"
        );
    }

    #[test]
    fn redacts_windows_paths() {
        let msg = r"file not found: C:\Users\admin\AppData\forge\config.toml";
        let result = redact_error_message(msg);
        assert!(result.contains("[path]"), "should redact path: {result}");
        assert!(
            !result.contains(r"C:\Users"),
            "should not contain path: {result}"
        );
    }

    // --- Credential redaction ---

    #[test]
    fn redacts_bearer_tokens() {
        let msg = "auth failed with Bearer eyJhbGciOiJIUzI1NiJ9.secret";
        let result = redact_error_message(msg);
        assert!(
            result.contains("[REDACTED]"),
            "should redact bearer: {result}"
        );
        assert!(
            !result.contains("eyJhbGci"),
            "should not contain token: {result}"
        );
    }

    #[test]
    fn redacts_api_keys() {
        let msg = "invalid api_key=sk-abc123def456 for this endpoint";
        let result = redact_error_message(msg);
        assert!(
            result.contains("[REDACTED]"),
            "should redact api key: {result}"
        );
        assert!(
            !result.contains("sk-abc123"),
            "should not contain key: {result}"
        );
    }

    // --- Stack trace redaction ---

    #[test]
    fn redacts_stack_traces() {
        let msg = "Error: something broke\n  at Module._compile (node:internal/modules/cjs/loader:1241:14)\n  at Object.Module._extensions (node:internal/modules/cjs/loader:1295:10)\nSome useful context";
        let result = redact_error_message(msg);
        assert!(
            !result.contains("Module._compile"),
            "should strip stack frames: {result}"
        );
        assert!(
            result.contains("something broke"),
            "should keep error message: {result}"
        );
        assert!(
            result.contains("Some useful context"),
            "should keep non-trace lines: {result}"
        );
    }

    #[test]
    fn redacts_caused_by_lines() {
        let msg = "tool error\nCaused by: java.lang.NullPointerException\n  at com.example.Service.run(Service.java:42)";
        let result = redact_error_message(msg);
        assert!(
            !result.contains("NullPointerException"),
            "should strip Caused by: {result}"
        );
        assert!(
            !result.contains("Service.java"),
            "should strip stack frame: {result}"
        );
    }

    // --- Preservation tests ---

    #[test]
    fn preserves_validation_errors() {
        let msg = "missing required field 'pattern'";
        let result = redact_error_message(msg);
        assert_eq!(result, msg, "validation errors should be preserved");
    }

    #[test]
    fn preserves_type_errors() {
        let msg = "expected string, got number for field 'count'";
        let result = redact_error_message(msg);
        assert_eq!(result, msg, "type errors should be preserved");
    }

    #[test]
    fn preserves_not_found_messages() {
        let msg = "symbol 'handleRequet' not found, did you mean 'handleRequest'?";
        let result = redact_error_message(msg);
        assert_eq!(result, msg, "not-found messages should be preserved");
    }

    #[test]
    fn preserves_empty_results() {
        let msg = "no results found";
        let result = redact_error_message(msg);
        assert_eq!(result, msg);
    }

    // --- Combined patterns ---

    #[test]
    fn handles_complex_error_with_multiple_patterns() {
        let msg = "connection to https://api.internal.io:8443/v2 failed\n\
                    Bearer sk-prod-abcdef was rejected\n\
                    config at /etc/forge/server.toml\n\
                      at TlsSocket.connect (node:tls:123:45)\n\
                    retrying with fallback 10.0.0.5:3000";
        let result = redact_error_message(msg);
        assert!(!result.contains("api.internal.io"), "URL host stripped");
        assert!(!result.contains("sk-prod"), "credential stripped");
        assert!(!result.contains("/etc/forge"), "path stripped");
        assert!(!result.contains("TlsSocket"), "stack trace stripped");
        assert!(!result.contains("10.0.0.5"), "IP stripped");
    }
}
