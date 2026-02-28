//! Error redaction for preventing information leakage to LLMs.
//!
//! Strips sensitive details (URLs, IPs, file paths, credentials, stack traces)
//! from error messages before they reach the LLM, while preserving actionable
//! information like tool names, validation errors, and "not found" messages.

use std::sync::LazyLock;

use regex::Regex;

// --- Compiled regex patterns (initialized once) ---

static URL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"https?://[^\s'")\]}>]+"#).unwrap());

static IP_PORT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?").unwrap());

static UNIX_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/(home|Users|etc|var|tmp|opt|usr|root|mnt|srv|proc|sys|dev|run|boot|snap|nix)(/[\w.\-]+)+").unwrap()
});

static WINDOWS_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Z]:\\[\w.\\\-]+").unwrap());

static CREDENTIAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(Bearer\s+\S+|api_key\s*=\s*\S+|token\s*=\s*\S+|password\s*=\s*\S+|secret\s*=\s*\S+)",
    )
    .unwrap()
});

/// AWS access key IDs (always start with AKIA, ABIA, ACCA, or ASIA + 16 alphanumeric chars).
static AWS_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}").unwrap());

/// PEM-encoded private key headers.
static PEM_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN[A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END[A-Z\s]+PRIVATE KEY-----")
        .unwrap()
});

/// GitHub tokens: PATs (ghp_), OAuth (gho_), and fine-grained (github_pat_).
static GITHUB_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:ghp_|gho_|ghs_|ghr_|github_pat_)[a-zA-Z0-9_]{20,}").unwrap());

/// Long hex strings (64+ chars) that look like secret keys or hashes used as tokens.
static HEX_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[0-9a-fA-F]{64,}\b").unwrap());

/// JWT tokens (three base64url-encoded segments separated by dots).
static JWT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+").unwrap());

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
    format!(
        "tool '{}' on server '{}' failed: {}",
        tool, server, redacted
    )
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

    // Order matters: strip most specific credential patterns first, then general ones,
    // then URLs (credentials may contain URLs).
    msg = PEM_KEY_RE.replace_all(&msg, "[REDACTED]").to_string();
    msg = JWT_RE.replace_all(&msg, "[REDACTED]").to_string();
    msg = AWS_KEY_RE.replace_all(&msg, "[REDACTED]").to_string();
    msg = GITHUB_TOKEN_RE.replace_all(&msg, "[REDACTED]").to_string();
    msg = CREDENTIAL_RE.replace_all(&msg, "[REDACTED]").to_string();
    msg = HEX_TOKEN_RE.replace_all(&msg, "[REDACTED]").to_string();
    msg = URL_RE.replace_all(&msg, "[url]").to_string();
    msg = IP_PORT_RE.replace_all(&msg, "[addr]").to_string();
    msg = WINDOWS_PATH_RE.replace_all(&msg, "[path]").to_string();
    msg = UNIX_PATH_RE.replace_all(&msg, "[path]").to_string();
    msg = STACK_TRACE_RE.replace_all(&msg, "").to_string();

    // Clean up blank lines left by stack trace removal
    let lines: Vec<&str> = msg.lines().filter(|l| !l.trim().is_empty()).collect();
    lines.join("\n")
}

/// Redact sensitive data from a structured error JSON object.
///
/// Applies [`redact_error_for_llm`] to the `message` field and
/// [`redact_error_message`] to the `suggested_fix` field, preserving
/// all other fields (`error`, `code`, `retryable`) untouched.
pub fn redact_structured_error(server: &str, tool: &str, error: &mut serde_json::Value) {
    if let Some(msg) = error
        .get("message")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
    {
        error["message"] = serde_json::Value::String(redact_error_for_llm(server, tool, &msg));
    }
    if let Some(fix) = error
        .get("suggested_fix")
        .and_then(|f| f.as_str())
        .map(|s| s.to_string())
    {
        error["suggested_fix"] = serde_json::Value::String(redact_error_message(&fix));
    }
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
        assert!(
            !result.contains("192.168"),
            "should not contain IP: {result}"
        );
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

    // --- CR-01: AWS access key redaction ---
    #[test]
    fn cr01_redacts_aws_access_keys() {
        let msg = "invalid credentials: AKIAIOSFODNN7EXAMPLE";
        let result = redact_error_message(msg);
        assert!(
            result.contains("[REDACTED]"),
            "should redact AWS key: {result}"
        );
        assert!(
            !result.contains("AKIAIOSFODNN7"),
            "should not contain AWS key: {result}"
        );
    }

    // --- CR-02: connection string credential redaction ---
    #[test]
    fn cr02_redacts_connection_string_passwords() {
        let msg = "connection failed: password=s3cr3t&host=db.internal";
        let result = redact_error_message(msg);
        assert!(
            result.contains("[REDACTED]"),
            "should redact password: {result}"
        );
        assert!(
            !result.contains("s3cr3t"),
            "should not contain password: {result}"
        );
    }

    // --- CR-03: PEM private key redaction ---
    #[test]
    fn cr03_redacts_pem_private_keys() {
        let msg = "cert error: -----BEGIN RSA PRIVATE KEY-----\nMIIBogIB...\n-----END RSA PRIVATE KEY-----";
        let result = redact_error_message(msg);
        assert!(result.contains("[REDACTED]"), "should redact PEM: {result}");
        assert!(
            !result.contains("MIIBogIB"),
            "should not contain key data: {result}"
        );
    }

    // --- CR-04: GitHub token redaction ---
    #[test]
    fn cr04_redacts_github_tokens() {
        let msg = "auth failed with token ghp_ABCDEFGHIJKLMNOPQRSTuvwxyz1234";
        let result = redact_error_message(msg);
        assert!(
            result.contains("[REDACTED]"),
            "should redact GitHub token: {result}"
        );
        assert!(
            !result.contains("ghp_ABCDE"),
            "should not contain token: {result}"
        );

        // Fine-grained PAT
        let msg2 = "rejected github_pat_ABCDEFGHIJKLMNOPQRSTUV1234567890abcdef";
        let result2 = redact_error_message(msg2);
        assert!(
            result2.contains("[REDACTED]"),
            "should redact fine-grained PAT: {result2}"
        );
    }

    // --- CR-05: long hex token redaction ---
    #[test]
    fn cr05_redacts_long_hex_tokens() {
        let hex_token = "a".repeat(64);
        let msg = format!("using secret key {hex_token} for encryption");
        let result = redact_error_message(&msg);
        assert!(
            result.contains("[REDACTED]"),
            "should redact hex token: {result}"
        );
        assert!(
            !result.contains(&hex_token),
            "should not contain hex token: {result}"
        );
    }

    // --- CR-06: JWT token redaction ---
    #[test]
    fn cr06_redacts_jwt_tokens() {
        let msg = "auth failed: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = redact_error_message(msg);
        assert!(result.contains("[REDACTED]"), "should redact JWT: {result}");
        assert!(
            !result.contains("eyJhbGci"),
            "should not contain JWT: {result}"
        );
    }

    // --- CR-07: no over-redaction of short hex strings ---
    #[test]
    fn cr07_no_over_redaction() {
        // Short hex strings (like error codes) should NOT be redacted
        let msg = "error code 0xDEADBEEF at offset 0x1234";
        let result = redact_error_message(msg);
        assert_eq!(result, msg, "short hex should not be redacted");

        // Normal words should not trigger credential patterns
        let msg2 = "the password field is required";
        let result2 = redact_error_message(msg2);
        assert_eq!(result2, msg2, "field names should not be redacted");
    }

    // --- WI-3c: Tightened path regex preserves tool error context ---

    #[test]
    fn preserves_tool_error_context() {
        // Tool/server names and error context should not be mangled by path regex
        let msg = "tool 'ast.parse' on server 'narsil' failed: missing field 'pattern'";
        let result = redact_error_message(msg);
        assert_eq!(result, msg, "tool error context should be fully preserved");
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

    // --- Structured error redaction tests (Phase R2) ---

    #[test]
    fn se_wire_05_redact_structured_error_redacts_message() {
        let mut err = serde_json::json!({
            "error": true,
            "code": "UPSTREAM_ERROR",
            "message": "upstream error from 'narsil': connection to https://internal.corp:9876/api failed",
            "retryable": true,
        });
        redact_structured_error("narsil", "find_symbols", &mut err);
        let msg = err["message"].as_str().unwrap();
        assert!(!msg.contains("internal.corp"), "should redact URL: {msg}");
        assert!(msg.contains("narsil"), "should preserve server name: {msg}");
    }

    #[test]
    fn se_wire_06_redact_structured_error_redacts_suggested_fix() {
        let mut err = serde_json::json!({
            "error": true,
            "code": "TOOL_NOT_FOUND",
            "message": "tool not found",
            "retryable": false,
            "suggested_fix": "config at /home/user/.config/forge/tools.toml, try 'find_symbols'"
        });
        redact_structured_error("narsil", "fnd_symbols", &mut err);
        let fix = err["suggested_fix"].as_str().unwrap();
        assert!(
            !fix.contains("/home/user"),
            "should redact paths in suggested_fix: {fix}"
        );
    }

    #[test]
    fn se_wire_07_redact_structured_error_preserves_code_and_retryable() {
        let mut err = serde_json::json!({
            "error": true,
            "code": "TIMEOUT",
            "message": "timeout after 5000ms on server 'slow'",
            "retryable": true,
            "suggested_fix": "Retry with a simpler operation"
        });
        redact_structured_error("slow", "heavy_op", &mut err);
        assert_eq!(err["error"], true);
        assert_eq!(err["code"], "TIMEOUT");
        assert_eq!(err["retryable"], true);
    }
}
