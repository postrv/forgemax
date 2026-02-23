//! Pre-execution code validator for the Forge sandbox.
//!
//! This validator is **defense-in-depth** — the V8 isolate is the real security
//! boundary. These checks catch common escape patterns early, provide better
//! error messages, and prevent prompt injection from reaching the runtime.

use crate::error::SandboxError;

/// Maximum code size in bytes (64 KB).
const DEFAULT_MAX_CODE_SIZE: usize = 64 * 1024;

/// Patterns that are banned from sandbox code.
///
/// These are belt-and-suspenders checks — the V8 sandbox itself prevents
/// access to these APIs, but catching them early gives better error messages
/// and prevents prompt injection from even reaching the runtime.
const BANNED_PATTERNS: &[&str] = &[
    "eval(",
    "Function(",
    "import(",              // Dynamic imports
    "require(",             // CommonJS
    "Deno.",                // Runtime escape
    "__proto__",            // Prototype pollution
    "constructor[",         // Prototype chain access via bracket notation
    "constructor.constructor", // Function constructor bypass
    "Reflect.",             // Reflect API escape
    "globalThis[",         // Dynamic global access
    "String.fromCharCode",  // String-based code construction
    // Specific process.* patterns (not bare "process." to avoid false positives
    // on e.g. data.process.status)
    "process.env",
    "process.exit",
    "process.argv",
    "process.stdin",
    "process.stdout",
    "process.stderr",
    "process.kill",
    "process.binding",
];

/// Validates LLM-generated code before sandbox execution.
pub fn validate_code(code: &str, max_size: Option<usize>) -> Result<(), SandboxError> {
    let max = max_size.unwrap_or(DEFAULT_MAX_CODE_SIZE);

    // 1. Size limit
    if code.len() > max {
        return Err(SandboxError::CodeTooLarge {
            max,
            actual: code.len(),
        });
    }

    // 2. Empty code
    if code.trim().is_empty() {
        return Err(SandboxError::ValidationFailed {
            reason: "code is empty".into(),
        });
    }

    // 3. Banned patterns
    for pattern in BANNED_PATTERNS {
        if code.contains(pattern) {
            return Err(SandboxError::BannedPattern {
                pattern: (*pattern).to_string(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_async_arrow() {
        let code = r#"async () => { return manifest.tools.filter(t => t.category === "ast"); }"#;
        assert!(validate_code(code, None).is_ok());
    }

    #[test]
    fn rejects_empty_code() {
        assert!(validate_code("", None).is_err());
        assert!(validate_code("   ", None).is_err());
    }

    #[test]
    fn rejects_oversized_code() {
        let big = "x".repeat(100_000);
        let err = validate_code(&big, None).unwrap_err();
        assert!(matches!(err, SandboxError::CodeTooLarge { .. }));
    }

    #[test]
    fn rejects_eval() {
        let code = r#"async () => { return eval("1+1"); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_dynamic_import() {
        let code = r#"async () => { const m = await import("fs"); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_deno_access() {
        let code = r#"async () => { return Deno.readFile("/etc/passwd"); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_proto_pollution() {
        let code = r#"async () => { ({}).__proto__.polluted = true; }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    // --- New tests for WU3 ---

    #[test]
    fn accepts_data_process_status() {
        // "process." as a substring should NOT be rejected — only specific
        // process.env/exit/argv/etc. patterns are banned.
        let code = r#"async () => { return data.process.status; }"#;
        assert!(validate_code(code, None).is_ok());
    }

    #[test]
    fn rejects_process_env() {
        let code = r#"async () => { return process.env.SECRET; }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_constructor_constructor() {
        let code = r#"async () => { return "".constructor.constructor("return this")(); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_reflect_construct() {
        let code = r#"async () => { return Reflect.construct(Array, []); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_globalthis_bracket_access() {
        let code = r#"async () => { return globalThis["eval"]("1+1"); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_string_from_char_code() {
        let code = r#"async () => { return String.fromCharCode(101, 118, 97, 108); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn accepts_legitimate_constructor_property() {
        // Accessing .constructor (not .constructor[ or .constructor.constructor) is fine
        let code = r#"async () => { return obj.constructor.name; }"#;
        assert!(validate_code(code, None).is_ok());
    }

    #[test]
    fn custom_max_size() {
        let code = "x".repeat(100);
        assert!(validate_code(&code, Some(50)).is_err());
        assert!(validate_code(&code, Some(200)).is_ok());
    }
}
