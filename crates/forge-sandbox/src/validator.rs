//! Pre-execution code validator for the Forge sandbox.
//!
//! This validator is **defense-in-depth** — the V8 isolate is the real security
//! boundary. These checks catch common escape patterns early, provide better
//! error messages, and prevent prompt injection from reaching the runtime.

use crate::error::SandboxError;
use regex::Regex;

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
    "import(",                 // Dynamic imports
    "require(",                // CommonJS
    "Deno.",                   // Runtime escape
    "__proto__",               // Prototype pollution
    "constructor[",            // Prototype chain access via bracket notation
    "constructor.constructor", // Function constructor bypass
    "Reflect.",                // Reflect API escape
    "globalThis[",             // Dynamic global access
    "String.fromCharCode",     // String-based code construction
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

/// Strip JS comments from code for pattern matching.
///
/// Removes both block comments (`/* ... */`) and line comments (`// ...`)
/// so that patterns like `eval/*bypass*/(` are still caught. This operates
/// on the validation copy only — the original code is executed unchanged.
fn strip_js_comments(code: &str) -> String {
    // Remove block comments (non-greedy to handle multiple comments)
    let block_re = Regex::new(r"/\*[\s\S]*?\*/").expect("valid regex");
    let without_blocks = block_re.replace_all(code, " ");
    // Remove line comments
    let line_re = Regex::new(r"//[^\n]*").expect("valid regex");
    line_re.replace_all(&without_blocks, " ").into_owned()
}

/// Normalize Unicode confusables to ASCII equivalents for validation.
///
/// Maps common Cyrillic/Greek/fullwidth homoglyphs to their ASCII lookalikes
/// so that `еval(` (Cyrillic е) is caught by the `eval(` pattern.
fn normalize_unicode_confusables(code: &str) -> String {
    code.chars()
        .map(|c| match c {
            // Cyrillic homoglyphs
            '\u{0430}' => 'a', // Cyrillic а
            '\u{0435}' => 'e', // Cyrillic е
            '\u{043E}' => 'o', // Cyrillic о
            '\u{0440}' => 'p', // Cyrillic р
            '\u{0441}' => 'c', // Cyrillic с
            '\u{0443}' => 'y', // Cyrillic у
            '\u{0445}' => 'x', // Cyrillic х
            '\u{0456}' => 'i', // Cyrillic і
            '\u{0455}' => 's', // Cyrillic ѕ
            // Cyrillic uppercase
            '\u{0410}' => 'A', // Cyrillic А
            '\u{0412}' => 'B', // Cyrillic В
            '\u{0415}' => 'E', // Cyrillic Е
            '\u{041A}' => 'K', // Cyrillic К
            '\u{041C}' => 'M', // Cyrillic М
            '\u{041D}' => 'H', // Cyrillic Н
            '\u{041E}' => 'O', // Cyrillic О
            '\u{0420}' => 'P', // Cyrillic Р
            '\u{0421}' => 'C', // Cyrillic С
            '\u{0422}' => 'T', // Cyrillic Т
            '\u{0425}' => 'X', // Cyrillic Х
            // Fullwidth ASCII (U+FF01..U+FF5E → U+0021..U+007E)
            '\u{FF01}'..='\u{FF5E}' => (c as u32 - 0xFF01 + 0x21) as u8 as char,
            _ => c,
        })
        .collect()
}

/// Collapse whitespace between identifier characters and `(` for pattern matching.
///
/// Catches attempts like `eval (` or `eval\t(` that try to evade `eval(`.
fn collapse_whitespace_before_parens(code: &str) -> String {
    let re = Regex::new(r"(\w)\s+\(").expect("valid regex");
    re.replace_all(code, "$1(").into_owned()
}

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

    // 3. Must be an async arrow function
    let trimmed = code.trim();
    if !trimmed.starts_with("async") {
        return Err(SandboxError::ValidationFailed {
            reason: "code must be an async arrow function, e.g. `async () => { ... }`. \
                     Do not provide bare statements — wrap your code in `async () => { ... }`"
                .into(),
        });
    }

    // 4. Banned patterns — check against normalized code to catch evasion attempts.
    //    The normalization pipeline: Unicode confusables → comment stripping → whitespace collapse.
    let normalized =
        collapse_whitespace_before_parens(&strip_js_comments(&normalize_unicode_confusables(code)));
    for pattern in BANNED_PATTERNS {
        if normalized.contains(pattern) {
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
        let code = format!("async () => {{ {} }}", "x".repeat(100));
        assert!(validate_code(&code, Some(50)).is_err());
        assert!(validate_code(&code, Some(200)).is_ok());
    }

    #[test]
    fn rejects_bare_statements() {
        let code = r#"return manifest.servers.map(s => s.name);"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::ValidationFailed { .. }));
        let msg = err.to_string();
        assert!(
            msg.contains("async arrow function"),
            "error should guide user to use async arrow: {msg}"
        );
    }

    #[test]
    fn rejects_non_async_function() {
        let code = r#"() => { return 42; }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::ValidationFailed { .. }));
    }

    // --- Evasion prevention tests ---

    #[test]
    fn rejects_eval_with_block_comment_bypass() {
        // eval/*trick*/( should still be caught after comment stripping
        let code = r#"async () => { return eval/*trick*/("1+1"); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_eval_with_line_comment_evasion() {
        // Multi-line evasion with line comment
        let code = "async () => { return eval//comment\n(\"1+1\"); }";
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_eval_with_whitespace_bypass() {
        // eval ( with space should be caught
        let code = r#"async () => { return eval ("1+1"); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_eval_with_tab_bypass() {
        let code = "async () => { return eval\t(\"1+1\"); }";
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_cyrillic_eval_homoglyph() {
        // Cyrillic е (U+0435) instead of Latin e
        let code = "async () => { return \u{0435}val(\"1+1\"); }";
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_cyrillic_deno_homoglyph() {
        // Cyrillic а (U+0430) and е (U+0435) in "Deno"
        let code = "async () => { return D\u{0435}no.readFile(\"/etc/passwd\"); }";
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_fullwidth_eval() {
        // Fullwidth e (U+FF45), v (U+FF56), a (U+FF41), l (U+FF4C)
        let code = "async () => { return \u{FF45}\u{FF56}\u{FF41}\u{FF4C}(\"1+1\"); }";
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_function_constructor_with_comment() {
        let code = r#"async () => { return Function/**/("return this")(); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn rejects_import_with_whitespace() {
        let code = r#"async () => { const m = await import ("fs"); }"#;
        let err = validate_code(code, None).unwrap_err();
        assert!(matches!(err, SandboxError::BannedPattern { .. }));
    }

    #[test]
    fn legitimate_comments_dont_cause_false_positives() {
        // A normal comment that happens to mention eval should be fine
        // because after stripping, the code itself doesn't contain eval(
        let code = r#"async () => { /* this does not use eval */ return 42; }"#;
        assert!(validate_code(code, None).is_ok());
    }
}
