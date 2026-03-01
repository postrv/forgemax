//! Validate that all example JavaScript files pass AST validation and are well-formed.

use std::path::PathBuf;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
}

fn js_examples() -> Vec<PathBuf> {
    let dir = examples_dir();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "js") {
            files.push(path);
        }
    }
    files.sort();
    files
}

#[test]
#[cfg(feature = "ast-validator")]
fn ex_01_all_examples_pass_ast_validation() {
    let files = js_examples();
    assert!(!files.is_empty(), "no JS example files found");

    for file in &files {
        let code = std::fs::read_to_string(file).unwrap();
        let result = forge_sandbox::ast_validator::validate_ast(&code);
        assert!(
            result.is_ok(),
            "AST validation failed for {}: {:?}",
            file.display(),
            result.err()
        );
    }
}

#[test]
fn ex_02_all_examples_are_valid_utf8() {
    let files = js_examples();
    for file in &files {
        let bytes = std::fs::read(file).unwrap();
        assert!(
            std::str::from_utf8(&bytes).is_ok(),
            "{} is not valid UTF-8",
            file.display()
        );
        // No BOM
        assert!(
            !bytes.starts_with(&[0xEF, 0xBB, 0xBF]),
            "{} has a UTF-8 BOM",
            file.display()
        );
    }
}

#[test]
fn ex_03_all_examples_have_header_comments() {
    let files = js_examples();
    for file in &files {
        let code = std::fs::read_to_string(file).unwrap();
        assert!(
            code.contains("@prompt"),
            "{} missing @prompt header",
            file.display()
        );
        assert!(
            code.contains("@features"),
            "{} missing @features header",
            file.display()
        );
        assert!(
            code.contains("@output"),
            "{} missing @output header",
            file.display()
        );
        assert!(
            code.contains("@servers"),
            "{} missing @servers header",
            file.display()
        );
    }
}

#[test]
#[cfg(feature = "ast-validator")]
fn ex_04_no_banned_patterns() {
    let files = js_examples();
    for file in &files {
        let code = std::fs::read_to_string(file).unwrap();
        // These should never appear in uncommented code
        let active_lines: Vec<&str> = code
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        let active = active_lines.join("\n");

        for banned in &["import(", "require(", "Deno.", "process.env"] {
            assert!(
                !active.contains(banned),
                "{} contains banned pattern: {}",
                file.display(),
                banned
            );
        }
    }
}

#[test]
fn ex_07_group_configs_parse() {
    let dir = examples_dir().join("group-isolation");
    for name in &["forge.toml.strict", "forge.toml.open"] {
        let path = dir.join(name);
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        let result = forge_config::ForgeConfig::from_toml(&content);
        assert!(
            result.is_ok(),
            "group config {} failed to parse: {:?}",
            name,
            result.err()
        );
    }
}

#[test]
#[cfg(feature = "ast-validator")]
fn ex_09_hero_example_validates() {
    let path = examples_dir().join("parallel-stash-pipeline.js");
    let code = std::fs::read_to_string(&path).unwrap();
    let result = forge_sandbox::ast_validator::validate_ast(&code);
    assert!(
        result.is_ok(),
        "hero example failed AST validation: {:?}",
        result.err()
    );
}

#[test]
fn ex_05_no_hardcoded_secrets() {
    let files = js_examples();
    for file in &files {
        let code = std::fs::read_to_string(file).unwrap();
        // Check for common secret patterns in non-comment lines
        let active_lines: Vec<&str> = code
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        let active = active_lines.join("\n");

        for pattern in &[
            "sk-",            // API keys
            "ghp_",           // GitHub personal access tokens
            "password",       // Hardcoded passwords
            "Bearer ",        // Hardcoded bearer tokens
            "Authorization:", // Hardcoded auth headers
        ] {
            assert!(
                !active.contains(pattern),
                "{} contains potential secret pattern: {}",
                file.display(),
                pattern
            );
        }
    }
}

#[test]
fn ex_06_example_sizes_reasonable() {
    let files = js_examples();
    for file in &files {
        let meta = std::fs::metadata(file).unwrap();
        // Examples should be concise: under 10KB each
        assert!(
            meta.len() < 10 * 1024,
            "{} is too large: {} bytes (max 10KB for examples)",
            file.display(),
            meta.len()
        );
        // And non-empty
        assert!(
            meta.len() > 10,
            "{} is suspiciously small: {} bytes",
            file.display(),
            meta.len()
        );
    }
}

#[test]
fn ex_08_group_isolation_configs_have_groups() {
    let dir = examples_dir().join("group-isolation");

    // Strict config should have strict isolation groups
    let strict_content = std::fs::read_to_string(dir.join("forge.toml.strict")).unwrap();
    let strict_config = forge_config::ForgeConfig::from_toml(&strict_content).unwrap();
    assert!(
        !strict_config.groups.is_empty(),
        "strict config should define groups"
    );
    let has_strict = strict_config
        .groups
        .values()
        .any(|g| g.isolation == "strict");
    assert!(has_strict, "strict config should have strict isolation");

    // Open config should have open isolation groups
    let open_content = std::fs::read_to_string(dir.join("forge.toml.open")).unwrap();
    let open_config = forge_config::ForgeConfig::from_toml(&open_content).unwrap();
    assert!(
        !open_config.groups.is_empty(),
        "open config should define groups"
    );
    let has_open = open_config.groups.values().any(|g| g.isolation == "open");
    assert!(has_open, "open config should have open isolation");
}

#[test]
fn ex_10_examples_count() {
    let files = js_examples();
    assert!(
        files.len() >= 7,
        "expected at least 7 JS examples, found {}",
        files.len()
    );
}
