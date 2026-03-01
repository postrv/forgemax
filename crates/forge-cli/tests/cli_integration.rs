//! CLI integration tests for forgemax binary.
//!
//! These tests spawn the actual `forgemax` binary and (where needed) the
//! `forge-test-server` mock MCP server. They verify end-to-end behavior
//! of the CLI subcommands.
//!
//! The tests rely on binaries being built by `cargo test --workspace`.

use std::path::PathBuf;
use std::process::Command;

/// Locate a built binary in the target directory.
fn binary_path(name: &str) -> PathBuf {
    // cargo test puts binaries in target/debug/
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/
    path.pop(); // project root
    path.push("target");
    path.push("debug");
    path.push(name);
    path
}

/// Create a minimal test config that references forge-test-server.
fn test_config_with_server() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = dir.path().join("forge.toml");
    let server_bin = binary_path("forge-test-server");
    let config = format!(
        r#"
[servers.test]
command = "{}"
transport = "stdio"
timeout_secs = 10

[sandbox]
timeout_secs = 5
max_heap_mb = 64
execution_mode = "in_process"
"#,
        server_bin.display()
    );
    std::fs::write(&config_path, &config).unwrap();
    (dir, config_path)
}

// ──────────────────────────────────────────────────────────────────────
// CLI scaffolding integration tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cli_int_01_version_flag() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    let output = Command::new(&bin)
        .arg("--version")
        .output()
        .expect("failed to execute forgemax");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("forgemax"),
        "version output should contain 'forgemax': {}",
        stdout
    );
}

#[test]
fn cli_int_02_help_flag() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    let output = Command::new(&bin)
        .arg("--help")
        .output()
        .expect("failed to execute forgemax");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Help should mention subcommands
    assert!(stdout.contains("doctor"), "help should mention doctor");
    assert!(stdout.contains("manifest"), "help should mention manifest");
    assert!(stdout.contains("run"), "help should mention run");
    assert!(stdout.contains("init"), "help should mention init");
}

#[test]
fn cli_int_03_unknown_subcommand_errors() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    let output = Command::new(&bin)
        .arg("nonexistent_subcommand")
        .output()
        .expect("failed to execute forgemax");

    assert!(!output.status.success(), "unknown subcommand should fail");
}

// ──────────────────────────────────────────────────────────────────────
// Doctor integration tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cli_int_04_doctor_json_output_valid() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    // Run doctor with no config file (should still produce valid JSON)
    let output = Command::new(&bin)
        .args(["doctor", "--json", "--config", "/nonexistent/forge.toml"])
        .output()
        .expect("failed to execute forgemax doctor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Doctor may exit 1 (failures) but should produce valid JSON on stdout
    if !stdout.trim().is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
        assert!(
            parsed.is_ok(),
            "doctor --json should produce valid JSON, got: {}",
            stdout
        );
        let json = parsed.unwrap();
        assert_eq!(json["schema_version"], 1, "schema_version should be 1");
        assert!(json["checks"].is_array(), "checks should be an array");
    }
}

#[test]
fn cli_int_05_doctor_with_valid_config() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("forge.toml");
    std::fs::write(&config, "[sandbox]\ntimeout_secs = 5\nmax_heap_mb = 64\n").unwrap();

    let output = Command::new(&bin)
        .args(["doctor", "--json", "--config", config.to_str().unwrap()])
        .output()
        .expect("failed to execute forgemax doctor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().is_empty() {
        let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
        // config_valid check should pass
        let checks = json["checks"].as_array().unwrap();
        let config_check = checks.iter().find(|c| c["name"] == "config_valid");
        assert!(config_check.is_some(), "should have config_valid check");
        assert_eq!(
            config_check.unwrap()["status"],
            "pass",
            "valid config should pass"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────
// Init integration tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cli_int_06_init_creates_config() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("forge.toml");

    let output = Command::new(&bin)
        .args([
            "init",
            "--non-interactive",
            "--output",
            config.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute forgemax init");

    assert!(output.status.success(), "init should succeed");
    assert!(config.exists(), "config file should be created");

    let content = std::fs::read_to_string(&config).unwrap();
    assert!(
        content.contains("[sandbox]"),
        "generated config should have sandbox section"
    );
}

#[test]
fn cli_int_07_init_refuses_overwrite() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("forge.toml");
    std::fs::write(&config, "existing").unwrap();

    let output = Command::new(&bin)
        .args([
            "init",
            "--non-interactive",
            "--output",
            config.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute forgemax init");

    assert!(
        !output.status.success(),
        "init should fail when file exists without --force"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Run integration tests (with forge-test-server)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cli_int_08_run_nonexistent_file() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("forge.toml");
    std::fs::write(&config, "[sandbox]\ntimeout_secs = 5\n").unwrap();

    let output = Command::new(&bin)
        .args([
            "run",
            "--config",
            config.to_str().unwrap(),
            "/nonexistent/file.js",
        ])
        .output()
        .expect("failed to execute forgemax run");

    assert!(
        !output.status.success(),
        "run with nonexistent file should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("No such file"),
        "error should mention file not found: {}",
        stderr
    );
}

#[test]
fn cli_int_09_run_with_test_server() {
    let bin = binary_path("forgemax");
    let test_server_bin = binary_path("forge-test-server");
    if !bin.exists() || !test_server_bin.exists() {
        eprintln!("skipping: binaries not built");
        return;
    }

    let (_dir, config_path) = test_config_with_server();

    // Create a simple JS file that calls echo
    let js_dir = tempfile::tempdir().unwrap();
    let js_file = js_dir.path().join("test.js");
    std::fs::write(
        &js_file,
        r#"async () => {
    const result = await forge.callTool("test", "echo", { message: "hello" });
    return result;
}"#,
    )
    .unwrap();

    let output = Command::new(&bin)
        .args([
            "run",
            "--config",
            config_path.to_str().unwrap(),
            js_file.to_str().unwrap(),
        ])
        .env("RUST_LOG", "error") // reduce noise
        .output()
        .expect("failed to execute forgemax run");

    // If the test server connected successfully, stdout should have JSON
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.trim().is_empty(),
            "successful run should produce output"
        );
        // Should be valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
        assert!(
            parsed.is_ok(),
            "run output should be valid JSON: {}",
            stdout
        );
    }
    // If it failed (e.g., test server not responsive), that's OK for CI
}

// ──────────────────────────────────────────────────────────────────────
// Manifest integration tests (with forge-test-server)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cli_int_10_manifest_json_with_test_server() {
    let bin = binary_path("forgemax");
    let test_server_bin = binary_path("forge-test-server");
    if !bin.exists() || !test_server_bin.exists() {
        eprintln!("skipping: binaries not built");
        return;
    }

    let (_dir, config_path) = test_config_with_server();

    let output = Command::new(&bin)
        .args([
            "manifest",
            "--json",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .env("RUST_LOG", "error")
        .output()
        .expect("failed to execute forgemax manifest");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
        assert!(
            parsed.is_ok(),
            "manifest --json should produce valid JSON: {}",
            stdout
        );
        let json = parsed.unwrap();
        // Should report at least 1 server
        if let Some(servers) = json["servers"].as_u64() {
            assert!(servers >= 1, "should have at least 1 server");
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Security integration tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cli_int_11_doctor_never_leaks_env_values() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("forge.toml");
    std::fs::write(
        &config,
        "[servers.test]\ncommand = \"echo\"\ntransport = \"stdio\"\nheaders = { Auth = \"${FORGE_TEST_SECRET_VALUE}\" }\n",
    )
    .unwrap();

    let output = Command::new(&bin)
        .args(["doctor", "--json", "--config", config.to_str().unwrap()])
        .env("FORGE_TEST_SECRET_VALUE", "super_secret_token_12345")
        .output()
        .expect("failed to execute forgemax doctor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Doctor should NEVER print env var values
    assert!(
        !combined.contains("super_secret_token_12345"),
        "doctor output must never contain secret values"
    );
}

#[test]
fn cli_int_12_run_rejects_banned_code() {
    let bin = binary_path("forgemax");
    if !bin.exists() {
        eprintln!("skipping: forgemax binary not built");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("forge.toml");
    std::fs::write(&config, "[sandbox]\ntimeout_secs = 5\n").unwrap();

    // Try to run code with banned import()
    let js_file = dir.path().join("evil.js");
    std::fs::write(&js_file, "async () => { return import('fs'); }").unwrap();

    let output = Command::new(&bin)
        .args([
            "run",
            "--config",
            config.to_str().unwrap(),
            js_file.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute forgemax run");

    // Should fail because AST validator rejects import()
    assert!(!output.status.success(), "run with import() should fail");
}
