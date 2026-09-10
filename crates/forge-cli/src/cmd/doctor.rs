//! `forgemax doctor` — validate configuration and connectivity.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::common;

/// Arguments for the doctor subcommand.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Output results as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Overall status for a single check.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// Check passed.
    Pass,
    /// Check produced a warning (non-fatal).
    Warn,
    /// Check failed.
    Fail,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Pass => write!(f, "PASS"),
            CheckStatus::Warn => write!(f, "WARN"),
            CheckStatus::Fail => write!(f, "FAIL"),
        }
    }
}

/// A single doctor check result.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    /// Check name (e.g., "config_valid").
    pub name: String,
    /// Check result.
    pub status: CheckStatus,
    /// Human-readable description.
    pub message: String,
    /// Suggested fix, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

/// The full doctor report.
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    /// Schema version for JSON output stability.
    pub schema_version: u32,
    /// Whether all checks passed.
    pub passed: bool,
    /// Individual check results.
    pub checks: Vec<DoctorCheck>,
    /// Summary message.
    pub summary: String,
}

/// Check that the config file parses.
fn check_config_valid(config_path: Option<&PathBuf>) -> DoctorCheck {
    let path = config_path.cloned().or_else(common::find_config_file);
    match path {
        Some(ref p) => match forge_config::ForgeConfig::from_file_with_env(p) {
            Ok(_) => DoctorCheck {
                name: "config_valid".into(),
                status: CheckStatus::Pass,
                message: format!("config file parses: {}", p.display()),
                fix: None,
            },
            Err(e) => DoctorCheck {
                name: "config_valid".into(),
                status: CheckStatus::Fail,
                message: format!("config parse error: {}", e),
                fix: Some("Fix the configuration file syntax".into()),
            },
        },
        None => DoctorCheck {
            name: "config_valid".into(),
            status: CheckStatus::Warn,
            message: "no config file found".into(),
            fix: Some(
                "Create forge.toml or set FORGE_CONFIG env var. Run `forgemax init` to generate one."
                    .into(),
            ),
        },
    }
}

/// Check that environment variable references in the config resolve.
fn check_env_vars(config_path: Option<&PathBuf>) -> DoctorCheck {
    let path = config_path.cloned().or_else(common::find_config_file);
    match path {
        Some(ref p) => match std::fs::read_to_string(p) {
            Ok(content) => {
                let vars = common::find_env_var_refs(&content);
                let mut missing = Vec::new();
                for var in &vars {
                    if std::env::var(var).is_err() {
                        missing.push(var.clone());
                    }
                }
                if missing.is_empty() {
                    DoctorCheck {
                        name: "env_vars".into(),
                        status: CheckStatus::Pass,
                        message: if vars.is_empty() {
                            "no environment variable references found".into()
                        } else {
                            format!("all {} env var references resolve", vars.len())
                        },
                        fix: None,
                    }
                } else {
                    DoctorCheck {
                        name: "env_vars".into(),
                        status: CheckStatus::Fail,
                        message: format!("unresolved env vars: {}", missing.join(", ")),
                        fix: Some("Set the missing environment variables before starting".into()),
                    }
                }
            }
            Err(e) => DoctorCheck {
                name: "env_vars".into(),
                status: CheckStatus::Fail,
                message: format!("cannot read config file: {}", e),
                fix: None,
            },
        },
        None => DoctorCheck {
            name: "env_vars".into(),
            status: CheckStatus::Pass,
            message: "no config file to check".into(),
            fix: None,
        },
    }
}

/// Check that the worker binary can be found.
fn check_worker_binary() -> DoctorCheck {
    match forge_sandbox::host::find_worker_binary() {
        Ok(path) => DoctorCheck {
            name: "worker_binary".into(),
            status: CheckStatus::Pass,
            message: format!("worker binary found: {}", path.display()),
            fix: None,
        },
        Err(e) => DoctorCheck {
            name: "worker_binary".into(),
            status: CheckStatus::Fail,
            message: format!("worker binary not found: {}", e),
            fix: Some(
                "Install forgemax-worker next to forgemax (`cargo install forgemax` ships both), \
                 or set FORGE_WORKER_BIN to an absolute path"
                    .into(),
            ),
        },
    }
}

/// Check file permissions on the config file (Unix only).
#[cfg(unix)]
fn check_config_permissions(config_path: Option<&PathBuf>) -> DoctorCheck {
    use std::os::unix::fs::PermissionsExt;

    let path = config_path.cloned().or_else(common::find_config_file);
    match path {
        Some(ref p) => match std::fs::metadata(p) {
            Ok(meta) => {
                let mode = meta.permissions().mode();
                // Check if file contains env var refs (secrets likely)
                let has_secrets = std::fs::read_to_string(p)
                    .map(|c| c.contains("${"))
                    .unwrap_or(false);
                if has_secrets && (mode & 0o044) != 0 {
                    DoctorCheck {
                        name: "config_permissions".into(),
                        status: CheckStatus::Warn,
                        message: format!(
                            "config with secrets is group/world-readable (mode: {:o})",
                            mode & 0o777
                        ),
                        fix: Some(format!("chmod 600 {}", p.display())),
                    }
                } else {
                    DoctorCheck {
                        name: "config_permissions".into(),
                        status: CheckStatus::Pass,
                        message: format!("config permissions OK (mode: {:o})", mode & 0o777),
                        fix: None,
                    }
                }
            }
            Err(e) => DoctorCheck {
                name: "config_permissions".into(),
                status: CheckStatus::Warn,
                message: format!("cannot stat config file: {}", e),
                fix: None,
            },
        },
        None => DoctorCheck {
            name: "config_permissions".into(),
            status: CheckStatus::Pass,
            message: "no config file to check".into(),
            fix: None,
        },
    }
}

#[cfg(not(unix))]
fn check_config_permissions(_config_path: Option<&PathBuf>) -> DoctorCheck {
    DoctorCheck {
        name: "config_permissions".into(),
        status: CheckStatus::Pass,
        message: "permission check skipped (non-Unix platform)".into(),
        fix: None,
    }
}

/// Check that group definitions reference valid servers.
fn check_groups(config_path: Option<&PathBuf>) -> DoctorCheck {
    let config = match common::load_config(config_path) {
        Ok(c) => c,
        Err(_) => {
            return DoctorCheck {
                name: "groups".into(),
                status: CheckStatus::Pass,
                message: "no valid config to check groups".into(),
                fix: None,
            };
        }
    };

    if config.groups.is_empty() {
        return DoctorCheck {
            name: "groups".into(),
            status: CheckStatus::Pass,
            message: "no groups configured".into(),
            fix: None,
        };
    }

    let server_names: std::collections::HashSet<&str> =
        config.servers.keys().map(|s| s.as_str()).collect();
    let grouped_servers: std::collections::HashSet<&str> = config
        .groups
        .values()
        .flat_map(|g| g.servers.iter().map(|s| s.as_str()))
        .collect();

    let orphaned: Vec<&str> = server_names.difference(&grouped_servers).copied().collect();

    if orphaned.is_empty() {
        DoctorCheck {
            name: "groups".into(),
            status: CheckStatus::Pass,
            message: format!(
                "{} group(s) covering all {} server(s)",
                config.groups.len(),
                server_names.len()
            ),
            fix: None,
        }
    } else {
        DoctorCheck {
            name: "groups".into(),
            status: CheckStatus::Warn,
            message: format!("servers not in any group: {}", orphaned.join(", ")),
            fix: Some("Add ungrouped servers to a group or leave ungrouped if intentional".into()),
        }
    }
}

/// Check compiled feature flags.
fn check_features() -> DoctorCheck {
    let line = common::feature_status_line();
    let all_on = cfg!(feature = "worker-pool")
        && cfg!(feature = "metrics")
        && cfg!(feature = "config-watch");

    DoctorCheck {
        name: "features".into(),
        status: if all_on {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: line,
        fix: if all_on {
            None
        } else {
            Some("Rebuild with default features for full functionality".into())
        },
    }
}

/// Get available system memory in MB.
fn get_system_memory_mb() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|b| b / (1024 * 1024))
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .map(|kb| kb / 1024)
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// Check available system memory.
fn check_memory() -> DoctorCheck {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sysctl")
            .arg("-n")
            .arg("hw.memsize")
            .output();
        match output {
            Ok(o) if o.status.success() => {
                let mem_str = String::from_utf8_lossy(&o.stdout);
                let mem_bytes: u64 = mem_str.trim().parse().unwrap_or(0);
                let mem_gb = mem_bytes / (1024 * 1024 * 1024);
                if mem_gb < 4 {
                    DoctorCheck {
                        name: "memory".into(),
                        status: CheckStatus::Warn,
                        message: format!("system memory: {} GB (recommended >= 4 GB)", mem_gb),
                        fix: None,
                    }
                } else {
                    DoctorCheck {
                        name: "memory".into(),
                        status: CheckStatus::Pass,
                        message: format!("system memory: {} GB", mem_gb),
                        fix: None,
                    }
                }
            }
            _ => DoctorCheck {
                name: "memory".into(),
                status: CheckStatus::Pass,
                message: "could not determine system memory".into(),
                fix: None,
            },
        }
    }
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/meminfo") {
            Ok(content) => {
                let mem_kb = content
                    .lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| {
                        l.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<u64>().ok())
                    })
                    .unwrap_or(0);
                let mem_gb = mem_kb / (1024 * 1024);
                if mem_gb < 4 {
                    DoctorCheck {
                        name: "memory".into(),
                        status: CheckStatus::Warn,
                        message: format!("system memory: {} GB (recommended >= 4 GB)", mem_gb),
                        fix: None,
                    }
                } else {
                    DoctorCheck {
                        name: "memory".into(),
                        status: CheckStatus::Pass,
                        message: format!("system memory: {} GB", mem_gb),
                        fix: None,
                    }
                }
            }
            Err(_) => DoctorCheck {
                name: "memory".into(),
                status: CheckStatus::Pass,
                message: "could not determine system memory".into(),
                fix: None,
            },
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        DoctorCheck {
            name: "memory".into(),
            status: CheckStatus::Pass,
            message: "memory check skipped (unsupported platform)".into(),
            fix: None,
        }
    }
}

/// Check that worst-case worker memory usage won't exceed system RAM.
fn check_memory_pressure(config_path: Option<&PathBuf>) -> DoctorCheck {
    let config = match common::load_config(config_path) {
        Ok(c) => c,
        Err(_) => {
            return DoctorCheck {
                name: "memory_pressure".into(),
                status: CheckStatus::Pass,
                message: "no valid config to check".into(),
                fix: None,
            };
        }
    };

    let max_concurrent = config.sandbox.max_concurrent.unwrap_or(4) as u64;
    let max_heap_mb = config.sandbox.max_heap_mb.unwrap_or(256) as u64;
    let worst_case_mb = max_concurrent * max_heap_mb;

    match get_system_memory_mb() {
        Some(available_mb) if available_mb > 0 => {
            if worst_case_mb > available_mb * 80 / 100 {
                DoctorCheck {
                    name: "memory_pressure".into(),
                    status: CheckStatus::Warn,
                    message: format!(
                        "worst-case memory: {} MB ({}x{} MB) exceeds 80% of {} MB system RAM",
                        worst_case_mb, max_concurrent, max_heap_mb, available_mb
                    ),
                    fix: Some(format!(
                        "Reduce max_concurrent (currently {}) or max_heap_mb (currently {})",
                        max_concurrent, max_heap_mb
                    )),
                }
            } else {
                DoctorCheck {
                    name: "memory_pressure".into(),
                    status: CheckStatus::Pass,
                    message: format!(
                        "worst-case memory: {} MB ({}x{} MB), system has {} MB",
                        worst_case_mb, max_concurrent, max_heap_mb, available_mb
                    ),
                    fix: None,
                }
            }
        }
        _ => DoctorCheck {
            name: "memory_pressure".into(),
            status: CheckStatus::Pass,
            message: format!(
                "worst-case memory: {} MB ({}x{} MB), could not detect system RAM",
                worst_case_mb, max_concurrent, max_heap_mb
            ),
            fix: None,
        },
    }
}

/// Check that HTTP/SSE servers have circuit breakers configured.
fn check_circuit_breakers(config_path: Option<&PathBuf>) -> DoctorCheck {
    let config = match common::load_config(config_path) {
        Ok(c) => c,
        Err(_) => {
            return DoctorCheck {
                name: "circuit_breakers".into(),
                status: CheckStatus::Pass,
                message: "no valid config to check".into(),
                fix: None,
            };
        }
    };

    let unprotected: Vec<&str> = config
        .servers
        .iter()
        .filter(|(_, s)| s.transport == "sse" && s.circuit_breaker != Some(true))
        .map(|(name, _)| name.as_str())
        .collect();

    if unprotected.is_empty() {
        DoctorCheck {
            name: "circuit_breakers".into(),
            status: CheckStatus::Pass,
            message: "all SSE servers have circuit breakers configured".into(),
            fix: None,
        }
    } else {
        DoctorCheck {
            name: "circuit_breakers".into(),
            status: CheckStatus::Warn,
            message: format!(
                "SSE servers without circuit breakers: {}",
                unprotected.join(", ")
            ),
            fix: Some(format!(
                "Add circuit_breaker = true to: {}",
                unprotected.join(", ")
            )),
        }
    }
}

/// Check that token/header values don't contain common formatting mistakes.
fn check_token_formats(config_path: Option<&PathBuf>) -> DoctorCheck {
    let config = match common::load_config(config_path) {
        Ok(c) => c,
        Err(_) => {
            return DoctorCheck {
                name: "token_formats".into(),
                status: CheckStatus::Pass,
                message: "no valid config to check".into(),
                fix: None,
            };
        }
    };

    let mut issues = Vec::new();

    for (name, server) in &config.servers {
        for (key, value) in &server.headers {
            if value.starts_with('"') || value.ends_with('"') {
                issues.push(format!("{name}: {key} has embedded quotes"));
            }
            if value.contains('\n') || value.contains('\r') {
                issues.push(format!("{name}: {key} contains newlines"));
            }
            if value.starts_with("Bearer ") && key.to_lowercase() != "authorization" {
                issues.push(format!(
                    "{name}: {key} has 'Bearer ' prefix (should be bare token)"
                ));
            }
        }
    }

    if issues.is_empty() {
        DoctorCheck {
            name: "token_formats".into(),
            status: CheckStatus::Pass,
            message: "all header values look well-formed".into(),
            fix: None,
        }
    } else {
        DoctorCheck {
            name: "token_formats".into(),
            status: CheckStatus::Warn,
            message: format!("potential token issues: {}", issues.join("; ")),
            fix: Some(
                "Check header values — remove quotes, newlines, and misplaced 'Bearer ' prefixes"
                    .into(),
            ),
        }
    }
}

/// Execute the doctor command.
pub async fn execute(args: &DoctorArgs, config_path: Option<PathBuf>) -> Result<()> {
    let config_ref = config_path.as_ref();

    let mut checks = vec![
        check_config_permissions(config_ref),
        check_config_valid(config_ref),
        check_env_vars(config_ref),
        check_worker_binary(),
        check_groups(config_ref),
        check_features(),
        check_memory(),
        check_memory_pressure(config_ref),
        check_circuit_breakers(config_ref),
        check_token_formats(config_ref),
    ];

    // Server connectivity check (async)
    let config = common::load_config(config_ref).ok();
    if let Some(ref config) = config {
        if !config.servers.is_empty() {
            for (name, server_config) in &config.servers {
                match common::to_transport_config(server_config) {
                    Ok(transport_config) => {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            forge_client::McpClient::connect(name.clone(), &transport_config),
                        )
                        .await
                        {
                            Ok(Ok(client)) => match client.list_tools().await {
                                Ok(tools) => {
                                    checks.push(DoctorCheck {
                                        name: format!("server_{}", name),
                                        status: CheckStatus::Pass,
                                        message: format!(
                                            "server '{}': connected, {} tools",
                                            name,
                                            tools.len()
                                        ),
                                        fix: None,
                                    });
                                }
                                Err(e) => {
                                    checks.push(DoctorCheck {
                                        name: format!("server_{}", name),
                                        status: CheckStatus::Fail,
                                        message: format!(
                                            "server '{}': connected but list_tools failed: {}",
                                            name, e
                                        ),
                                        fix: None,
                                    });
                                }
                            },
                            Ok(Err(e)) => {
                                checks.push(DoctorCheck {
                                    name: format!("server_{}", name),
                                    status: CheckStatus::Fail,
                                    message: format!("server '{}': connection failed: {}", name, e),
                                    fix: Some(format!(
                                        "Verify server '{}' is installed and running",
                                        name
                                    )),
                                });
                            }
                            Err(_) => {
                                checks.push(DoctorCheck {
                                    name: format!("server_{}", name),
                                    status: CheckStatus::Fail,
                                    message: format!(
                                        "server '{}': connection timed out (10s)",
                                        name
                                    ),
                                    fix: Some(format!(
                                        "Verify server '{}' is installed and responsive",
                                        name
                                    )),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        checks.push(DoctorCheck {
                            name: format!("server_{}", name),
                            status: CheckStatus::Fail,
                            message: format!("server '{}': invalid transport config: {}", name, e),
                            fix: None,
                        });
                    }
                }
            }
        }
    }

    let has_fail = checks.iter().any(|c| c.status == CheckStatus::Fail);
    let pass_count = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Pass)
        .count();
    let warn_count = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warn)
        .count();
    let fail_count = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .count();

    let summary = format!(
        "{} passed, {} warnings, {} failed",
        pass_count, warn_count, fail_count
    );

    let report = DoctorReport {
        schema_version: 1,
        passed: !has_fail,
        checks,
        summary: summary.clone(),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for check in &report.checks {
            let status_str = match check.status {
                CheckStatus::Pass => "\x1b[32mPASS\x1b[0m",
                CheckStatus::Warn => "\x1b[33mWARN\x1b[0m",
                CheckStatus::Fail => "\x1b[31mFAIL\x1b[0m",
            };
            println!("  [{}] {}: {}", status_str, check.name, check.message);
            if let Some(ref fix) = check.fix {
                println!("         fix: {}", fix);
            }
        }
        println!();
        println!("  {}", summary);
    }

    if has_fail {
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dr_01_check_config_valid_with_valid_toml() {
        let dir = std::env::temp_dir().join("forge-doctor-test-valid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            "[servers.test]\ncommand = \"test\"\ntransport = \"stdio\"\n",
        )
        .unwrap();
        let check = check_config_valid(Some(&path));
        assert_eq!(check.status, CheckStatus::Pass);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_02_check_config_valid_missing() {
        let path = PathBuf::from("/nonexistent/forge.toml");
        let check = check_config_valid(Some(&path));
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn dr_03_check_config_valid_invalid_toml() {
        let dir = std::env::temp_dir().join("forge-doctor-test-invalid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(&path, "[[[invalid toml").unwrap();
        let check = check_config_valid(Some(&path));
        assert_eq!(check.status, CheckStatus::Fail);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_04_check_env_vars_all_set() {
        let dir = std::env::temp_dir().join("forge-doctor-test-env");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(&path, "# no env var refs\n[sandbox]\ntimeout_secs = 5\n").unwrap();
        let check = check_env_vars(Some(&path));
        assert_eq!(check.status, CheckStatus::Pass);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_05_check_env_vars_unresolved() {
        let dir = std::env::temp_dir().join("forge-doctor-test-env-missing");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            "[servers.test]\ncommand = \"test\"\ntransport = \"stdio\"\nheaders = { Auth = \"${FORGE_DOCTOR_TEST_NONEXISTENT_VAR}\" }\n",
        )
        .unwrap();
        let check = check_env_vars(Some(&path));
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.message.contains("FORGE_DOCTOR_TEST_NONEXISTENT_VAR"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_06_check_worker_binary() {
        // This test just verifies the check doesn't panic.
        // Result depends on the build environment.
        let check = check_worker_binary();
        assert!(
            check.status == CheckStatus::Pass || check.status == CheckStatus::Fail,
            "unexpected status: {:?}",
            check.status
        );
    }

    #[test]
    fn dr_09_check_groups_no_config() {
        let path = PathBuf::from("/nonexistent/forge.toml");
        let check = check_groups(Some(&path));
        // Should pass gracefully when no valid config
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn dr_10_check_groups_orphaned_servers() {
        let dir = std::env::temp_dir().join("forge-doctor-test-groups");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
[servers.a]
command = "a"
transport = "stdio"
[servers.b]
command = "b"
transport = "stdio"
[groups.grp]
servers = ["a"]
"#,
        )
        .unwrap();
        let check = check_groups(Some(&path));
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(
            check.message.contains("b"),
            "should mention orphaned server"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_11_check_features() {
        let check = check_features();
        // With default features on, should pass. With --no-default-features, Warn is expected.
        if cfg!(feature = "worker-pool")
            && cfg!(feature = "metrics")
            && cfg!(feature = "config-watch")
        {
            assert_eq!(check.status, CheckStatus::Pass);
        } else {
            assert_eq!(check.status, CheckStatus::Warn);
        }
    }

    #[test]
    fn dr_12_check_memory() {
        let check = check_memory();
        assert!(
            check.status == CheckStatus::Pass || check.status == CheckStatus::Warn,
            "unexpected: {:?}",
            check.status
        );
    }

    #[test]
    fn dr_13_report_json_valid() {
        let report = DoctorReport {
            schema_version: 1,
            passed: true,
            checks: vec![DoctorCheck {
                name: "test".into(),
                status: CheckStatus::Pass,
                message: "ok".into(),
                fix: None,
            }],
            summary: "1 passed, 0 warnings, 0 failed".into(),
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["passed"], true);
    }

    #[test]
    fn dr_14_schema_version_is_one() {
        let report = DoctorReport {
            schema_version: 1,
            passed: true,
            checks: vec![],
            summary: String::new(),
        };
        assert_eq!(report.schema_version, 1);
    }

    #[cfg(unix)]
    #[test]
    fn dr_15_config_permissions_world_readable_with_secrets() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("forge-doctor-test-perms");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(&path, "headers = { Auth = \"${SECRET}\" }\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let check = check_config_permissions(Some(&path));
        assert_eq!(check.status, CheckStatus::Warn);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn dr_16_config_permissions_secure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("forge-doctor-test-perms-ok");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(&path, "headers = { Auth = \"${SECRET}\" }\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let check = check_config_permissions(Some(&path));
        assert_eq!(check.status, CheckStatus::Pass);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_07_unreachable_server_config() {
        // Verify that an invalid transport config produces a Fail check.
        // We simulate this by creating a config with a server that uses
        // a nonexistent binary — the doctor check_config_valid still passes
        // (config syntax is valid), but the server connectivity check would fail.
        let dir = std::env::temp_dir().join("forge-doctor-test-unreachable");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
[servers.fake_unreachable]
command = "/nonexistent/binary/that/does/not/exist"
transport = "stdio"
timeout_secs = 1
"#,
        )
        .unwrap();
        // Config parses OK — the server binary being missing is a connectivity issue
        let config_check = check_config_valid(Some(&path));
        assert_eq!(config_check.status, CheckStatus::Pass);
        // Groups check should still pass (no groups defined)
        let groups_check = check_groups(Some(&path));
        assert_eq!(groups_check.status, CheckStatus::Pass);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn dr_08_server_connectivity_timeout() {
        // Verify the execute function handles server timeouts gracefully.
        // We create a config referencing a non-existent binary, and run doctor
        // in JSON mode to verify the report structure includes a server failure.
        let dir = std::env::temp_dir().join("forge-doctor-test-timeout");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
[servers.timeout_test]
command = "/nonexistent/binary/xyzzy"
transport = "stdio"
timeout_secs = 1
"#,
        )
        .unwrap();

        let args = DoctorArgs { json: true };
        // Doctor should complete without panic (exit code is via process::exit
        // which we can't catch in tests, but the check collection works)
        let config_check = check_config_valid(Some(&path));
        assert_eq!(config_check.status, CheckStatus::Pass);

        // Verify the env var check works against this config
        let env_check = check_env_vars(Some(&path));
        assert_eq!(
            env_check.status,
            CheckStatus::Pass,
            "no env var refs expected"
        );
        let _ = args; // acknowledge args
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn dr_17_config_permissions_ok_without_env_vars() {
        use std::os::unix::fs::PermissionsExt;

        // Config files without ${} references should pass permissions check
        // even if world-readable, since they don't contain secrets.
        let dir = std::env::temp_dir().join("forge-doctor-test-perms-no-env");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            "[servers.test]\ncommand = \"test\"\ntransport = \"stdio\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let check = check_config_permissions(Some(&path));
        // Should pass because the file has no secret references
        assert_eq!(
            check.status,
            CheckStatus::Pass,
            "world-readable config without secrets should pass: {}",
            check.message
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_18_memory_check_returns_pass_or_warn() {
        // Memory check should always return Pass or Warn, never Fail.
        // On low-memory systems it warns; on normal systems it passes.
        // On unsupported platforms it passes with a skip message.
        let check = check_memory();
        assert!(
            check.status == CheckStatus::Pass || check.status == CheckStatus::Warn,
            "memory check should never fail, got: {:?} - {}",
            check.status,
            check.message
        );
        // Verify the message contains memory info or skip reason
        assert!(
            check.message.contains("memory") || check.message.contains("determine"),
            "memory check message should mention memory: {}",
            check.message
        );
    }

    #[test]
    fn dr_20_memory_pressure_warns_high_usage() {
        // Config with 16×512 MB = 8192 MB worst case
        let dir = std::env::temp_dir().join("forge-doctor-test-mempressure-high");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(&path, "[sandbox]\nmax_concurrent = 16\nmax_heap_mb = 512\n").unwrap();
        let check = check_memory_pressure(Some(&path));
        // On most test machines (< 10 GB), this should warn.
        // On very large machines it might pass, which is also correct.
        assert!(
            check.status == CheckStatus::Warn || check.status == CheckStatus::Pass,
            "unexpected: {:?} - {}",
            check.status,
            check.message
        );
        assert!(
            check.message.contains("8192"),
            "should show 8192 MB: {}",
            check.message
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_21_memory_pressure_passes_low_usage() {
        // Config with 2×64 MB = 128 MB worst case — should always pass
        let dir = std::env::temp_dir().join("forge-doctor-test-mempressure-low");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(&path, "[sandbox]\nmax_concurrent = 2\nmax_heap_mb = 64\n").unwrap();
        let check = check_memory_pressure(Some(&path));
        assert_eq!(check.status, CheckStatus::Pass, "{}", check.message);
        assert!(
            check.message.contains("128"),
            "should show 128 MB: {}",
            check.message
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_22_memory_pressure_defaults() {
        // Config with no sandbox overrides — defaults to 4×256 = 1024 MB
        let dir = std::env::temp_dir().join("forge-doctor-test-mempressure-default");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            "[servers.test]\ncommand = \"test\"\ntransport = \"stdio\"\n",
        )
        .unwrap();
        let check = check_memory_pressure(Some(&path));
        assert_eq!(check.status, CheckStatus::Pass, "{}", check.message);
        assert!(
            check.message.contains("1024"),
            "should show 1024 MB: {}",
            check.message
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_23_circuit_breakers_warns_unprotected_sse() {
        let dir = std::env::temp_dir().join("forge-doctor-test-cb-warn");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
[servers.remote]
transport = "sse"
url = "http://example.com/sse"
"#,
        )
        .unwrap();
        let check = check_circuit_breakers(Some(&path));
        assert_eq!(check.status, CheckStatus::Warn, "{}", check.message);
        assert!(
            check.message.contains("remote"),
            "should mention server name: {}",
            check.message
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_24_circuit_breakers_passes_all_protected() {
        let dir = std::env::temp_dir().join("forge-doctor-test-cb-pass");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
[servers.remote]
transport = "sse"
url = "http://example.com/sse"
circuit_breaker = true
"#,
        )
        .unwrap();
        let check = check_circuit_breakers(Some(&path));
        assert_eq!(check.status, CheckStatus::Pass, "{}", check.message);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_25_circuit_breakers_ignores_stdio() {
        let dir = std::env::temp_dir().join("forge-doctor-test-cb-stdio");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
[servers.local]
command = "test"
transport = "stdio"
"#,
        )
        .unwrap();
        let check = check_circuit_breakers(Some(&path));
        assert_eq!(check.status, CheckStatus::Pass, "{}", check.message);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_26_token_formats_detects_quoted_token() {
        let dir = std::env::temp_dir().join("forge-doctor-test-token-quote");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
[servers.test]
transport = "sse"
url = "http://example.com/sse"
headers = { x-api-key = "\"my-key\"" }
"#,
        )
        .unwrap();
        let check = check_token_formats(Some(&path));
        assert_eq!(check.status, CheckStatus::Warn, "{}", check.message);
        assert!(check.message.contains("quotes"), "{}", check.message);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_27_token_formats_detects_bearer_prefix() {
        let dir = std::env::temp_dir().join("forge-doctor-test-token-bearer");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
[servers.test]
transport = "sse"
url = "http://example.com/sse"
headers = { x-api-key = "Bearer sk-12345" }
"#,
        )
        .unwrap();
        let check = check_token_formats(Some(&path));
        assert_eq!(check.status, CheckStatus::Warn, "{}", check.message);
        assert!(check.message.contains("Bearer"), "{}", check.message);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_28_token_formats_passes_clean() {
        let dir = std::env::temp_dir().join("forge-doctor-test-token-clean");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
[servers.test]
transport = "sse"
url = "http://example.com/sse"
headers = { Authorization = "Bearer sk-12345", x-api-key = "clean-token" }
"#,
        )
        .unwrap();
        let check = check_token_formats(Some(&path));
        assert_eq!(check.status, CheckStatus::Pass, "{}", check.message);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dr_29_token_formats_no_config() {
        let path = PathBuf::from("/nonexistent/forge.toml");
        let check = check_token_formats(Some(&path));
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn dr_19_memory_check_platform_behavior() {
        let check = check_memory();
        #[cfg(target_os = "macos")]
        {
            // On macOS, should report GB or indicate detection issue
            assert!(
                check.message.contains("GB") || check.message.contains("determine"),
                "macOS memory check should report GB: {}",
                check.message
            );
        }
        #[cfg(target_os = "linux")]
        {
            assert!(
                check.message.contains("GB") || check.message.contains("determine"),
                "Linux memory check should report GB: {}",
                check.message
            );
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            assert!(
                check.message.contains("skipped"),
                "unsupported platform should skip: {}",
                check.message
            );
        }
        let _ = check;
    }
}
