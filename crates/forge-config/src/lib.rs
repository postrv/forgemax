#![warn(missing_docs)]

//! # forge-config
//!
//! Configuration loading for the Forgemax Code Mode MCP Gateway.
//!
//! Supports TOML configuration files with environment variable expansion.
//!
//! ## Example
//!
//! ```toml
//! [servers.narsil]
//! command = "narsil-mcp"
//! args = ["--repos", "."]
//! transport = "stdio"
//!
//! [servers.github]
//! url = "https://mcp.github.com/mcp"
//! transport = "sse"
//! headers = { Authorization = "Bearer ${GITHUB_TOKEN}" }
//!
//! [sandbox]
//! timeout_secs = 5
//! max_heap_mb = 64
//! max_concurrent = 8
//! max_tool_calls = 50
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

/// Errors from config parsing.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read config file.
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to parse TOML.
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),

    /// Invalid configuration value.
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Top-level Forge configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ForgeConfig {
    /// Downstream MCP server configurations, keyed by server name.
    #[serde(default)]
    pub servers: HashMap<String, ServerConfig>,

    /// Sandbox execution settings.
    #[serde(default)]
    pub sandbox: SandboxOverrides,

    /// Server group definitions for cross-server data flow policies.
    #[serde(default)]
    pub groups: HashMap<String, GroupConfig>,
}

/// Configuration for a server group.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupConfig {
    /// Server names belonging to this group.
    pub servers: Vec<String>,

    /// Isolation mode: "strict" (no cross-group data flow) or "open" (unrestricted).
    #[serde(default = "default_isolation")]
    pub isolation: String,
}

fn default_isolation() -> String {
    "open".to_string()
}

/// Configuration for a single downstream MCP server.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Transport type: "stdio" or "sse".
    pub transport: String,

    /// Command to execute (stdio transport).
    #[serde(default)]
    pub command: Option<String>,

    /// Command arguments (stdio transport).
    #[serde(default)]
    pub args: Vec<String>,

    /// Server URL (sse transport).
    #[serde(default)]
    pub url: Option<String>,

    /// HTTP headers (sse transport).
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Server description (optional, for manifest).
    #[serde(default)]
    pub description: Option<String>,

    /// Per-server timeout in seconds for individual tool calls.
    #[serde(default)]
    pub timeout_secs: Option<u64>,

    /// Enable circuit breaker for this server.
    #[serde(default)]
    pub circuit_breaker: Option<bool>,

    /// Number of consecutive failures before opening the circuit (default: 3).
    #[serde(default)]
    pub failure_threshold: Option<u32>,

    /// Seconds to wait before probing a tripped circuit (default: 30).
    #[serde(default)]
    pub recovery_timeout_secs: Option<u64>,
}

/// Sandbox configuration overrides.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SandboxOverrides {
    /// Execution timeout in seconds.
    #[serde(default)]
    pub timeout_secs: Option<u64>,

    /// Maximum V8 heap size in megabytes.
    #[serde(default)]
    pub max_heap_mb: Option<usize>,

    /// Maximum concurrent sandbox executions.
    #[serde(default)]
    pub max_concurrent: Option<usize>,

    /// Maximum tool calls per execution.
    #[serde(default)]
    pub max_tool_calls: Option<usize>,

    /// Execution mode: "in_process" (default) or "child_process".
    #[serde(default)]
    pub execution_mode: Option<String>,

    /// Maximum IPC message size in megabytes (default: 8 MB).
    #[serde(default)]
    pub max_ipc_message_size_mb: Option<usize>,

    /// Maximum resource content size in megabytes (default: 64 MB).
    #[serde(default)]
    pub max_resource_size_mb: Option<usize>,

    /// Maximum concurrent calls in forge.parallel() (default: 8).
    #[serde(default)]
    pub max_parallel: Option<usize>,

    /// Stash configuration overrides.
    #[serde(default)]
    pub stash: Option<StashOverrides>,
}

/// Configuration overrides for the ephemeral stash.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StashOverrides {
    /// Maximum number of stash entries per session.
    #[serde(default)]
    pub max_keys: Option<usize>,

    /// Maximum size of a single stash value in megabytes.
    #[serde(default)]
    pub max_value_size_mb: Option<usize>,

    /// Maximum total stash size in megabytes.
    #[serde(default)]
    pub max_total_size_mb: Option<usize>,

    /// Default TTL for stash entries in seconds.
    #[serde(default)]
    pub default_ttl_secs: Option<u64>,

    /// Maximum TTL for stash entries in seconds.
    #[serde(default)]
    pub max_ttl_secs: Option<u64>,
}

impl ForgeConfig {
    /// Parse a config from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        let config: ForgeConfig = toml::from_str(toml_str)?;
        config.validate()?;
        Ok(config)
    }

    /// Load config from a file path.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// Parse a config from a TOML string, expanding `${ENV_VAR}` references.
    pub fn from_toml_with_env(toml_str: &str) -> Result<Self, ConfigError> {
        let expanded = expand_env_vars(toml_str);
        Self::from_toml(&expanded)
    }

    /// Load config from a file path, expanding environment variables.
    pub fn from_file_with_env(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml_with_env(&content)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for (name, server) in &self.servers {
            match server.transport.as_str() {
                "stdio" => {
                    if server.command.is_none() {
                        return Err(ConfigError::Invalid(format!(
                            "server '{}': stdio transport requires 'command'",
                            name
                        )));
                    }
                }
                "sse" => {
                    if server.url.is_none() {
                        return Err(ConfigError::Invalid(format!(
                            "server '{}': sse transport requires 'url'",
                            name
                        )));
                    }
                }
                other => {
                    return Err(ConfigError::Invalid(format!(
                        "server '{}': unsupported transport '{}', supported: stdio, sse",
                        name, other
                    )));
                }
            }
        }

        // Validate groups
        let mut seen_servers: HashMap<&str, &str> = HashMap::new();
        for (group_name, group_config) in &self.groups {
            // Validate isolation mode
            match group_config.isolation.as_str() {
                "strict" | "open" => {}
                other => {
                    return Err(ConfigError::Invalid(format!(
                        "group '{}': unsupported isolation '{}', supported: strict, open",
                        group_name, other
                    )));
                }
            }

            for server_ref in &group_config.servers {
                // Check server exists
                if !self.servers.contains_key(server_ref) {
                    return Err(ConfigError::Invalid(format!(
                        "group '{}': references unknown server '{}'",
                        group_name, server_ref
                    )));
                }
                // Check no server in multiple groups
                if let Some(existing_group) = seen_servers.get(server_ref.as_str()) {
                    return Err(ConfigError::Invalid(format!(
                        "server '{}' is in multiple groups: '{}' and '{}'",
                        server_ref, existing_group, group_name
                    )));
                }
                seen_servers.insert(server_ref, group_name);
            }
        }

        // Validate sandbox v0.2 fields
        self.validate_sandbox_v2()?;

        Ok(())
    }

    fn validate_sandbox_v2(&self) -> Result<(), ConfigError> {
        // CV-01: max_resource_size_mb must be > 0 and <= 512
        if let Some(size) = self.sandbox.max_resource_size_mb {
            if size == 0 || size > 512 {
                return Err(ConfigError::Invalid(
                    "sandbox.max_resource_size_mb must be > 0 and <= 512".into(),
                ));
            }
        }

        // CV-02: max_parallel must be >= 1 and <= max_concurrent (or default 8)
        if let Some(parallel) = self.sandbox.max_parallel {
            let max_concurrent = self.sandbox.max_concurrent.unwrap_or(8);
            if parallel < 1 || parallel > max_concurrent {
                return Err(ConfigError::Invalid(format!(
                    "sandbox.max_parallel must be >= 1 and <= max_concurrent ({})",
                    max_concurrent
                )));
            }
        }

        if let Some(ref stash) = self.sandbox.stash {
            // CV-03: stash.max_value_size_mb must be > 0 and <= 256
            if let Some(size) = stash.max_value_size_mb {
                if size == 0 || size > 256 {
                    return Err(ConfigError::Invalid(
                        "sandbox.stash.max_value_size_mb must be > 0 and <= 256".into(),
                    ));
                }
            }

            // CV-04: stash.max_total_size_mb must be >= stash.max_value_size_mb
            if let (Some(total), Some(value)) = (stash.max_total_size_mb, stash.max_value_size_mb) {
                if total < value {
                    return Err(ConfigError::Invalid(
                        "sandbox.stash.max_total_size_mb must be >= sandbox.stash.max_value_size_mb"
                            .into(),
                    ));
                }
            }

            // CV-05: stash.default_ttl_secs must be > 0 and <= stash.max_ttl_secs
            if let Some(default_ttl) = stash.default_ttl_secs {
                if default_ttl == 0 {
                    return Err(ConfigError::Invalid(
                        "sandbox.stash.default_ttl_secs must be > 0".into(),
                    ));
                }
                let max_ttl = stash.max_ttl_secs.unwrap_or(86400);
                if default_ttl > max_ttl {
                    return Err(ConfigError::Invalid(format!(
                        "sandbox.stash.default_ttl_secs ({}) must be <= max_ttl_secs ({})",
                        default_ttl, max_ttl
                    )));
                }
            }

            // CV-06: stash.max_ttl_secs must be > 0 and <= 604800 (7 days)
            if let Some(max_ttl) = stash.max_ttl_secs {
                if max_ttl == 0 || max_ttl > 604800 {
                    return Err(ConfigError::Invalid(
                        "sandbox.stash.max_ttl_secs must be > 0 and <= 604800 (7 days)".into(),
                    ));
                }
            }
        }

        // CV-07: max_resource_size_mb + 1 must fit within IPC message size
        // In child_process mode, resource content flows over IPC
        if let Some(resource_mb) = self.sandbox.max_resource_size_mb {
            let ipc_limit_mb = self.sandbox.max_ipc_message_size_mb.unwrap_or(8); // default 8 MB
            if resource_mb + 1 > ipc_limit_mb {
                return Err(ConfigError::Invalid(format!(
                    "sandbox.max_resource_size_mb ({}) + 1 MB overhead exceeds IPC message limit ({} MB)",
                    resource_mb, ipc_limit_mb
                )));
            }
        }

        Ok(())
    }
}

/// Expand `${ENV_VAR}` patterns in a string using environment variables.
fn expand_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            for c in chars.by_ref() {
                if c == '}' {
                    break;
                }
                var_name.push(c);
            }
            match std::env::var(&var_name) {
                Ok(value) => result.push_str(&value),
                Err(_) => {
                    // Leave the placeholder if env var not found
                    result.push_str(&format!("${{{}}}", var_name));
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_minimal_toml() {
        let toml = r#"
            [servers.narsil]
            command = "narsil-mcp"
            transport = "stdio"
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert_eq!(config.servers.len(), 1);
        let narsil = &config.servers["narsil"];
        assert_eq!(narsil.transport, "stdio");
        assert_eq!(narsil.command.as_deref(), Some("narsil-mcp"));
    }

    #[test]
    fn config_parses_sse_server() {
        let toml = r#"
            [servers.github]
            url = "https://mcp.github.com/sse"
            transport = "sse"
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        let github = &config.servers["github"];
        assert_eq!(github.transport, "sse");
        assert_eq!(github.url.as_deref(), Some("https://mcp.github.com/sse"));
    }

    #[test]
    fn config_parses_sandbox_overrides() {
        let toml = r#"
            [sandbox]
            timeout_secs = 10
            max_heap_mb = 128
            max_concurrent = 4
            max_tool_calls = 100
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert_eq!(config.sandbox.timeout_secs, Some(10));
        assert_eq!(config.sandbox.max_heap_mb, Some(128));
        assert_eq!(config.sandbox.max_concurrent, Some(4));
        assert_eq!(config.sandbox.max_tool_calls, Some(100));
    }

    #[test]
    fn config_expands_environment_variables() {
        temp_env::with_var("FORGE_TEST_TOKEN", Some("secret123"), || {
            let toml = r#"
                [servers.github]
                url = "https://mcp.github.com/sse"
                transport = "sse"
                headers = { Authorization = "Bearer ${FORGE_TEST_TOKEN}" }
            "#;

            let config = ForgeConfig::from_toml_with_env(toml).unwrap();
            let github = &config.servers["github"];
            assert_eq!(
                github.headers.get("Authorization").unwrap(),
                "Bearer secret123"
            );
        });
    }

    #[test]
    fn config_rejects_invalid_transport() {
        let toml = r#"
            [servers.test]
            command = "test"
            transport = "grpc"
        "#;

        let err = ForgeConfig::from_toml(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("grpc"),
            "error should mention the transport: {msg}"
        );
        assert!(
            msg.contains("stdio"),
            "error should mention supported transports: {msg}"
        );
    }

    #[test]
    fn config_rejects_stdio_without_command() {
        let toml = r#"
            [servers.test]
            transport = "stdio"
        "#;

        let err = ForgeConfig::from_toml(toml).unwrap_err();
        assert!(err.to_string().contains("command"));
    }

    #[test]
    fn config_rejects_sse_without_url() {
        let toml = r#"
            [servers.test]
            transport = "sse"
        "#;

        let err = ForgeConfig::from_toml(toml).unwrap_err();
        assert!(err.to_string().contains("url"));
    }

    #[test]
    fn config_loads_from_file() {
        let dir = std::env::temp_dir().join("forge-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("forge.toml");
        std::fs::write(
            &path,
            r#"
            [servers.test]
            command = "test-server"
            transport = "stdio"
        "#,
        )
        .unwrap();

        let config = ForgeConfig::from_file(&path).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(
            config.servers["test"].command.as_deref(),
            Some("test-server")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_uses_defaults_when_absent() {
        let toml = r#"
            [servers.test]
            command = "test"
            transport = "stdio"
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert!(config.sandbox.timeout_secs.is_none());
        assert!(config.sandbox.max_heap_mb.is_none());
        assert!(config.sandbox.max_concurrent.is_none());
        assert!(config.sandbox.max_tool_calls.is_none());
    }

    #[test]
    fn config_parses_full_example() {
        let toml = r#"
            [servers.narsil]
            command = "narsil-mcp"
            args = ["--repos", ".", "--streaming"]
            transport = "stdio"
            description = "Code intelligence"

            [servers.github]
            url = "https://mcp.github.com/sse"
            transport = "sse"
            headers = { Authorization = "Bearer token123" }

            [sandbox]
            timeout_secs = 5
            max_heap_mb = 64
            max_concurrent = 8
            max_tool_calls = 50
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert_eq!(config.servers.len(), 2);

        let narsil = &config.servers["narsil"];
        assert_eq!(narsil.command.as_deref(), Some("narsil-mcp"));
        assert_eq!(narsil.args, vec!["--repos", ".", "--streaming"]);
        assert_eq!(narsil.description.as_deref(), Some("Code intelligence"));

        let github = &config.servers["github"];
        assert_eq!(github.url.as_deref(), Some("https://mcp.github.com/sse"));
        assert_eq!(
            github.headers.get("Authorization").unwrap(),
            "Bearer token123"
        );

        assert_eq!(config.sandbox.timeout_secs, Some(5));
    }

    #[test]
    fn config_empty_servers_is_valid() {
        let toml = "";
        let config = ForgeConfig::from_toml(toml).unwrap();
        assert!(config.servers.is_empty());
    }

    #[test]
    fn env_var_expansion_preserves_unresolved() {
        let result = expand_env_vars("prefix ${DEFINITELY_NOT_SET_12345} suffix");
        assert_eq!(result, "prefix ${DEFINITELY_NOT_SET_12345} suffix");
    }

    #[test]
    fn env_var_expansion_handles_no_vars() {
        let result = expand_env_vars("no variables here");
        assert_eq!(result, "no variables here");
    }

    #[test]
    fn config_parses_execution_mode_child_process() {
        let toml = r#"
            [sandbox]
            execution_mode = "child_process"
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert_eq!(
            config.sandbox.execution_mode.as_deref(),
            Some("child_process")
        );
    }

    #[test]
    fn config_parses_groups() {
        let toml = r#"
            [servers.vault]
            command = "vault-mcp"
            transport = "stdio"

            [servers.slack]
            command = "slack-mcp"
            transport = "stdio"

            [groups.internal]
            servers = ["vault"]
            isolation = "strict"

            [groups.external]
            servers = ["slack"]
            isolation = "open"
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert_eq!(config.groups.len(), 2);
        assert_eq!(config.groups["internal"].isolation, "strict");
        assert_eq!(config.groups["external"].servers, vec!["slack"]);
    }

    #[test]
    fn config_groups_default_to_empty() {
        let toml = r#"
            [servers.test]
            command = "test"
            transport = "stdio"
        "#;
        let config = ForgeConfig::from_toml(toml).unwrap();
        assert!(config.groups.is_empty());
    }

    #[test]
    fn config_rejects_group_with_unknown_server() {
        let toml = r#"
            [servers.real]
            command = "real"
            transport = "stdio"

            [groups.bad]
            servers = ["nonexistent"]
        "#;
        let err = ForgeConfig::from_toml(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("nonexistent"), "should mention server: {msg}");
        assert!(msg.contains("unknown"), "should say unknown: {msg}");
    }

    #[test]
    fn config_rejects_server_in_multiple_groups() {
        let toml = r#"
            [servers.shared]
            command = "shared"
            transport = "stdio"

            [groups.a]
            servers = ["shared"]

            [groups.b]
            servers = ["shared"]
        "#;
        let err = ForgeConfig::from_toml(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("shared"), "should mention server: {msg}");
        assert!(
            msg.contains("multiple groups"),
            "should say multiple groups: {msg}"
        );
    }

    #[test]
    fn config_rejects_invalid_isolation_mode() {
        let toml = r#"
            [servers.test]
            command = "test"
            transport = "stdio"

            [groups.bad]
            servers = ["test"]
            isolation = "paranoid"
        "#;
        let err = ForgeConfig::from_toml(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("paranoid"), "should mention mode: {msg}");
    }

    #[test]
    fn config_parses_server_timeout() {
        let toml = r#"
            [servers.slow]
            command = "slow-mcp"
            transport = "stdio"
            timeout_secs = 30
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert_eq!(config.servers["slow"].timeout_secs, Some(30));
    }

    #[test]
    fn config_server_timeout_defaults_to_none() {
        let toml = r#"
            [servers.fast]
            command = "fast-mcp"
            transport = "stdio"
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert!(config.servers["fast"].timeout_secs.is_none());
    }

    #[test]
    fn config_parses_circuit_breaker() {
        let toml = r#"
            [servers.flaky]
            command = "flaky-mcp"
            transport = "stdio"
            circuit_breaker = true
            failure_threshold = 5
            recovery_timeout_secs = 60
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        let flaky = &config.servers["flaky"];
        assert_eq!(flaky.circuit_breaker, Some(true));
        assert_eq!(flaky.failure_threshold, Some(5));
        assert_eq!(flaky.recovery_timeout_secs, Some(60));
    }

    #[test]
    fn config_circuit_breaker_defaults_to_none() {
        let toml = r#"
            [servers.stable]
            command = "stable-mcp"
            transport = "stdio"
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        let stable = &config.servers["stable"];
        assert!(stable.circuit_breaker.is_none());
        assert!(stable.failure_threshold.is_none());
        assert!(stable.recovery_timeout_secs.is_none());
    }

    #[test]
    fn config_execution_mode_defaults_to_none() {
        let toml = r#"
            [sandbox]
            timeout_secs = 5
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert!(config.sandbox.execution_mode.is_none());
    }

    // --- v0.2 Config Validation Tests (CV-01..CV-07) ---

    #[test]
    fn cv01_max_resource_size_mb_range() {
        // Valid (must fit within IPC limit — default 8 MB)
        let toml = "[sandbox]\nmax_resource_size_mb = 7";
        assert!(ForgeConfig::from_toml(toml).is_ok());

        // Zero is invalid
        let toml = "[sandbox]\nmax_resource_size_mb = 0";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("max_resource_size_mb"), "got: {err}");

        // Over 512 is invalid
        let toml = "[sandbox]\nmax_resource_size_mb = 513";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("max_resource_size_mb"), "got: {err}");
    }

    #[test]
    fn cv02_max_parallel_range() {
        // Valid: within default max_concurrent (8)
        let toml = "[sandbox]\nmax_parallel = 4";
        assert!(ForgeConfig::from_toml(toml).is_ok());

        // Zero is invalid
        let toml = "[sandbox]\nmax_parallel = 0";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("max_parallel"), "got: {err}");

        // Exceeding max_concurrent is invalid
        let toml = "[sandbox]\nmax_concurrent = 4\nmax_parallel = 5";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("max_parallel"), "got: {err}");
    }

    #[test]
    fn cv03_stash_max_value_size_mb_range() {
        // Valid
        let toml = "[sandbox.stash]\nmax_value_size_mb = 16";
        assert!(ForgeConfig::from_toml(toml).is_ok());

        // Zero is invalid
        let toml = "[sandbox.stash]\nmax_value_size_mb = 0";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("max_value_size_mb"), "got: {err}");

        // Over 256 is invalid
        let toml = "[sandbox.stash]\nmax_value_size_mb = 257";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("max_value_size_mb"), "got: {err}");
    }

    #[test]
    fn cv04_stash_total_size_gte_value_size() {
        // Valid: total >= value
        let toml = "[sandbox.stash]\nmax_value_size_mb = 16\nmax_total_size_mb = 128";
        assert!(ForgeConfig::from_toml(toml).is_ok());

        // Invalid: total < value
        let toml = "[sandbox.stash]\nmax_value_size_mb = 32\nmax_total_size_mb = 16";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("max_total_size_mb"), "got: {err}");
    }

    #[test]
    fn cv05_stash_default_ttl_range() {
        // Valid
        let toml = "[sandbox.stash]\ndefault_ttl_secs = 3600";
        assert!(ForgeConfig::from_toml(toml).is_ok());

        // Zero is invalid
        let toml = "[sandbox.stash]\ndefault_ttl_secs = 0";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("default_ttl_secs"), "got: {err}");

        // Exceeding max_ttl is invalid
        let toml = "[sandbox.stash]\ndefault_ttl_secs = 100000\nmax_ttl_secs = 86400";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("default_ttl_secs"), "got: {err}");
    }

    #[test]
    fn cv06_stash_max_ttl_range() {
        // Valid
        let toml = "[sandbox.stash]\nmax_ttl_secs = 86400";
        assert!(ForgeConfig::from_toml(toml).is_ok());

        // Zero is invalid
        let toml = "[sandbox.stash]\nmax_ttl_secs = 0";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("max_ttl_secs"), "got: {err}");

        // Over 7 days is invalid
        let toml = "[sandbox.stash]\nmax_ttl_secs = 604801";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("max_ttl_secs"), "got: {err}");
    }

    #[test]
    fn cv07_max_resource_size_fits_ipc() {
        // Valid: 7 MB + 1 MB overhead = 8 MB = fits default IPC limit
        let toml = "[sandbox]\nmax_resource_size_mb = 7";
        assert!(ForgeConfig::from_toml(toml).is_ok());

        // Invalid: 8 MB + 1 MB overhead = 9 MB > 8 MB default IPC limit
        let toml = "[sandbox]\nmax_resource_size_mb = 8";
        let err = ForgeConfig::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("IPC"), "got: {err}");

        // Valid with explicit larger IPC limit
        let toml = "[sandbox]\nmax_resource_size_mb = 32\nmax_ipc_message_size_mb = 64";
        assert!(ForgeConfig::from_toml(toml).is_ok());
    }

    #[test]
    fn config_parses_v02_sandbox_fields() {
        let toml = r#"
            [sandbox]
            max_resource_size_mb = 7
            max_ipc_message_size_mb = 64
            max_parallel = 4

            [sandbox.stash]
            max_keys = 128
            max_value_size_mb = 8
            max_total_size_mb = 64
            default_ttl_secs = 1800
            max_ttl_secs = 43200
        "#;

        let config = ForgeConfig::from_toml(toml).unwrap();
        assert_eq!(config.sandbox.max_resource_size_mb, Some(7));
        assert_eq!(config.sandbox.max_ipc_message_size_mb, Some(64));
        assert_eq!(config.sandbox.max_parallel, Some(4));

        let stash = config.sandbox.stash.unwrap();
        assert_eq!(stash.max_keys, Some(128));
        assert_eq!(stash.max_value_size_mb, Some(8));
        assert_eq!(stash.max_total_size_mb, Some(64));
        assert_eq!(stash.default_ttl_secs, Some(1800));
        assert_eq!(stash.max_ttl_secs, Some(43200));
    }
}
