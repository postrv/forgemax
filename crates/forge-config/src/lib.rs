#![warn(missing_docs)]

//! # forge-config
//!
//! Configuration loading for the Forge Code Mode MCP Gateway.
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
        std::env::set_var("FORGE_TEST_TOKEN", "secret123");
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
        std::env::remove_var("FORGE_TEST_TOKEN");
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
        assert!(msg.contains("grpc"), "error should mention the transport: {msg}");
        assert!(msg.contains("stdio"), "error should mention supported transports: {msg}");
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
        assert_eq!(config.servers["test"].command.as_deref(), Some("test-server"));

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
        assert_eq!(config.sandbox.execution_mode.as_deref(), Some("child_process"));
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
}
