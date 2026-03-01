#![warn(missing_docs)]

//! Forgemax Code Mode MCP Gateway
//!
//! Give your agent every tool. Use 1,000 tokens.

mod cmd;
pub mod common;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// Forgemax Code Mode MCP Gateway — collapses N servers x M tools into 2 tools.
#[derive(Parser)]
#[command(name = "forgemax", version, about = "Code Mode MCP Gateway")]
struct Cli {
    /// Path to config file (default: auto-detect).
    #[arg(long, short, global = true, env = "FORGE_CONFIG")]
    config: Option<PathBuf>,

    /// Subcommand to execute.
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Available subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Start the MCP gateway server (default when no subcommand given).
    Serve,
    /// Validate configuration and connectivity.
    Doctor(cmd::doctor::DoctorArgs),
    /// Inspect the capability manifest from connected servers.
    Manifest(cmd::manifest::ManifestArgs),
    /// Execute a JavaScript file against configured servers.
    Run(cmd::run::RunArgs),
    /// Generate a starter configuration file.
    Init(cmd::init::InitArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("{}", common::feature_status_line());

    match cli.command {
        None | Some(Commands::Serve) => cmd::serve::execute(cli.config).await,
        Some(Commands::Doctor(args)) => cmd::doctor::execute(&args, cli.config).await,
        Some(Commands::Manifest(args)) => cmd::manifest::execute(&args, cli.config).await,
        Some(Commands::Run(args)) => cmd::run::execute(&args, cli.config).await,
        Some(Commands::Init(args)) => cmd::init::execute(&args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_s01_no_args_is_none() {
        let cli = Cli::try_parse_from(["forgemax"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_s02_version_flag() {
        let result = Cli::try_parse_from(["forgemax", "--version"]);
        // clap exits with an error (DisplayVersion) on --version
        assert!(result.is_err());
    }

    #[test]
    fn cli_s03_help_flag() {
        let result = Cli::try_parse_from(["forgemax", "--help"]);
        // clap exits with an error (DisplayHelp) on --help
        assert!(result.is_err());
    }

    #[test]
    fn cli_s04_serve_explicit() {
        let cli = Cli::try_parse_from(["forgemax", "serve"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Serve)));
    }

    #[test]
    fn cli_s05_unknown_errors() {
        let result = Cli::try_parse_from(["forgemax", "nonexistent"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_s06_config_flag() {
        let cli = Cli::try_parse_from(["forgemax", "--config", "/tmp/forge.toml"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/forge.toml")));
    }

    #[test]
    fn cli_s07_doctor_subcommand() {
        let cli = Cli::try_parse_from(["forgemax", "doctor"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Doctor(_))));
    }

    #[test]
    fn cli_s08_doctor_json_flag() {
        let cli = Cli::try_parse_from(["forgemax", "doctor", "--json"]).unwrap();
        if let Some(Commands::Doctor(args)) = cli.command {
            assert!(args.json);
        } else {
            panic!("expected Doctor command");
        }
    }

    #[test]
    fn cli_s09_manifest_subcommand() {
        let cli = Cli::try_parse_from(["forgemax", "manifest"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Manifest(_))));
    }

    #[test]
    fn cli_s10_run_subcommand() {
        let cli = Cli::try_parse_from(["forgemax", "run", "test.js"]).unwrap();
        if let Some(Commands::Run(args)) = cli.command {
            assert_eq!(args.file, PathBuf::from("test.js"));
        } else {
            panic!("expected Run command");
        }
    }

    #[test]
    fn cli_s11_init_subcommand() {
        let cli = Cli::try_parse_from(["forgemax", "init"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Init(_))));
    }

    #[test]
    fn ver_01_cargo_pkg_version() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.4.0");
    }
}
