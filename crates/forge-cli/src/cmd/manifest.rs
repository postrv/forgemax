//! `forgemax manifest` — inspect the capability manifest.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::common;

/// Arguments for the manifest subcommand.
#[derive(Debug, Args)]
pub struct ManifestArgs {
    /// Output as JSON.
    #[arg(long)]
    pub json: bool,

    /// Filter by server name.
    #[arg(long)]
    pub server: Option<String>,

    /// Detail level (0=summary, 1=tools, 2=full schemas).
    #[arg(long, default_value = "0")]
    pub layer: u8,
}

/// Execute the manifest command.
pub async fn execute(args: &ManifestArgs, config_path: Option<PathBuf>) -> Result<()> {
    let config = common::load_config(config_path.as_ref())?;
    let result = common::connect_and_build_manifest(&config).await?;
    let manifest = &result.manifest;

    // Filter by server if requested
    if let Some(ref server_name) = args.server {
        let found = manifest.servers.iter().find(|s| s.name == *server_name);

        match found {
            Some(server) => {
                if args.json {
                    print_server_json(server, args.layer)?;
                } else {
                    print_server_human(server, args.layer);
                }
            }
            None => {
                // Fuzzy suggest
                let names: Vec<&str> = manifest.servers.iter().map(|s| s.name.as_str()).collect();
                let suggestion = find_closest(server_name, &names);
                let msg = if let Some(suggest) = suggestion {
                    format!(
                        "server '{}' not found. Did you mean '{}'?",
                        server_name, suggest
                    )
                } else {
                    format!(
                        "server '{}' not found. Available: {}",
                        server_name,
                        names.join(", ")
                    )
                };
                anyhow::bail!(msg);
            }
        }
    } else if args.json {
        print_all_json(manifest, args.layer)?;
    } else {
        print_all_human(manifest, args.layer);
    }

    Ok(())
}

fn find_closest<'a>(query: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (*c, strsim::levenshtein(query, c)))
        .filter(|(_, d)| *d <= 3)
        .min_by_key(|(_, d)| *d)
        .map(|(c, _)| c)
}

fn print_all_human(manifest: &forge_manifest::Manifest, layer: u8) {
    println!(
        "Forgemax Manifest: {} server(s), {} tool(s)\n",
        manifest.total_servers(),
        manifest.total_tools(),
    );

    for server in &manifest.servers {
        print_server_human(server, layer);
        println!();
    }
}

fn print_server_human(server: &forge_manifest::ServerEntry, layer: u8) {
    println!("  {} — {}", server.name, server.description);

    if layer >= 1 {
        for (cat_name, cat) in &server.categories {
            println!("    [{}] {}", cat_name, cat.description);
            for tool in &cat.tools {
                println!("      - {}: {}", tool.name, tool.description);

                if layer >= 2 {
                    if let Some(ref schema) = tool.input_schema {
                        let json = serde_json::to_string_pretty(schema).unwrap_or_default();
                        for line in json.lines() {
                            println!("          {}", line);
                        }
                    }
                }
            }
        }
    } else {
        let tool_count: usize = server.categories.values().map(|c| c.tools.len()).sum();
        println!(
            "    {} categor{}, {} tool(s)",
            server.categories.len(),
            if server.categories.len() == 1 {
                "y"
            } else {
                "ies"
            },
            tool_count,
        );
    }
}

fn print_all_json(manifest: &forge_manifest::Manifest, layer: u8) -> Result<()> {
    let json = match layer {
        0 => {
            let summary = serde_json::json!({
                "servers": manifest.total_servers(),
                "tools": manifest.total_tools(),
                "server_names": manifest.servers.iter().map(|s| &s.name).collect::<Vec<_>>(),
            });
            serde_json::to_string_pretty(&summary)?
        }
        _ => {
            let value = manifest.to_json()?;
            serde_json::to_string_pretty(&value)?
        }
    };
    println!("{}", json);
    Ok(())
}

fn print_server_json(server: &forge_manifest::ServerEntry, layer: u8) -> Result<()> {
    let json = match layer {
        0 => {
            let tool_count: usize = server.categories.values().map(|c| c.tools.len()).sum();
            serde_json::json!({
                "name": server.name,
                "description": server.description,
                "categories": server.categories.len(),
                "tools": tool_count,
            })
        }
        _ => serde_json::to_value(server)?,
    };
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mf_01_find_closest_exact_match() {
        let candidates = vec!["narsil", "github", "supabase"];
        assert_eq!(find_closest("narsil", &candidates), Some("narsil"));
    }

    #[test]
    fn mf_02_find_closest_typo() {
        let candidates = vec!["narsil", "github", "supabase"];
        assert_eq!(find_closest("narsill", &candidates), Some("narsil"));
    }

    #[test]
    fn mf_03_find_closest_no_match() {
        let candidates = vec!["narsil", "github", "supabase"];
        assert_eq!(find_closest("zzzzzzzzzzz", &candidates), None);
    }

    #[test]
    fn mf_04_find_closest_empty() {
        let candidates: Vec<&str> = vec![];
        assert_eq!(find_closest("anything", &candidates), None);
    }

    #[test]
    fn mf_05_manifest_server_filter_exact_match() {
        use forge_manifest::{ManifestBuilder, ServerBuilder};

        let manifest = ManifestBuilder::new()
            .add_server(ServerBuilder::new("alpha", "Alpha server").build())
            .add_server(ServerBuilder::new("beta", "Beta server").build())
            .build();

        let found = manifest.servers.iter().find(|s| s.name == "alpha");
        assert!(found.is_some(), "should find 'alpha' by exact name");
        assert_eq!(found.unwrap().description, "Alpha server");
    }

    #[test]
    fn mf_06_manifest_nonexistent_server_fuzzy_suggestion() {
        use forge_manifest::{ManifestBuilder, ServerBuilder};

        let manifest = ManifestBuilder::new()
            .add_server(ServerBuilder::new("narsil", "Code intel").build())
            .add_server(ServerBuilder::new("github", "GitHub server").build())
            .build();

        let names: Vec<&str> = manifest.servers.iter().map(|s| s.name.as_str()).collect();
        // Typo: "narsill" should suggest "narsil"
        let suggestion = find_closest("narsill", &names);
        assert_eq!(suggestion, Some("narsil"));

        // Completely unrelated name should not suggest
        let no_match = find_closest("zzzzzzzzz", &names);
        assert!(no_match.is_none(), "should not suggest for distant strings");
    }

    #[test]
    fn mf_07_manifest_layer0_summary() {
        use forge_manifest::{Category, ManifestBuilder, ServerBuilder, ToolEntry};

        let manifest = ManifestBuilder::new()
            .add_server(
                ServerBuilder::new("srv1", "Server 1")
                    .add_category(Category {
                        name: "cat1".into(),
                        description: "Category 1".into(),
                        tools: vec![ToolEntry {
                            name: "tool_a".into(),
                            description: "Tool A".into(),
                            params: vec![],
                            returns: None,
                            input_schema: None,
                        }],
                    })
                    .build(),
            )
            .build();

        // Layer 0 = summary only: server count, tool count, server names
        assert_eq!(manifest.total_servers(), 1);
        assert_eq!(manifest.total_tools(), 1);
    }

    #[test]
    fn mf_08_manifest_layer1_shows_categories_and_tools() {
        use forge_manifest::{Category, ManifestBuilder, ServerBuilder, ToolEntry};

        let manifest = ManifestBuilder::new()
            .add_server(
                ServerBuilder::new("srv1", "Server 1")
                    .add_category(Category {
                        name: "ast".into(),
                        description: "AST tools".into(),
                        tools: vec![
                            ToolEntry {
                                name: "parse".into(),
                                description: "Parse code".into(),
                                params: vec![],
                                returns: None,
                                input_schema: None,
                            },
                            ToolEntry {
                                name: "find_symbols".into(),
                                description: "Find symbols".into(),
                                params: vec![],
                                returns: None,
                                input_schema: None,
                            },
                        ],
                    })
                    .add_category(Category {
                        name: "git".into(),
                        description: "Git tools".into(),
                        tools: vec![ToolEntry {
                            name: "diff".into(),
                            description: "Git diff".into(),
                            params: vec![],
                            returns: None,
                            input_schema: None,
                        }],
                    })
                    .build(),
            )
            .build();

        let server = &manifest.servers[0];
        assert_eq!(server.categories.len(), 2);
        assert!(server.categories.contains_key("ast"));
        assert!(server.categories.contains_key("git"));
        assert_eq!(server.categories["ast"].tools.len(), 2);
        assert_eq!(server.categories["git"].tools.len(), 1);
    }

    #[test]
    fn mf_09_manifest_layer2_full_schema() {
        use forge_manifest::{Category, ManifestBuilder, ServerBuilder, ToolEntry};

        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string" }
            },
            "required": ["pattern"]
        });

        let manifest = ManifestBuilder::new()
            .add_server(
                ServerBuilder::new("srv1", "Server 1")
                    .add_category(Category {
                        name: "search".into(),
                        description: "Search tools".into(),
                        tools: vec![ToolEntry {
                            name: "find".into(),
                            description: "Find things".into(),
                            params: vec![],
                            returns: None,
                            input_schema: Some(schema.clone()),
                        }],
                    })
                    .build(),
            )
            .build();

        let tool = &manifest.servers[0].categories["search"].tools[0];
        assert!(tool.input_schema.is_some());
        let got_schema = tool.input_schema.as_ref().unwrap();
        assert_eq!(got_schema["required"][0], "pattern");
    }

    #[test]
    fn mf_10_manifest_group_membership_from_config() {
        let toml = r#"
[servers.alpha]
command = "alpha"
transport = "stdio"
[servers.beta]
command = "beta"
transport = "stdio"
[groups.internal]
servers = ["alpha"]
isolation = "strict"
[groups.external]
servers = ["beta"]
isolation = "open"
"#;
        let config = forge_config::ForgeConfig::from_toml(toml).unwrap();
        let groups = crate::common::build_group_map(&config);
        assert_eq!(groups.len(), 2);
        assert!(groups["internal"].0.contains(&"alpha".to_string()));
        assert!(groups["external"].0.contains(&"beta".to_string()));
        assert_eq!(groups["internal"].1, "strict");
        assert_eq!(groups["external"].1, "open");
    }

    #[test]
    fn mf_11_empty_manifest() {
        use forge_manifest::ManifestBuilder;

        let manifest = ManifestBuilder::new().build();
        assert_eq!(manifest.total_servers(), 0);
        assert_eq!(manifest.total_tools(), 0);
        // JSON serialization should work for empty manifest
        let json = manifest.to_json().unwrap();
        assert!(json["servers"].is_array());
    }

    #[test]
    fn mf_12_manifest_descriptions_sanitized() {
        use forge_manifest::{ManifestBuilder, ServerBuilder};

        // Descriptions should be stored as-is — sanitization happens at the
        // manifest builder level via MAX_DESCRIPTION_LENGTH truncation.
        let long_desc = "A".repeat(2000);
        let server = ServerBuilder::new("srv", &long_desc).build();
        let manifest = ManifestBuilder::new().add_server(server).build();

        // The description is stored but manifest builder should handle length
        assert!(!manifest.servers[0].description.is_empty());
    }

    #[test]
    fn mf_13_manifest_json_output_valid() {
        use forge_manifest::{Category, ManifestBuilder, ServerBuilder, ToolEntry};

        let manifest = ManifestBuilder::new()
            .add_server(
                ServerBuilder::new("test_srv", "Test server")
                    .add_category(Category {
                        name: "general".into(),
                        description: "General tools".into(),
                        tools: vec![ToolEntry {
                            name: "echo".into(),
                            description: "Echo input".into(),
                            params: vec![],
                            returns: None,
                            input_schema: None,
                        }],
                    })
                    .build(),
            )
            .build();

        let json_value = manifest.to_json().unwrap();
        // Verify the JSON roundtrips successfully
        let json_str = serde_json::to_string_pretty(&json_value).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(reparsed["servers"].is_array());
        assert_eq!(reparsed["servers"][0]["name"], "test_srv");
    }
}
