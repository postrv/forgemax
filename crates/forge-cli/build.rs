use std::path::Path;

fn main() {
    // Keep the crate-local copy of forge.toml.example.production in sync with
    // the workspace root copy during local builds. The crate-local copy is what
    // ships to crates.io (cargo publish can't include files outside the crate).
    let workspace_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../forge.toml.example.production");
    let local_copy = Path::new(env!("CARGO_MANIFEST_DIR")).join("forge.toml.example.production");

    if workspace_root.exists() {
        let root_content = std::fs::read_to_string(&workspace_root).unwrap();
        let needs_update = match std::fs::read_to_string(&local_copy) {
            Ok(local_content) => local_content != root_content,
            Err(_) => true,
        };
        if needs_update {
            std::fs::copy(&workspace_root, &local_copy).unwrap();
        }
    }

    println!("cargo::rerun-if-changed=../../forge.toml.example.production");
    println!("cargo::rerun-if-changed=forge.toml.example.production");
}
