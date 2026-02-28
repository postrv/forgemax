fn main() {
    println!("cargo:rerun-if-changed=src/forge.d.ts");

    // Validate that forge.d.ts contains key interfaces.
    // Types are hand-authored (JSDoc examples can't be auto-generated),
    // so we validate structural presence at build time.
    let dts = std::fs::read_to_string("src/forge.d.ts").expect("forge.d.ts must exist");

    let required = [
        "interface Forge",
        "interface ForgeStash",
        "interface StashPutOptions",
        "interface ParallelCall",
        "callTool",
        "readResource",
        "server(",
    ];

    for keyword in &required {
        assert!(
            dts.contains(keyword),
            "forge.d.ts must contain '{}' — did you accidentally remove a key type?",
            keyword
        );
    }
}
