# Contributing to Forgemax

## Development Setup

### Prerequisites

- Rust 1.91.1+ (see `rust-version` in `Cargo.toml`)
- The V8 prebuilt library is fetched automatically during build

### Building

```bash
cargo build --workspace
```

### Running Tests

```bash
# Full test suite (~800 tests)
cargo test --workspace

# Single crate
cargo test -p forge-sandbox

# Minimal build (no optional features)
cargo test --workspace --no-default-features
```

### Linting

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system design. Key crates:

| Crate | Role |
|-------|------|
| `forge-sandbox` | V8 sandbox, IPC, worker pool, AST validator |
| `forge-manifest` | Capability manifest, LiveManifest (arc-swap) |
| `forge-server` | MCP server (rmcp), search + execute tools |
| `forge-client` | MCP client connections, router, timeout, circuit breaker |
| `forge-config` | TOML config, env var expansion, validation |
| `forgemax` (dir: `forge-cli`) | Binary entry point, clap subcommands |
| `forge-error` | Typed DispatchError with fuzzy matching |
| `forge-audit` | Audit event types |
| `forge-test-server` | Mock MCP server for integration tests |

## Testing Conventions

### Test ID Format

Tests use a prefix-number format for traceability:

- `ff_01`, `ff_02` — Feature flag tests
- `cv_01` — Config validation tests
- `dr_01` — Doctor check tests
- `cli_s01` — CLI subcommand tests

### Security Tests

- AST validator bypass tests must cover all evasion techniques
- Never add `unsafe` code without justification and review
- New IPC message types must include backward-compatibility tests

### Using forge-test-server

Integration tests use `forge-test-server`, a mock MCP server with tools:
- `echo` — Returns its input
- `math.add` — Adds two numbers
- `symbols.find` — Returns mock symbol results

## Pull Request Process

1. Fork the repository and create a feature branch
2. Write tests before implementation (TDD)
3. Ensure `cargo test --workspace` passes with zero failures
4. Ensure `cargo clippy --workspace -- -D warnings` is clean
5. Update CHANGELOG.md with your changes
6. Submit a pull request with a clear description

## Release Checklist

1. Bump version in workspace `Cargo.toml` and `npm/package.json`
2. Update `CHANGELOG.md` with all changes
3. Update `UPGRADE.md` if any migration steps are needed
4. Run full test suite: `cargo test --workspace`
5. Run `cargo clippy --workspace -- -D warnings`
6. Run `cargo deny check` (if `deny.toml` exists)
7. Tag: `git tag vX.Y.Z && git push --tags`
8. Verify CI: checksums, SBOM, all platforms green
9. Verify install: `curl -fsSL .../install.sh | bash` on a fresh machine
10. Publish npm: `cd npm && npm publish`

## Vulnerability Reporting

See [SECURITY.md](SECURITY.md) for how to report security vulnerabilities.
