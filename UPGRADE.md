# Upgrading Forgemax

## v0.5.0 (Transport Resilience + Dependency Upgrades)

### Breaking: rmcp 0.17 → 1.2.0

rmcp 1.2 marks all model structs `#[non_exhaustive]`. If you construct rmcp types directly (e.g., `Implementation { ... }`), you must migrate to the builder API:

```rust
// Before (rmcp 0.17)
Implementation {
    name: "my-server".into(),
    version: "1.0".into(),
}

// After (rmcp 1.2)
Implementation::new("my-server", Some("1.0"))
```

Affected types: `Implementation`, `ServerInfo`, `CallToolResult`, `ReadResourceResult`, `ListResourcesResult`, `CallToolRequestParams`, `ReadResourceRequestParams`.

### New Config Fields

Two optional fields on `[servers.*]`:

```toml
[servers.my-server]
reconnect = true                  # Enable auto-reconnect on transport death (default: true for stdio)
max_reconnect_backoff_secs = 30   # Max backoff between reconnect attempts (default: 30)
```

### New Error Variant

`DispatchError::TransportDead` is a new variant for permanent transport failures (broken pipe, channel closed). If you match exhaustively on `DispatchError`, add a branch for `TransportDead`. It is not retryable — the `ReconnectingClient` decorator handles reconnection automatically.

### Decorator Chain Change

The client decorator chain is now: `McpClient → ReconnectingClient → Timeout → CircuitBreaker → Router`. The reconnecting layer sits below timeout/circuit-breaker so transport death is caught before circuit breaker probing.

### Configuration Compatibility

v0.4.x configuration files work without modification. The new `reconnect` and `max_reconnect_backoff_secs` fields default to safe values when absent.

---

## v0.4.0 (Platform Release)

### Feature Flag Migration

In v0.3.x, `worker-pool`, `metrics`, and `config-watch` were opt-in features (default off). In v0.4.0, all three are **default-on**.

**If you were already using `--features worker-pool,metrics`:** Remove the flag — features are now on by default. The redundant flag is harmless but unnecessary.

**If you want a minimal build:** Use `--no-default-features` to disable all optional features:
```bash
cargo build --release --no-default-features
```

**If you want selective features:** Combine `--no-default-features` with `--features`:
```bash
cargo build --release --no-default-features --features ast-validator,worker-pool
```

### New CLI Subcommands

`forgemax` now uses `clap` for argument parsing with subcommands:

| Command | Description |
|---------|-------------|
| `forgemax` (no args) | Start the MCP gateway server (unchanged behavior) |
| `forgemax serve` | Explicit alias for the default server mode |
| `forgemax doctor` | Validate configuration and connectivity |
| `forgemax manifest` | Inspect the capability manifest |
| `forgemax run <file>` | Execute a JavaScript file against configured servers |
| `forgemax init` | Generate a starter configuration file |

**Backward compatibility:** Running `forgemax` with no arguments still starts the server, exactly as in v0.3.x.

### Configuration Compatibility

v0.3.x configuration files work without modification. New optional sections (`[sandbox.pool]`, `[manifest]`, `[groups.*]`) default to safe values when absent.

A production configuration example is available at `forge.toml.example.production`.

### New Documentation

- `SECURITY.md` — Comprehensive security model documentation
- `CONTRIBUTING.md` — Developer setup and contribution guidelines
- `ROADMAP.md` — Project roadmap and non-goals
- `examples/` — JavaScript examples demonstrating all sandbox APIs

---

## v0.3.1 (Production Hardening)

### Security Fixes

- **Stash group isolation (H1):** IPC stash messages now carry `group: Option<String>`, ensuring stash data is scoped by server group in ChildProcess mode. Previously, `_current_group` was discarded, allowing cross-group access.
- **Worker stderr hardening (H3):** Worker stderr is now `Stdio::piped()` (debug, bounded to 4KB) or `Stdio::null()` (production). `Stdio::inherit()` is never used, preventing unbounded stderr leakage.
- **URI scheme validation (M2):** `validate_resource_uri()` now blocks dangerous URI schemes (`data:`, `javascript:`, `ftp:`, `gopher:`, `telnet:`, `ldap:`, `dict:`). Custom MCP schemes (e.g., `postgres://`) are allowed.
- **AST alias detection (AST-12):** The AST validator now detects aliased dangerous identifiers (`const e = eval; e("code")`), including multi-hop aliases and destructured eval from `globalThis`.
- **AST `require()` blocking:** `require` added to `DANGEROUS_IDENTIFIERS` and `check_call_callee`, preventing `require('child_process')` and alias evasion (`const r = require; r('fs')`).
- **Audit code_preview redaction:** `code_preview` in audit entries is now passed through `redact_error_message()` to strip credentials before logging.
- **Stash operation limits:** Per-execution rate limiting for stash operations via `max_stash_calls` in `StashOverrides`.

### Bug Fixes

- **IPC error type preservation:** Introduced `IpcDispatchError` struct to preserve `DispatchError` variant (code, server, tool, timeout_ms) across the IPC boundary. Previously, typed errors were flattened to strings when crossing from host to worker, losing structured error information (fuzzy-match suggestions, error codes).
- **Pre-dispatch tool name validation:** `RouterDispatcher` now validates tool names against known tools before dispatching to upstream servers. Previously, misspelled tool names were sent upstream and returned as generic `Upstream` errors with no fuzzy-match suggestions. Now returns `ToolNotFound` with Levenshtein-based suggestions (e.g., `find_symbls` → `Did you mean 'find_symbols'?`).

### New Features

- **Worker pool pre-warming:** `WorkerPool::pre_warm()` spawns `min_workers` workers at startup (requires `worker-pool` feature).
- **Background reaping:** `WorkerPool::start_reap_task()` runs periodic idle worker cleanup while preserving `min_workers` (requires `worker-pool` feature).
- **Prometheus metrics:** `ForgeMetrics` struct with execution counters, duration histograms, error counters, and pool gauges (requires `metrics` feature).
- **Structured timeout in IPC:** `ExecutionComplete` now carries `timeout_ms: Option<u64>` for structured timeout reporting, with backward-compatible string parsing fallback.
- **Raw IPC passthrough:** `write_raw_message()` / `read_raw_message()` functions for zero-copy message forwarding.

### Feature Flags

New optional feature flags (all default off):
- `worker-pool` — gates `pre_warm()` and `start_reap_task()` in forge-sandbox
- `metrics` — gates `prometheus-client` dependency and `ForgeMetrics` module
- `config-watch` — gates `notify` crate for config file watching (forge-config)

### IPC Backward Compatibility

All new IPC fields use `#[serde(default, skip_serializing_if = "Option::is_none")]`. A v0.3.1 parent receiving a v0.3.0 worker message (missing new fields) deserializes them as `None`. A v0.3.0 parent receiving a v0.3.1 worker message (extra fields) ignores them. Rolling upgrades are safe in both directions.

## v0.3.0

### Breaking Changes

- **`ToolDispatcher::call_tool`** and **`ResourceDispatcher::read_resource`** now return `Result<Value, DispatchError>` instead of `Result<Value, anyhow::Error>`. Update trait implementations to use `forge_error::DispatchError`.
- **`SandboxConfig`** has new required fields. Use struct update syntax (`..Default::default()`) when constructing.

### Migration

- Replace string `.contains()` assertions on errors with typed `matches!` patterns on `DispatchError` or `SandboxError` variants.
- Update `ToolDispatcher` / `ResourceDispatcher` implementations to return `DispatchError`.

### New Features

- **AST validator:** Pre-execution validation of JavaScript code for banned patterns, import/require, eval, and environment access.
- **Structured errors:** `DispatchError` enum with `ServerNotFound`, `ToolNotFound`, `ExecutionFailed`, and `Timeout` variants, plus fuzzy matching suggestions.
- **LiveManifest refresh:** `arc-swap`-based lock-free manifest with SIGHUP and periodic refresh.
- **Worker pool:** Configurable worker pool with health checks, max-uses recycling, and idle reaping.
- **Resource reading:** `ResourceDispatcher` trait and `readResource()` sandbox API.
- **Stash API:** Per-session key-value store with TTL, group isolation, and audit logging.
