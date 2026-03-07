# Changelog

All notable changes to Forgemax will be documented in this file.

## [0.4.2] - 2026-03-07

### Added

- **Concurrent server startup:** Downstream MCP server connections are now made concurrently at startup using `JoinSet` + `Semaphore`, replacing the previous sequential loop. 10 servers × 500ms = 5s sequential → ~500ms concurrent. Configurable via `sandbox.startup_concurrency` (default 8, cap 64, set to 1 for sequential).
- **CV-12 config validation:** `sandbox.startup_concurrency` must be >= 1 and <= 64.
- **4 new config tests:** `cv_12_startup_concurrency_validation`, `default_startup_concurrency_is_at_least_one`, `sc_01_startup_concurrency_config_parses`, `sc_02_startup_concurrency_defaults_to_none`.

### Changed

- **Startup safety:** Transport configs are validated upfront before spawning any connection tasks (fail-fast, no orphan risk). `JoinSet` (not `Vec<JoinHandle>`) ensures all in-flight tasks are aborted on Drop if any connection fails, preventing task/process leaks.
- **Test count:** ~780 tests (up from ~800).

### Acknowledgements

- Thanks to [Madison Steiner (@mh0pe)](https://github.com/mh0pe) for the concurrent startup idea in [PR #1](https://github.com/postrv/forgemax/pull/1).

## [0.4.1] - 2026-03-01

### Added

- **SHA256 installer verification:** Both `install.sh` and `npm/install.js` now verify downloaded archive checksums against `SHA256SUMS.txt` from the release. Falls back gracefully for older releases.
- **Doctor memory pressure check:** `forgemax doctor` calculates worst-case memory usage (`max_concurrent` x `max_heap_mb`) and warns if it exceeds 80% of system RAM.
- **Doctor circuit breaker check:** Warns when SSE servers are configured without circuit breakers.
- **Doctor token format check:** Detects common token mistakes (embedded quotes, newlines, misplaced `Bearer` prefix) in header values.
- **`cargo deny` CI job:** License compliance, advisory, ban, and source policy checking via `deny.toml`.
- **V8 fetch composite action:** `.github/actions/fetch-v8/action.yml` replaces 10+ duplicated V8 download blocks across CI workflows.
- **CycloneDX SBOM:** `forgemax-sbom.json` is now attached to every GitHub release.
- **Token savings benchmark:** `cargo run -p forge-manifest --example token_savings` — measures and reports context window savings.
- **Performance section in README:** Measured token savings table (73-98% reduction depending on tool count).
- **Workspace clippy lint policy:** `[workspace.lints.clippy]` declares `unwrap_used`, `expect_used`, `panic` as warnings (opt-in per crate).
- **`#![warn(missing_docs)]`** added to `forge-error` and `forge-audit`.

### Changed

- **Structure-aware truncation:** `truncate_result_if_needed` now cuts at newline/comma boundaries instead of arbitrary character positions. Adds `_data_is_fragment: true` flag to truncated results so LLMs know not to `JSON.parse()` the fragment.
- **Error handling dedup:** Extracted `format_sandbox_result()` helper to eliminate duplicated error formatting between `search()` and `execute()`.
- **forge.d.ts:** Added truncation behavior documentation.
- **Test count:** ~800 tests (up from ~740).

### Changed (Dependencies)

- **deno_core:** 0.385 → 0.387
- **rmcp:** 0.16 → 0.17
- **v8:** 145 → 146.1

### Fixed

- **Truncation safety:** Truncated results no longer produce invalid JSON fragments inside the `data` field. Cut points are now structure-aware.

## [0.4.0] - 2026-03-01

### Added

- **CLI subcommands:** `forgemax doctor` (configuration validation), `forgemax manifest` (capability inspection), `forgemax run <file>` (JavaScript execution), `forgemax init` (config generation). Uses clap for argument parsing. Default behavior (no args = serve) is unchanged.
- **Production config example:** `forge.toml.example.production` with worker pool, circuit breakers, strict groups, and stash limits.
- **Example files:** 7 JavaScript examples demonstrating all sandbox APIs (`examples/`), plus 2 group isolation TOML configs.
- **Example validation tests:** AST validation, header checks, and UTF-8/BOM verification for all examples.
- **SECURITY.md:** Comprehensive security documentation with threat model, defense-in-depth table, and hardening checklist.
- **CONTRIBUTING.md:** Developer setup, testing conventions, and PR process.
- **ROADMAP.md:** Project roadmap with non-goals.
- **Upgrade path tests:** v0.3.x config compatibility verification (UP-01 through UP-03).
- **Production config parse tests:** CFG-P01 through CFG-P06 verifying production example validity.
- **Feature status banner:** `feature_status_line()` logs compiled feature flags at startup.

### Changed

- **Feature flags default-on:** `worker-pool`, `metrics`, and `config-watch` are now enabled by default. Use `--no-default-features` for minimal builds. Added `minimal = []` feature to both `forge-sandbox` and `forge-config`.
- **README.md:** Added CLI commands table, examples section, doctor in quick start, link to SECURITY.md.
- **`find_worker_binary` visibility:** Changed from `pub(crate)` to `pub` for use by `forgemax doctor`.
- **forge-cli features:** Added feature forwarding section for `worker-pool`, `metrics`, `config-watch`.
- **Test count:** ~740 tests (up from 618).

## [0.3.1] - 2026-02-28

### Fixed

- **IPC error type preservation:** `IpcDispatchError` struct preserves `DispatchError` variant (code, server, tool) across the IPC boundary. Structured error codes (`SERVER_NOT_FOUND`, `TOOL_NOT_FOUND`) and fuzzy-match suggestions now work correctly in ChildProcess mode.
- **Pre-dispatch tool name validation:** `RouterDispatcher` validates tool names before dispatching to upstream servers. Misspelled tool names now return `TOOL_NOT_FOUND` with Levenshtein suggestions instead of opaque upstream errors.
- **AST `require()` blocking:** `require` added to `DANGEROUS_IDENTIFIERS` and `check_call_callee`, preventing `require('child_process')` and alias evasion (`const r = require; r('fs')`).
- **Flaky timeout test:** `rs_i06_read_resource_timeout_enforcement` now accepts both async timeout and CPU watchdog timeout messages, fixing a race condition between the two timeout mechanisms.

## [0.3.0] - 2026-02-28

### Added

- **AST-based code validator** — replaces regex patterns with oxc-powered static analysis for sandbox code validation. 28 bypass tests verify security guarantees.
- **Typed `DispatchError` enum** — replaces `anyhow::Error` across all dispatchers with structured, matchable error variants (`ServerNotFound`, `ToolNotFound`, `Timeout`, `CircuitOpen`, `GroupPolicyDenied`, `Upstream`, `RateLimit`, `Internal`).
- **Worker pool** — warm process reuse via `Reset`/`ResetComplete` IPC messages. Configurable pool size with automatic scaling.
- **ErrorKind typed errors across IPC** — preserves error types (`Timeout`, `HeapLimit`, `JsError`, `Execution`) across the child process boundary.
- **TypeScript API definitions** — `forge.d.ts` compiled into the binary and served in MCP server instructions for LLM type awareness.
- **Structured errors with fuzzy matching** — tool/resource errors return `{error, code, message, retryable, suggested_fix}` JSON instead of throwing JS exceptions. Levenshtein-based suggestions for typos.
- **LiveManifest** — lock-free manifest reads via `arc-swap` with atomic swap for background refresh.
- **Manifest refresh** — periodic re-discovery of downstream server tools + SIGHUP-triggered refresh (Unix).
- **`TracingAuditLogger`** — structured audit logging via `tracing` spans on key operations.
- **`#[non_exhaustive]`** — applied to all 14 public enums for semver-safe future extensibility.
- **`AuditEntry` pool metadata** — `worker_reused` and `pool_size_at_acquire` fields for observability.
- **`ManifestConfig`** — configurable `refresh_interval_secs` for periodic tool re-discovery.

### Changed

- **Breaking:** `ToolDispatcher::call_tool` and `ResourceDispatcher::read_resource` return `Result<_, DispatchError>` instead of `Result<_, anyhow::Error>`.
- Error assertions in tests migrated from string `.contains()` to typed `matches!` and structured error code checks.
- `build.rs` for `forge-manifest` triggers recompilation on `forge.d.ts` changes.

### Fixed

- Clippy warning in audit test (`unused variable` turned into meaningful security assertion).

## [0.2.0] - 2026-02-15

### Added

- Resource reading via `forge.readResource(server, uri)`.
- Session-scoped key-value stash (`forge.stash.put/get/delete/keys`).
- `forge.parallel()` for bounded concurrent tool/resource calls.
- Server instructions with tool name guidance.
- Error redaction for LLM-facing error messages.

## [0.1.0] - 2026-01-20

### Added

- Initial release: Code Mode MCP Gateway.
- `forge.callTool(server, tool, args)` — proxy tool calls to downstream MCP servers.
- `forge.server("name").category.tool(args)` — hierarchical tool access.
- Sandbox execution via deno_core V8 isolate.
- Child process worker with secure IPC (4-byte length prefix + JSON).
- TOML configuration with environment variable expansion.
- Circuit breaker and timeout support per downstream server.
