# Changelog

All notable changes to Forgemax will be documented in this file.

## [0.6.0] - 2026-05-14

### Security

- **Stdio child env isolation:** Downstream stdio MCP servers no longer inherit the parent process environment. `forge-client` now calls `env_clear()` on every stdio launch and passes only a small allowlist (`PATH`, `HOME`, `USERPROFILE`, `SYSTEMROOT`, `WINDIR`, `PATHEXT`, `TEMP`, `TMP`, `TMPDIR`, `SSL_CERT_FILE`, `SSL_CERT_DIR`) plus an explicit per-server `env` map from config.
- **Stash group isolation enforced:** `ServerStashDispatcher` now consults the live `SharedGroupLock` for every put/get/delete/keys call. Previously the dispatcher always passed `current_group = None`, so cross-group reads of stash entries were not actually blocked.
- **`forge run` enforces groups:** The `forge run script.js` subcommand now wraps the dispatcher in `GroupEnforcingDispatcher` when `[groups]` are configured. Previously the CLI bypassed group enforcement entirely.
- **Argv/URL redaction in transport logs:** stdio command arguments are scanned for sensitive names (`*token`, `*api*key*`, `*secret*`, `*password*`, `*credential*`) and known secret prefixes (`sk-`, `ghp_`, `gho_`, `ghs_`, `ghr_`, `github_pat_`, `bearer `) and redacted before logging. HTTP URLs have their query string redacted.
- **Safer default execution mode:** When `[sandbox]` does not specify `execution_mode`, `forge serve`/`run` now default to `child_process` (was `in_process`). An unknown `execution_mode` value at runtime now warns and falls back to `child_process` instead of silently falling back to `in_process`.
- **Pool worker structured-error fix:** Pooled workers now receive `known_servers` and `known_tools`. Previously the worker pool path didn't propagate these, regressing structured-error fuzzy matching introduced in v0.3.1 (the fix only applied in non-pooled child-process mode).
- **install.ps1 SHA256 verification:** The PowerShell installer now downloads `SHA256SUMS.txt` and verifies the archive hash before extraction, matching the existing `install.sh` and `npm/install.js` behaviour.

### Added

- **`[servers.*].env` config field:** Map of explicit environment variables passed to stdio child processes. Supports `${VAR}` env expansion. Required for downstream servers that need credentials (e.g., `GITHUB_PERSONAL_ACCESS_TOKEN`) now that the parent environment is no longer inherited.
- **`[sandbox.stash].max_calls`:** Per-execution cap on stash operations (default unlimited). Plumbed through `StashCallLimits` and validated against an upper bound of 10,000.
- **Range validation for sandbox limits:** `timeout_secs` (1-3600), `max_heap_mb` (1-4096), `max_concurrent` (1-256), `max_tool_calls` (1-10000), `max_ipc_message_size_mb` (1-512), `stash.max_calls` (1-10000), and `execution_mode` (must be `child_process` or `in_process`) are now rejected at config parse time with explicit error messages.
- **`deny_unknown_fields` on all config structs:** Typos and stale config keys are now rejected at parse time instead of being silently ignored.
- **Structured resource truncation:** When a resource exceeds `max_resource_size`, the host now returns a structured object `{_truncated, _data_is_fragment, _shown_bytes, _original_bytes, data}` instead of truncated raw JSON (which JS would fail to parse).

### Changed

- **`TransportConfig::Stdio` gains an `env: HashMap<String, String>` field.** External consumers constructing this enum directly must add the field; downstream of `to_transport_config()` (the CLI path) this is transparent.
- **`max_resource_size` default: 64 MB (unchanged); `max_ipc_message_size` default: 8 MB to 65 MB.** The IPC default is now sized to fit a full-size resource payload (64 MB) plus 1 MB envelope overhead. Previously the two defaults were internally inconsistent: a 64 MB resource could not actually flow through the 8 MB IPC envelope in `child_process` mode. Tighten both for memory-constrained deployments.
- **`SandboxExecutor::run_execute_with_known_servers`:** New `StashCallLimits` parameter (additive; callers that don't pass it get unlimited stash operations as before).
- **`PooledExecutionContext`:** New struct bundles `dispatcher`, `resource_dispatcher`, `stash_dispatcher`, `known_servers`, `known_tools` for pooled worker execution (refactor, not a breaking change for external callers).

### Changed (Dependencies)

- **deno_core:** 0.398 to 0.400
- **serde_v8:** 0.307 to 0.309 (transitive via deno_core)
- **v8:** 147.2 to 147.4 (transitive via deno_core)
- **deno_error:** =0.7.1 (unchanged; still pinned to match deno_core)
- **oxc_parser / oxc_ast / oxc_span / oxc_allocator:** 0.126 to 0.130
- **notify:** 7 to 8 (8.2.0)

### Changed (Platform)

- **macOS deployment target:** raised to 13.0 (Ventura, Oct 2022). v8 147.4 prebuilts are compiled with a macOS 12.0+ deployment target; the CI/release workflows now set `MACOSX_DEPLOYMENT_TARGET=13.0` so released macOS binaries declare a modern minimum and link cleanly. Users on macOS 11 / 12 should pin to v0.5.1.

### Fixed

- **UTF-8 boundary panics in truncation:** Added `floor_char_boundary` helper in three sites (`forge-client`, `forge-server`, `forge-sandbox/ops`) where multi-byte UTF-8 strings could trigger panics when sliced at exact byte limits.
- **Config watcher hang under parallel test execution / cross-file events:** `notify::recommended_watcher` watches the parent directory of the config file (to catch atomic-rename saves), which previously fired the FSEvents callback for *any* file in that directory. Multiple watchers on the same parent dir (e.g., parallel `tempfile`-based tests on macOS) filled the bounded mpsc channel until `blocking_send` deadlocked the FSEvents thread, then runtime shutdown could not drain it. The callback now (a) filters `event.paths` to match the watched file via canonicalized path comparison, and (b) uses `try_send` instead of `blocking_send` (the 200 ms polling tick will catch any dropped hint).

### Verification

- `cargo test --workspace --no-fail-fast` -- 803 passed, 0 failed, 1 ignored.
- `cargo clippy --workspace --all-targets -- -D warnings` -- clean.

## [0.5.1] - 2026-04-17

### Fixed

- **ReconnectingClient coordination:** Concurrent callers that detect a dead transport now wait on a `tokio::sync::Notify` for the in-flight reconnection to finish, then retry with the fresh client. Previously a fixed 100ms sleep was used — too short under heavy load, causing waiting callers to give up and surface transport errors that could then trip the circuit breaker. A 30s bounded wait prevents hangs if the reconnector is stuck.

### Changed (Dependencies)

- **deno_core:** 0.391 → 0.398
- **v8:** 146.3 → 147.2
- **serde_v8:** 0.300 → 0.307
- **oxc_parser / oxc_ast / oxc_span / oxc_allocator:** 0.115 → 0.126
- **sha2:** 0.10 → 0.11 (major bump; internal hashing API unchanged)

## [0.5.0] - 2026-03-17

### Added

- **TransportDead error variant:** New `DispatchError::TransportDead` distinguishes permanent transport failures (broken pipe, channel closed) from transient upstream errors. Not retryable — requires reconnection at a higher layer.
- **ReconnectingClient decorator:** Auto-reconnects on `TransportDead` errors with exponential backoff (1s → 2s → 4s → ... → max). Uses `RwLock` for zero-contention reads during normal operation. Default enabled for stdio transports.
- **Reconnect config fields:** `reconnect` (bool) and `max_reconnect_backoff_secs` (u64) on `[servers.*]` config.
- **Transport death detection:** `McpClient` now classifies rmcp errors containing "TransportClosed", "channel closed", or "broken pipe" as `TransportDead` instead of `Upstream`.
- **IPC support:** `TRANSPORT_DEAD` error code preserved across the parent ↔ worker IPC boundary.

### Changed (Dependencies)

- **rmcp:** 0.17 → 1.2.0 (breaking: `#[non_exhaustive]` on model structs, migrated to constructor/builder API)
- **deno_core:** 0.387 → 0.391
- **deno_error:** 0.7 → =0.7.1 (pinned to match deno_core 0.391)
- **v8:** 146.1 → 146.3

### Changed

- **rmcp API migration:** All struct literal constructions (`Implementation`, `ServerInfo`, `CallToolResult`, `ReadResourceResult`, `ListResourcesResult`, `CallToolRequestParams`, `ReadResourceRequestParams`) migrated to use `new()`/`with_*()` builder methods per rmcp 1.2's `#[non_exhaustive]` policy.
- **Decorator chain order:** `McpClient → ReconnectingClient → TimeoutDispatcher → CircuitBreakerDispatcher → Router` (reconnection sits below timeout/CB so transport death is caught before circuit breaker probing).

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
