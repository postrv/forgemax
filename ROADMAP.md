# Forgemax Roadmap

## v0.4.0 — Platform Release

- CLI subcommands: `doctor`, `manifest`, `run`, `init`
- Production features default-on: worker-pool, metrics, config-watch
- Documentation: SECURITY.md, CONTRIBUTING.md, examples/
- Production configuration template
- SHA256 installer verification, doctor enhancements, structure-aware truncation
- Concurrent server startup via JoinSet + Semaphore

## v0.5.0 — Transport Resilience (current)

- `TransportDead` error variant distinguishing permanent transport failures from transient errors
- `ReconnectingClient` decorator with exponential backoff auto-reconnection
- Per-server `reconnect` and `max_reconnect_backoff_secs` configuration
- rmcp 1.2.0 migration (`#[non_exhaustive]` structs, builder API)
- deno_core 0.391, V8 146.8

## v0.6.0 — Observability

- Prometheus metrics endpoint (HTTP)
- OpenTelemetry tracing integration
- Structured audit log output (JSON)
- Health check endpoint
- Dashboard templates (Grafana)

## v0.7.0 — Ecosystem

- Server discovery (auto-detect MCP servers on PATH)
- Configuration profiles (dev/staging/production)
- Plugin system for custom validators

## v1.0.0 — Stability

- Stable public API (SemVer guarantee)
- Long-term support commitment
- Comprehensive migration guides
- Performance benchmarks and optimization

## Non-Goals

The following are explicitly out of scope:

- **VS Code / IDE extension** — Forgemax is a protocol-level gateway, not an editor plugin
- **GUI / TUI** — CLI-first design; use `forgemax doctor --json` and pipe to your preferred UI
- **Telemetry / analytics** — No data leaves your machine unless you configure a downstream server
- **Built-in lodash / utility libraries in sandbox** — Keep the sandbox minimal; LLMs can write vanilla JS
- **Plugin system for sandbox extensions** — Security boundary must remain simple and auditable
