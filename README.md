# Forgemax

**Code Mode MCP Gateway** — collapses N servers x M tools into 2 tools (~1,000 tokens).

Instead of dumping every tool schema into the LLM's context window, Forgemax exposes exactly two MCP tools:

- **`search`** — query a capability manifest to discover tools (read-only, sandboxed)
- **`execute`** — run JavaScript against the tool API in a sandboxed V8 isolate

The LLM writes JavaScript that calls through typed proxy objects. Credentials, file paths, and internal state never leave the host — the sandbox only sees opaque bindings.

Forgemax's Code Mode approach draws inspiration from [Cloudflare's sandbox tool-calling pattern](https://blog.cloudflare.com/code-mode/) — their implementation of sandboxed code execution for MCP tool orchestration is excellent and well worth studying. We encourage supporting their work.

## Why

| Traditional MCP | Forgemax Code Mode |
|---|---|
| 76 tools = ~15,000 tokens of schema | 2 tools = ~1,000 tokens |
| 5-10 sequential round-trips | 1 `execute()` call with chaining |
| Every new tool widens the context | Tool count is invisible to the LLM |

LLMs are trained on billions of lines of code. They're better at writing `narsil.symbols.find({pattern: "handle_*"})` than picking the right tool from a 76-item JSON schema list.

## Architecture

```
forgemax                 Binary entry point (stdio MCP transport)
  forge-config           TOML config loading with env var expansion
  forge-client           MCP client connections (stdio + HTTP/SSE)
  forge-server           MCP server handler (search + execute via rmcp)
    forge-sandbox        V8 sandbox (deno_core, dual-mode execution)
      forgemax-worker    Isolated child process for V8 execution
    forge-manifest       Hierarchical capability manifest registry
  forge-test-server      Mock MCP server for integration tests
```

### forge-sandbox

The core innovation. Uses `deno_core` to run LLM-generated JavaScript in a locked-down V8 isolate:

- No filesystem, network, environment, or child process access
- Fresh runtime per execution (no state leakage)
- Pre-execution validation (banned patterns caught before V8)
- Timeout + heap limit enforcement
- Output size caps
- Tool call rate limiting
- Opaque bindings — credentials never exposed to sandbox code
- Dual-mode execution: in-process (tests) or isolated child process (production)

### forgemax-worker

Isolated child process binary for production execution. Communicates with the parent via length-delimited JSON IPC over stdin/stdout. Starts with a clean environment — no env vars, no inherited file descriptors. Even a V8 zero-day is contained at the OS process boundary.

### forge-manifest

Queryable index of all tools across all connected MCP servers. Supports progressive discovery:

- **Layer 0**: Server names + descriptions (~50 tokens)
- **Layer 1**: Categories per server (~200 tokens)
- **Layer 2**: Tool list per category (~500 tokens)
- **Layer 3**: Full schema per tool (~200 tokens each)

Built dynamically from live `tools/list` responses when downstream servers connect.

### forge-client

MCP client connections to downstream servers. Supports stdio and HTTP/SSE transports. `RouterDispatcher` routes `callTool(server, tool, args)` to the correct downstream connection.

### forge-server

Implements `ServerHandler` from rmcp. Exposes `search` and `execute` as MCP tools, wires them to the sandbox executor, and serves over stdio.

### forge-config

TOML configuration with environment variable expansion (`${GITHUB_TOKEN}`). Configures downstream servers, transports, sandbox limits, and execution mode.

## Install

**npm** (recommended):
```bash
npm install -g forgemax
```

**Homebrew** (macOS/Linux):
```bash
brew tap postrv/forgemax && brew install forgemax
```

**Shell installer** (macOS/Linux):
```bash
curl -fsSL https://raw.githubusercontent.com/postrv/forgemax/main/install.sh | bash
```

**PowerShell** (Windows):
```powershell
irm https://raw.githubusercontent.com/postrv/forgemax/main/install.ps1 | iex
```

**Scoop** (Windows):
```powershell
scoop bucket add forgemax https://github.com/postrv/scoop-forgemax
scoop install forgemax
```

**Cargo** (from source):
```bash
cargo install forge-cli
```

**From source**:
```bash
cargo build --release
# Binaries: target/release/forgemax + target/release/forgemax-worker
```

## Quick Start

```bash
# Run (serves MCP over stdio)
RUST_LOG=info forgemax

# Run tests (development)
cargo test --workspace
```

### Configuration

Copy the example config and add your tokens:

```bash
cp forge.toml.example forge.toml
```

The example includes pre-configured connections for 11 reputable MCP servers:

| Server | Company | Transport | Auth |
|--------|---------|-----------|------|
| narsil | — | stdio | None |
| github | GitHub | stdio (Docker) | Personal access token |
| playwright | Microsoft | stdio (npx) | None |
| sentry | Sentry | stdio (npx) | Auth token |
| cloudflare | Cloudflare | SSE | OAuth |
| supabase | Supabase | stdio (npx) | Access token |
| notion | Notion | stdio (npx) | Integration token |
| figma | Figma | SSE | OAuth |
| stripe | Stripe | stdio (npx) | Secret key |
| linear | Linear | SSE | OAuth |
| atlassian | Atlassian | SSE | OAuth |

Uncomment only the servers you need. Environment variables are expanded (`${GITHUB_TOKEN}`).

<details>
<summary>Minimal config (narsil only)</summary>

```toml
[servers.narsil]
command = "narsil-mcp"
args = ["--repos", "."]
transport = "stdio"

[sandbox]
timeout_secs = 5
max_heap_mb = 64
execution_mode = "child_process"
```
</details>

<details>
<summary>Advanced options</summary>

```toml
# Per-server resilience
[servers.narsil]
command = "narsil-mcp"
args = ["--repos", "."]
transport = "stdio"
timeout_secs = 30
circuit_breaker = true
failure_threshold = 3
recovery_timeout_secs = 60

# Cross-server data flow isolation
[groups.internal]
servers = ["supabase"]
isolation = "strict"

[groups.external]
servers = ["notion", "linear", "atlassian"]
isolation = "strict"

[groups.tools]
servers = ["narsil", "playwright", "github"]
isolation = "open"
```
</details>

## How It Works

**1. Agent discovers tools via `search()`:**

```javascript
async () => {
  return manifest.servers.map(s => ({
    name: s.name,
    categories: Object.keys(s.categories)
  }));
}
```

**2. Agent calls tools via `execute()`:**

```javascript
async () => {
  const symbols = await forge.callTool("narsil", "symbols.find", {
    pattern: "handle_*"
  });
  const refs = await forge.callTool("narsil", "symbols.references", {
    symbol: symbols[0].name
  });
  return { symbols, refs };
}
```

**3. Or using the proxy API:**

```javascript
async () => {
  const result = await forge.server("narsil").ast.parse({ file: "main.rs" });
  return result;
}
```

The sandbox executes JavaScript, routes `forge.callTool()` to real MCP servers via the `ToolDispatcher` trait, and returns JSON. The LLM never sees credentials, connection details, or raw API surfaces.

## Security Model

```
Code Validator          Banned patterns, size limits, Unicode normalization,
                        comment stripping, whitespace-aware matching
        |
  V8 Bootstrap          eval/Function constructor removal at runtime
        |
   V8 Isolate           No fs/net/env, fresh per call, memory-isolated
        |
  API Boundary          Opaque bindings, arg validation, rate limits
        |
Manifest Sanitization   Tool metadata sanitized to prevent prompt injection
        |
 Content Size Limits    OOM prevention for text (10MB), binary (1MB) responses
        |
  Error Redaction       URLs, IPs, paths, credentials, stack traces stripped
                        before reaching the LLM — validation errors preserved
        |
 Resource Limits        Timeout, heap cap, output size cap, concurrency cap
        |
 Header Security        Sensitive headers (auth, token, key, cookie, secret,
                        credential, password) stripped on plain HTTP
        |
 Per-Server Timeouts    Individual timeout per downstream server
        |
  Circuit Breakers      Closed → Open → HalfOpen state machine per server,
                        prevents cascade failures from flaky downstreams
        |
  Server Groups         Opt-in strict/open isolation policies controlling
                        cross-server data flow within a single execution
        |
Process Isolation       Child process, clean env, kill-on-timeout (production mode)
        |
 Binary Security        Absolute paths only, permission checks, no PATH fallback
        |
  IPC Protocol          Length-delimited JSON, configurable message size limits,
                        protocol desync prevention
        |
  Audit Logging         Every execution logged — code hash, tool calls, duration, outcome
```

Three rounds of adversarial security testing (automated scanners + manual review + Arbiter prompt shield) resolved 19 findings across all severity levels. See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed security analysis.

## Tests

222 tests across the workspace:

```
forge-sandbox       108 unit + 10 integration (child process mode)
forge-manifest       25 (builders + dynamic generation + sanitization)
forge-config         24 (parsing, validation, env expansion, groups)
forge-client         32 unit (router, timeout, circuit breaker, header sanitization) + 9 e2e
forge-server          6 unit + 4 integration
forge-cli             4 unit (config parsing)
```

```bash
cargo test --workspace
```

## Dependencies

| Crate | Version | Purpose |
|---|---|---|
| deno_core | 0.385 | V8 sandbox runtime |
| rmcp | 0.16 | MCP protocol (server + client) |
| tokio | 1.x | Async runtime |
| serde | 1.x | Serialization |
| schemars | 1.0 | JSON Schema (matches rmcp) |
| sha2 | 0.10 | Code hashing for audit log |
| chrono | 0.4 | Audit timestamps |

## License

[FSL-1.1-ALv2](LICENSE) — Functional Source License, Version 1.1, with Apache License 2.0 future grant.

You can use, modify, and redistribute Forgemax for any purpose **except** offering a competing commercial product or service. After two years from each release, that version converts to Apache 2.0.
