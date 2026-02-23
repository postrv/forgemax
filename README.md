# Forge

**Code Mode MCP Gateway** — collapses N servers x M tools into 2 tools (~1,000 tokens).

Instead of dumping every tool schema into the LLM's context window, Forge exposes exactly two MCP tools:

- **`search`** — query a capability manifest to discover tools (read-only, sandboxed)
- **`execute`** — run JavaScript against the tool API in a sandboxed V8 isolate

The LLM writes JavaScript that calls through typed proxy objects. Credentials, file paths, and internal state never leave the host — the sandbox only sees opaque bindings.

## Why

| Traditional MCP | Forge Code Mode |
|---|---|
| 76 tools = ~15,000 tokens of schema | 2 tools = ~1,000 tokens |
| 5-10 sequential round-trips | 1 `execute()` call with chaining |
| Every new tool widens the context | Tool count is invisible to the LLM |

LLMs are trained on billions of lines of code. They're better at writing `narsil.symbols.find({pattern: "handle_*"})` than picking the right tool from a 76-item JSON schema list.

## Architecture

```
forge-cli                Binary entry point (stdio MCP transport)
  forge-config           TOML config loading with env var expansion
  forge-client           MCP client connections (stdio + HTTP/SSE)
  forge-server           MCP server handler (search + execute via rmcp)
    forge-sandbox        V8 sandbox (deno_core, dual-mode execution)
      forge-sandbox-worker  Isolated child process for V8 execution
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

### forge-sandbox-worker

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

## Quick Start

```bash
# Build
cargo build --release

# Run (serves MCP over stdio)
RUST_LOG=info cargo run

# Run tests
cargo test --workspace
```

### Configuration

Create `forge.toml` in your working directory:

```toml
[servers.narsil]
command = "narsil-mcp"
args = ["--repos", "."]
transport = "stdio"

[servers.github]
url = "https://mcp.github.com/sse"
transport = "sse"
headers = { Authorization = "Bearer ${GITHUB_TOKEN}" }

[sandbox]
timeout_secs = 5
max_heap_mb = 64
max_concurrent = 8
max_tool_calls = 50
execution_mode = "child_process"  # or "in_process" (default)
```

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
Input Validation        Banned patterns, size limits, format checks
        |
   V8 Isolate           No fs/net/env, fresh per call, memory-isolated
        |
  API Boundary          Opaque bindings, per-op auth, rate limits, arg validation
        |
 Resource Limits        Timeout, heap cap, output size cap, concurrency cap
        |
Process Isolation       Child process, clean env, kill-on-timeout (production mode)
        |
  Audit Logging         Every execution logged — code hash, tool calls, duration, outcome
```

## Tests

122 tests across the workspace:

```
forge-sandbox       52 unit + 10 integration (child process mode)
forge-manifest      19 (builders + dynamic generation)
forge-config        15 (parsing, validation, env expansion)
forge-client         7 unit (router) + 9 e2e (real MCP connections)
forge-server         6 unit + 4 integration
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

MIT
