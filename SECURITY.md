# Security

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Email security concerns to the repository maintainers via the contact information in the repository
3. Include: vulnerability description, reproduction steps, affected versions, potential impact
4. We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days

## Threat Model

### Trust Boundaries

```
  LLM (untrusted code author)
       │
       ▼
  Forgemax Gateway (trust boundary 1: AST + V8 sandbox)
       │
       ▼
  Downstream MCP Servers (trust boundary 2: credential isolation)
       │
       ▼
  Backend APIs (databases, SaaS, etc.)
```

### Attacker Profiles

| Profile | Goal | Mitigations |
|---------|------|------------|
| Malicious LLM output | Escape sandbox, exfiltrate data | AST validator, V8 isolation, no fs/net/env, error redaction |
| Prompt injection via tool results | Hijack LLM behavior via poisoned tool output | Manifest sanitization, content size limits, typed errors |
| Cross-server data exfiltration | Move data between isolated server groups | Group isolation (strict mode), stash group scoping |
| Denial of service | Exhaust resources | Timeouts, heap caps, concurrency limits, circuit breakers |
| Credential theft | Extract API tokens from config | Opaque bindings, env var expansion (never in sandbox), worker env clearing |

### Data Exfiltration Analysis

The sandbox has **no direct exfiltration channels**:
- No filesystem access (no `fs`, `Deno.readFile`, etc.)
- No network access (no `fetch`, `XMLHttpRequest`, `WebSocket`)
- No environment access (no `process.env`, `Deno.env`)
- No module loading (no `import()`, `require()`, `eval()`)
- Return values go only to the MCP client (the LLM) — not to external endpoints

The only data flow is: **sandbox → forge.callTool() → downstream server → response → sandbox → return to LLM**. Group isolation policies can restrict which servers participate in a single execution.

### Non-Protections

Forgemax does NOT protect against:
- A compromised downstream MCP server returning malicious data
- The LLM itself deciding to misuse legitimate tool calls
- Side-channel attacks on the V8 engine (Spectre, etc.)
- Physical access to the host machine

## Defense-in-Depth Layers

| # | Layer | What It Prevents | Default in v0.4.0? |
|---|-------|-----------------|-------------------|
| 1 | AST Validator | import/require/eval/Deno/process before V8 runs | Yes |
| 2 | V8 Bootstrap | eval/Function constructor removal at runtime | Yes |
| 3 | V8 Isolate | No fs/net/env, fresh per call, memory-isolated | Yes |
| 4 | API Boundary | Opaque bindings, arg validation, rate limits | Yes |
| 5 | Manifest Sanitization | Tool metadata sanitized to prevent prompt injection | Yes |
| 6 | Typed Errors | Structured errors with fuzzy matching | Yes |
| 7 | Content Size Limits | OOM prevention for text/binary responses | Yes |
| 8 | Resource Validation | URI scheme blocklist, path traversal, null bytes | Yes |
| 9 | Session Stash | Key validation, size limits, TTL, group isolation | Yes |
| 10 | Parallel Execution | Bounded concurrency, shared rate limit | Yes |
| 11 | Error Redaction | URLs, IPs, paths, credentials stripped from errors | Yes |
| 12 | Resource Limits | Timeout, heap cap, output size, concurrency cap | Yes |
| 13 | Header Security | Sensitive headers stripped on plain HTTP | Yes |
| 14 | Per-Server Timeouts | Individual timeout per downstream server | Yes |
| 15 | Circuit Breakers | Cascade failure prevention | Yes |
| 16 | Server Groups | Cross-server data flow isolation | Opt-in |
| 17 | Process Isolation | Child process, clean env, kill-on-timeout | Yes |
| 18 | Worker Pool | Health checks, idle reaping, typed IPC errors | Yes |
| 19 | Binary Security | Absolute paths, permission checks, no PATH fallback | Yes |
| 20 | IPC Protocol | Length-delimited JSON, size limits, desync prevention | Yes |
| 21 | Audit Logging | Code hash, tool calls, duration, outcome logging | Yes |

## Sandbox Security Guarantees

1. **No ambient capabilities**: Sandbox code cannot access the filesystem, network, environment variables, or child processes
2. **Fresh runtime per call**: Each `execute()` creates a fresh V8 isolate — no state leaks between executions
3. **Pre-execution validation**: The oxc-powered AST validator catches banned patterns (import, require, eval, Function constructor, Deno.*, process.*) before code reaches V8, including multi-hop alias tracking
4. **Credential isolation**: API tokens and connection details are never exposed to sandbox code — they exist only in the host process
5. **Environment clearing**: Sandbox workers clear all environment variables on startup; downstream stdio servers receive only a small launch allowlist plus explicit per-server `env` entries

## Configuration Hardening Checklist

- [ ] Keep `execution_mode = "child_process"` for process-level isolation
- [ ] Set `chmod 600 forge.toml` to protect secrets
- [ ] Enable `circuit_breaker = true` on all servers
- [ ] Configure server groups with `isolation = "strict"` for sensitive servers
- [ ] Set reasonable `timeout_secs` on all servers (15-60s)
- [ ] Configure stash limits (`max_keys`, `max_total_size_mb`) to prevent abuse
- [ ] Enable worker pool for production (`[sandbox.pool] enabled = true`)
- [ ] Set `max_concurrent` to limit parallel sandbox executions
- [ ] Review `forge.toml.example.production` for a complete hardened config

## Security Testing

Run the full security test suite:

```bash
# All tests including security integration tests
cargo test --workspace

# AST validator bypass tests specifically
cargo test -p forge-sandbox ast_

# Security integration tests (child process mode)
cargo test -p forge-sandbox --test security_integration

# Example validation (ensures examples don't contain banned patterns)
cargo test -p forge-sandbox --test example_validation
```

## Known Limitations

- **V8 engine vulnerabilities**: Forgemax inherits any V8 security issues. Keep `deno_core` updated.
- **Timing side channels**: No protection against timing-based information leakage between tool calls.
- **Resource exhaustion**: While limits exist, a determined attacker with many concurrent sessions could still cause load. Rate limiting at the MCP client level is recommended.
- **No sandboxing of downstream servers**: Forgemax trusts that downstream MCP servers behave correctly. A compromised server could return malicious data.
