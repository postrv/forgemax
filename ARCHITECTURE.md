# Forgemax Architecture — Security Considerations

## Cross-Server Isolation

### The Problem

Forgemax collapses N MCP servers into a single sandbox execution context. When an LLM writes `execute()` code, it can call tools on _any_ connected server within the same JavaScript execution:

```javascript
async () => {
  // Read sensitive data from server A
  const secrets = await forge.callTool("vault", "secrets.list", {});
  // Exfiltrate to server B
  await forge.callTool("slack", "messages.send", {
    channel: "#public",
    text: JSON.stringify(secrets)
  });
}
```

This is the **cross-server data flow problem**: any server the LLM can read from, it can write to any other server it can reach. This is not a sandbox escape — the sandbox is working correctly. The LLM is simply using its legitimate tool access in a way that violates an implicit trust boundary.

### Analysis

This is fundamentally an **authorization design question**, not a bug. Consider the threat model:

1. **Trusted LLM, trusted servers**: No issue. The LLM is acting on behalf of the user, and the user has configured all servers. This is the normal case.

2. **Compromised downstream server**: A malicious MCP server could return tool results containing prompt injection payloads designed to trick the LLM into calling tools on other servers. Our manifest sanitization (C1) strips injection from tool _metadata_, but tool _results_ flow through the LLM's context naturally.

3. **Prompt injection via user input**: If the LLM processes untrusted user input that contains injection payloads, it might be directed to exfiltrate data across servers.

### Design Decision: Trust the LLM, Constrain the Blast Radius

Forgemax's position: **the LLM is the user's agent**. If the user connects both a vault server and a Slack server, they are implicitly granting the LLM access to both. Restricting cross-server calls would break the core value proposition — multi-tool chaining in a single execution.

However, we can provide **opt-in isolation** for security-conscious deployments:

#### Server Groups (Implemented)

```toml
[groups.internal]
servers = ["vault", "database"]
isolation = "strict"  # Cannot flow data to other groups

[groups.external]
servers = ["slack", "github"]
isolation = "strict"

[groups.analysis]
servers = ["narsil", "arbiter"]
isolation = "open"  # Can interact with any group
```

`GroupPolicy` (compiled once from config, shared across executions) and `GroupEnforcingDispatcher` (fresh per `execute()` call) enforce data flow policies at the `callTool()` boundary. When a strict-group server is called, the execution is "locked" to that group — subsequent calls to servers in a different strict group are rejected. Open-group and ungrouped servers are always accessible. The dispatcher state is fresh per execution, so there is no cross-execution leakage.

#### Additional Mitigations

1. **Audit logging**: Every `callTool()` invocation is logged with server, tool name, args hash, and timestamp. Cross-server flows are visible in the audit trail.

2. **Manifest sanitization**: Tool names and descriptions from downstream servers are sanitized to prevent injection that could trick the LLM into unexpected tool calls.

3. **Rate limiting**: `max_tool_calls` per execution bounds the damage from a runaway chain.

4. **Process isolation**: Each execution runs in a fresh V8 isolate with no state persistence. A compromised execution cannot influence future ones.

### Cascade Failure Prevention

If one downstream server hangs or crashes, it must not take down the gateway or block other servers.

**Per-server timeouts**: `TimeoutDispatcher` wraps each server connection with a `tokio::time::timeout()`. Configured via `timeout_secs` per server in `forge.toml`. A hanging server is killed at its individual timeout, not the global sandbox timeout.

**Circuit breakers**: `CircuitBreakerDispatcher` wraps outside the timeout layer (`CircuitBreaker(Timeout(McpClient))`), implementing a Closed → Open → HalfOpen state machine:
- **Closed**: Calls pass through. Consecutive failures are counted.
- **Open**: After `failure_threshold` consecutive failures, all calls are rejected immediately without contacting the server.
- **HalfOpen**: After `recovery_timeout_secs`, one probe call is allowed. If it succeeds, the circuit closes. If it fails, it re-opens.

```toml
[servers.narsil]
timeout_secs = 10
circuit_breaker = true
failure_threshold = 3
recovery_timeout_secs = 60
```

Timeouts trip the circuit breaker (a timeout is a failure), so a persistently slow server will be automatically removed from the pool until it recovers.

---

## Error Redaction Philosophy

### The Tension

Security best practice says: **never expose internal error details to untrusted consumers** — stack traces, file paths, database schemas, and connection strings are all information that aids attackers.

But Forgemax's consumer is an LLM that needs to **self-correct**. A redacted error like `"tool call failed"` gives the LLM nothing to work with. A verbose error like `"narsil: symbol 'handleRequet' not found, did you mean 'handleRequest'?"` lets it fix the typo and retry.

### Design Decision: Layered Redaction

Errors flow through three layers, each with different redaction needs:

```
Downstream Server  →  Forgemax Gateway  →  LLM (via MCP)  →  User
```

**Layer 1: Downstream → Gateway** (internal, full detail)

No redaction. The gateway needs full error context for logging and debugging. These errors are written to the audit log with full detail (args are hashed, but error messages are preserved).

**Layer 2: Gateway → LLM** (tool results, moderate redaction)

This is where the balance matters. The LLM needs enough to self-correct, but we should strip:

- **Connection strings and URLs**: Replace with server name (`"server 'narsil' is unreachable"` not `"connection refused: 127.0.0.1:9876"`)
- **File system paths on the gateway host**: The LLM doesn't need to know where Forgemax is installed
- **Stack traces**: Replace with the top-level error message only
- **Credentials in error context**: Should never appear, but strip patterns like `Bearer ...`, API keys

What we should **preserve**:
- Tool name and the fact that it failed
- The downstream server's error _message_ (not stack trace) — this is what helps the LLM self-correct
- Input validation errors ("missing required field 'pattern'")
- Type errors ("expected string, got number")

**Layer 3: LLM → User** (final output)

Not our concern — the LLM decides what to show the user. But by keeping Layer 2 clean, we avoid leaking internal details even if the LLM echoes errors verbatim.

### Implementation

Error redaction is implemented in `forge-sandbox/src/redact.rs` as a standalone, independently tested module. It applies regex-based stripping on the tool call error path in `ops.rs` and on `search()`/`execute()` error branches in `forge-server`:

```rust
pub fn redact_error_for_llm(error: &str) -> String // strips internals, preserves semantics
pub fn redact_error_message(error: &str) -> String  // server-level redaction
```

The redaction pipeline strips (in order): HTTP/HTTPS URLs, IPv4/IPv6 addresses with ports, Unix and Windows file paths, Bearer tokens, API keys (sk-/pk-/api_/key_ prefixes), stack traces, and `Caused by:` chains. Each pattern is tested independently against known error shapes from real MCP servers.

### What NOT to Redact

- **Do not redact tool names or server names** — the LLM needs these to route retries
- **Do not redact "not found" / "no results"** — these are normal operational responses, not errors
- **Do not redact input validation messages** — "field 'pattern' is required" is exactly what the LLM needs
- **Do not strip all context to a generic "error occurred"** — this makes the LLM retry blindly, wasting tokens and time
- **Do not redact in audit logs** — full detail is needed for incident investigation

---

## Defense-in-Depth Summary

```
Layer                    What It Prevents                          Status
─────────────────────────────────────────────────────────────────────────────
Code Validator           Banned patterns, size limits               Done (WU3)
  + Unicode Normalization  Cyrillic/fullwidth homoglyph bypasses   Done (SR1)
  + Comment Stripping      eval/**/( and // comment evasion        Done (SR1)
  + Whitespace Matching    eval ( whitespace insertion bypass       Done (SR1)
V8 Bootstrap             eval/Function constructor removal          Done (C2)
V8 Isolate               No fs/net/env, fresh per call              Done (Phase 1)
API Boundary             Opaque bindings, arg validation            Done (Phase 1)
Manifest Sanitization    Prompt injection via tool metadata         Done (C1)
Content Size Limits      OOM via oversized responses                Done (WU2, M6)
Process Isolation        OS-level containment, clean env            Done (Phase 3)
Binary Security          Path validation, permission checks         Done (WU1)
Audit Logging            Full trail of all executions               Done (Phase 3)
Header Security          All sensitive headers stripped on HTTP     Done (WU2, SR2)
IPC Length Checks        Protocol desync prevention                 Done (WU6)
  + Configurable Limits    Per-deployment IPC message size          Done (SR3)
Graceful Shutdown        Worker process cleanup on SIGINT           Done (WU4)
Error Redaction          URLs, IPs, paths, creds, stack traces     Done (Phase 4)
Server Groups            Cross-server data flow policies            Done (Phase 4)
Circuit Breakers         Cascade failure prevention                 Done (Phase 4)
Per-Server Timeouts      Hanging server isolation                   Done (Phase 4)
```

Legend: WU = warm-up, C = code review, SR = security review, Phase = implementation phase

---

## Deployment Checklist

Before connecting Forgemax to untrusted or external MCP servers:

- [ ] Use `execution_mode = "child_process"` (OS-level isolation)
- [ ] Set `timeout_secs` per server (30s for security tools, 5s for simple lookups)
- [ ] Enable `circuit_breaker = true` on servers that may be unreliable
- [ ] Set `max_tool_calls` to bound execution cost
- [ ] Review the audit log format and ensure it's being collected
- [ ] Use HTTPS for all HTTP/SSE transport connections (sensitive headers are stripped on plain HTTP)
- [ ] Configure `[groups]` with `isolation = "strict"` for servers that should not share data
- [ ] Set `RUST_LOG=info` to capture connection lifecycle events
- [ ] Protect `forge.toml` with appropriate file permissions — env var expansion (`${VAR}`) means a writable config file could exfiltrate environment variables via server URLs

### What's Built In (no action needed)

- Error redaction: URLs, IPs, paths, credentials, and stack traces are automatically stripped before reaching the LLM
- Header sanitization: Authorization, Cookie, Token, Key, Secret, Credential, and Password headers are stripped on plain HTTP
- Code validation: Unicode homoglyph normalization, JS comment stripping, and whitespace-aware pattern matching catch evasion attempts
- IPC message limits: Configurable per-deployment, defaults to 64 MB
- Manifest sanitization: Downstream tool metadata is cleaned of injection patterns before reaching LLM context
