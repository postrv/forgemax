# Forgemax v0.3.1 Comprehensive Test Prompt

Paste everything below the line into a fresh Claude Code session that has forgemax configured as an MCP server.

---

I want to run a comprehensive test of the forgemax MCP gateway. Please execute each test below **in order**, reporting PASS/FAIL for each. Use the forge `search()` and `execute()` tools. Do NOT skip any test. After all tests, give me a summary table.

## Test 1 — Basic Search (manifest discovery)

Use the forge `search()` tool to discover available servers and tools. Report how many servers and total tools are available.

**Expected:** Returns a structured manifest with server names, categories, and tool schemas.

## Test 2 — Basic Execute (tool call via forge.callTool)

Use `execute()` to run:
```js
async () => {
  const result = await forge.callTool('narsil', 'list_repos', {});
  return result;
}
```

**Expected:** Returns a list of indexed repositories.

## Test 3 — Server Proxy API (forge.server fluent syntax)

Use `execute()` to run:
```js
async () => {
  const s = forge.server('narsil');
  const result = await s.general.find_symbols({ repo: 'Forge', pattern: 'main', symbol_type: 'function' });
  return result;
}
```

**Expected:** Returns symbol search results using the fluent proxy API.

## Test 4 — Structured Error: Wrong Server Name (fuzzy matching)

Use `execute()` to run:
```js
async () => {
  const result = await forge.callTool('narsill', 'list_repos', {});
  return result;
}
```

**Expected:** Returns a structured JSON error (not a JS exception) with `"code": "SERVER_NOT_FOUND"` and a `suggested_fix` field suggesting "narsil".

## Test 5 — Structured Error: Wrong Tool Name (fuzzy matching)

Use `execute()` to run:
```js
async () => {
  const result = await forge.callTool('narsil', 'find_symbls', { pattern: 'main' });
  return result;
}
```

**Expected:** Returns a structured JSON error with `"code": "TOOL_NOT_FOUND"` and a `suggested_fix` like "find_symbols".

## Test 6 — Stash: Put, Get, Keys, Delete lifecycle

Use `execute()` to run:
```js
async () => {
  await forge.stash.put('test-key-v031', { version: '0.3.1', ts: Date.now() }, { ttl: 60 });
  const val = await forge.stash.get('test-key-v031');
  const keys = await forge.stash.keys();
  const del = await forge.stash.delete('test-key-v031');
  const afterDelete = await forge.stash.get('test-key-v031');
  return { stored: val, keys, deleted: del, afterDelete };
}
```

**Expected:** `stored` contains the object we put. `keys` includes `"test-key-v031"`. `deleted.deleted` is true. `afterDelete` is null.

## Test 7 — Stash Persistence Across Executions

First call:
```js
async () => {
  await forge.stash.put('cross-exec', 'hello from call 1', { ttl: 120 });
  return 'stored';
}
```

Second call (separate execute):
```js
async () => {
  const val = await forge.stash.get('cross-exec');
  return { retrieved: val };
}
```

**Expected:** Second call retrieves `"hello from call 1"` — stash persists across executions.

## Test 8 — Parallel Execution (forge.parallel)

Use `execute()` to run:
```js
async () => {
  const out = await forge.parallel([
    { fn: () => forge.callTool('narsil', 'list_repos', {}) },
    { fn: () => forge.callTool('narsil', 'get_index_status', { repo: 'Forge' }) },
  ], { concurrency: 2 });
  return out.results.map(r => typeof r === 'object' ? 'ok' : 'fail');
}
```

**Expected:** Both calls return results concurrently. `out.results` contains the two results. Output is `["ok", "ok"]` or similar. Both bare functions `() => ...` and `{fn: () => ...}` objects are accepted.

## Test 9 — AST Validator: Block eval()

Use `execute()` to run:
```js
async () => {
  eval('1+1');
  return 'should not reach here';
}
```

**Expected:** Rejected BEFORE execution with an error mentioning banned pattern or `eval`.

## Test 10 — AST Validator: Block import()

Use `execute()` to run:
```js
async () => {
  const fs = await import('fs');
  return fs.readFileSync('/etc/passwd', 'utf8');
}
```

**Expected:** Rejected with an error mentioning dynamic import or banned pattern.

## Test 11 — AST Validator: Block require()

Use `execute()` to run:
```js
async () => {
  const cp = require('child_process');
  return cp.execSync('whoami').toString();
}
```

**Expected:** Rejected by the AST validator with banned pattern error mentioning `require`.

## Test 12 — AST Alias Detection: eval alias (v0.3.1 NEW)

Use `execute()` to run:
```js
async () => {
  const e = eval;
  return e('1+1');
}
```

**Expected:** Rejected by the AST validator. The alias `const e = eval; e(...)` should be caught.

## Test 13 — AST Alias Detection: Function constructor alias (v0.3.1 NEW)

Use `execute()` to run:
```js
async () => {
  const F = Function;
  return F('return 42')();
}
```

**Expected:** Rejected — `Function` aliased to `F` and called.

## Test 14 — AST Alias Detection: Multi-hop alias (v0.3.1 NEW)

Use `execute()` to run:
```js
async () => {
  const a = eval;
  const b = a;
  return b('1+1');
}
```

**Expected:** Rejected — multi-hop alias chain `eval → a → b` detected.

## Test 15 — AST Alias Detection: Safe code NOT blocked (no false positives)

Use `execute()` to run:
```js
async () => {
  const e = 'eval';
  const arr = [1, 2, 3];
  const m = arr.map;
  return { e, mapped: m.call(arr, x => x * 2) };
}
```

**Expected:** Executes successfully. String `'eval'` and `arr.map` alias should NOT trigger the validator.

## Test 16 — URI Scheme Validation (v0.3.1 NEW)

Use `execute()` to run:
```js
async () => {
  const result = await forge.readResource('narsil', 'javascript:alert(1)');
  return result;
}
```

**Expected:** Rejected with an error about blocked URI scheme.

## Test 17 — URI Scheme: data: blocked

Use `execute()` to run:
```js
async () => {
  const result = await forge.readResource('narsil', 'data:text/html,<script>alert(1)</script>');
  return result;
}
```

**Expected:** Rejected — `data:` scheme is blocked.

## Test 18 — Timeout Handling

Use `execute()` to run:
```js
async () => {
  while (true) {} // infinite loop
  return 'unreachable';
}
```

**Expected:** Returns a timeout error (not a hang). Should complete within the configured timeout (typically 5-30 seconds).

## Test 19 — JS Error Handling (structured)

Use `execute()` to run:
```js
async () => {
  const obj = null;
  return obj.property;
}
```

**Expected:** Returns a structured error with the JS error message (TypeError: Cannot read properties of null).

## Test 20 — Output Size Limit

Use `execute()` to run:
```js
async () => {
  return 'x'.repeat(10_000_000);
}
```

**Expected:** Either returns the result or returns an error about output size limits. Should NOT crash the server.

## Test 21 — No Filesystem Access

Use `execute()` to run:
```js
async () => {
  return Deno.readTextFileSync('/etc/passwd');
}
```

**Expected:** Rejected by AST validator (Deno access blocked) or fails at runtime with no access to Deno APIs.

## Test 22 — No Environment Access

Use `execute()` to run:
```js
async () => {
  return Deno.env.get('HOME');
}
```

**Expected:** Rejected by AST validator or runtime error. No env access from sandbox.

## Test 23 — Resource Reading (valid)

Use `execute()` to run (adjust repo name if needed):
```js
async () => {
  // Try reading a resource — this may or may not be supported by the downstream server
  // The point is to verify the readResource API works without crashing
  try {
    const result = await forge.readResource('narsil', 'file:///README.md');
    return { success: true, type: typeof result };
  } catch (e) {
    return { success: false, error: e.message || String(e) };
  }
}
```

**Expected:** Either succeeds with resource content or returns a structured error. Should NOT crash.

## Test 24 — Manifest contains TypeScript definitions

Use the `search()` tool. Check that the server instructions include TypeScript type definitions (interface Forge, ForgeStash, callTool, readResource, etc.).

**Expected:** The search result or server instructions contain `interface Forge` and `forge.stash` type definitions.

## Test 25 — Multiple sequential executions (worker reuse)

Run three separate `execute()` calls in sequence:

Call 1: `async () => { return 'first'; }`
Call 2: `async () => { return 'second'; }`
Call 3: `async () => { return 'third'; }`

**Expected:** All three return their respective strings. No state leakage between calls. Worker pool handles sequential requests.

---

## Summary

After running all 25 tests, provide a table:

| # | Test | Result | Notes |
|---|------|--------|-------|
| 1 | Basic Search | PASS/FAIL | ... |
| ... | ... | ... | ... |

And list any failures with details.
