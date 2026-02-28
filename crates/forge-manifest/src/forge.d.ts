/**
 * Forgemax Code Mode Gateway — TypeScript Definitions
 *
 * These type definitions describe the APIs available inside the V8 sandbox.
 * Code submitted to `execute()` and `search()` runs in this environment.
 */

/** Result of calling a tool on a downstream MCP server. */
type ToolResult = Record<string, unknown>;

/** Result of reading a resource from a downstream MCP server. */
type ResourceResult = Record<string, unknown>;

/** Options for forge.stash.put(). */
interface StashPutOptions {
  /** Time-to-live in seconds. Omit for default TTL. */
  ttl?: number;
}

/** A single call descriptor for forge.parallel(). */
interface ParallelCall {
  /** The async function to execute. */
  fn: () => Promise<unknown>;
}

/** Options for forge.parallel(). */
interface ParallelOptions {
  /** Maximum concurrent calls (capped at server-configured limit). */
  concurrency?: number;
}

/** Session-scoped key-value store. */
interface ForgeStash {
  /**
   * Store a value.
   * @example await forge.stash.put("cache-key", {data: [1,2,3]}, {ttl: 3600})
   */
  put(key: string, value: unknown, options?: StashPutOptions): Promise<{ ok: boolean }>;

  /**
   * Retrieve a value. Returns null if not found or expired.
   * @example const val = await forge.stash.get("cache-key")
   */
  get(key: string): Promise<unknown | null>;

  /**
   * Delete a value. Returns whether the key existed.
   * @example await forge.stash.delete("cache-key")
   */
  delete(key: string): Promise<{ deleted: boolean }>;

  /**
   * List all keys in the current scope.
   * @example const keys = await forge.stash.keys()
   */
  keys(): Promise<string[]>;
}

/** The forge global API object available in the sandbox. */
interface Forge {
  /**
   * Call a tool on a downstream MCP server.
   * @param server - Server name (e.g., "narsil")
   * @param tool - Tool name (e.g., "find_symbols")
   * @param args - Tool arguments object
   * @example const result = await forge.callTool("narsil", "find_symbols", { pattern: "main" })
   */
  callTool(server: string, tool: string, args?: Record<string, unknown>): Promise<ToolResult>;

  /**
   * Get a server proxy for fluent tool invocation.
   * Access tools via server.category.tool(args).
   * @param name - Server name
   * @example const result = await forge.server("narsil").ast.parse({ file: "main.rs" })
   */
  server(name: string): Record<string, Record<string, (args?: Record<string, unknown>) => Promise<ToolResult>>>;

  /**
   * Read a resource from a downstream MCP server.
   * @param server - Server name
   * @param uri - Resource URI
   * @example const content = await forge.readResource("postgres", "file:///logs/app.log")
   */
  readResource(server: string, uri: string): Promise<ResourceResult>;

  /** Session-scoped key-value store. */
  stash: ForgeStash;

  /**
   * Execute multiple async calls with bounded concurrency.
   * @param calls - Array of call descriptors
   * @param options - Concurrency options
   * @example
   * const results = await forge.parallel(
   *   [{ fn: () => forge.callTool("s", "t1", {}) },
   *    { fn: () => forge.callTool("s", "t2", {}) }],
   *   { concurrency: 4 }
   * )
   */
  parallel(calls: ParallelCall[], options?: ParallelOptions): Promise<unknown[]>;
}

/** Tool definition in the capability manifest. */
interface ManifestTool {
  name: string;
  description: string;
  input_schema?: Record<string, unknown>;
}

/** Category of tools within a server. */
interface ManifestCategory {
  name: string;
  description: string;
  tools: ManifestTool[];
}

/** A connected MCP server in the manifest. */
interface ManifestServer {
  name: string;
  description: string;
  /** Categories keyed by name. Use Object.entries() to iterate. */
  categories: Record<string, ManifestCategory>;
}

/** The capability manifest — available as globalThis.manifest in search(). */
interface Manifest {
  servers: ManifestServer[];
}

declare const forge: Forge;
declare const manifest: Manifest;
