"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync, spawnSync } = require("child_process");
const version = require("./package.json").version;

test("packed npm package creates a working launcher before postinstall", { skip: process.platform === "win32" }, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "forgemax npm package "));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const npmOptions = { encoding: "utf8", timeout: 30000, env: { ...process.env, npm_config_update_notifier: "false" } };
  const [packed] = JSON.parse(execFileSync("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", root], {
    ...npmOptions, cwd: __dirname,
  }));
  const files = packed.files.map((file) => file.path);
  assert.ok(files.includes("cli.js"), "launcher must be in the package before lifecycle scripts run");
  assert.ok(files.includes("install.js"));
  assert.ok(!files.some((name) => name.startsWith("native/") || name.endsWith(".test.js")));
  const destination = path.join(root, "installed");
  execFileSync("npm", ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", destination, path.join(root, packed.filename)], npmOptions);
  const nativeDir = path.join(destination, "node_modules", "forgemax", "native");
  fs.mkdirSync(nativeDir);
  fs.writeFileSync(path.join(nativeDir, "forgemax"), `#!/bin/sh\nif [ "$1" = "--version" ]; then\n  printf '%s\\n' 'forgemax ${version}'\nelse\n  printf '%s\\n' "$@"\n  exit 23\nfi\n`, { mode: 0o755 });
  const launcher = path.join(destination, "node_modules", ".bin", "forgemax");
  assert.equal(execFileSync(launcher, ["--version"], { encoding: "utf8" }).trim(), `forgemax ${version}`);
  const result = spawnSync(launcher, ["--message", "two words"], { encoding: "utf8" });
  assert.equal(result.status, 23);
  assert.equal(result.stdout, "--message\ntwo words\n");
});
