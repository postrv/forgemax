"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

/**
 * Resolve the downloaded native binary for `name` (`forgemax` or `forgemax-worker`).
 *
 * Layout after postinstall:
 *   vendor/forgemax[.exe]
 *   vendor/forgemax-worker[.exe]
 *
 * The JS files in `bin/` are the npm `bin` entrypoints so that `npm install -g`
 * always creates PATH shims, even before (and independently of) the native
 * download. Older installs that extracted into `bin/` are still accepted.
 */
function resolveNative(name) {
  const isWin = process.platform === "win32";
  const fileName = isWin ? `${name}.exe` : name;
  const pkgRoot = path.join(__dirname, "..");
  const candidates = [
    path.join(pkgRoot, "vendor", fileName),
    path.join(__dirname, fileName),
  ];
  return candidates.find((p) => fs.existsSync(p)) || null;
}

function spawnNative(name) {
  const bin = resolveNative(name);
  if (!bin) {
    console.error(
      `${name} native binary not found. The postinstall download may have failed.\n` +
        `Re-run: npm install -g forgemax\n` +
        `Fallback: cargo install forgemax  (installs both forgemax and forgemax-worker)`
    );
    return 1;
  }

  const result = spawnSync(bin, process.argv.slice(2), {
    stdio: "inherit",
    windowsHide: true,
  });

  if (result.error) {
    console.error(`Failed to start ${name}: ${result.error.message}`);
    return 1;
  }

  if (result.signal) {
    return 1;
  }

  return typeof result.status === "number" ? result.status : 1;
}

module.exports = { resolveNative, spawnNative };
