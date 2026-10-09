#!/usr/bin/env node
"use strict";

const path = require("path");
const { spawnSync } = require("child_process");

const executable = process.platform === "win32" ? "forgemax.exe" : "forgemax";
const result = spawnSync(path.join(__dirname, "native", executable), process.argv.slice(2), {
  stdio: "inherit",
});
if (result.error) {
  console.error(`Unable to start forgemax: ${result.error.message}`);
  console.error("Reinstall forgemax with npm lifecycle scripts enabled to download its binaries.");
  process.exitCode = 1;
} else if (result.signal) {
  process.kill(process.pid, result.signal);
} else {
  process.exitCode = result.status === null ? 1 : result.status;
}
