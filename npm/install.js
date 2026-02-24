#!/usr/bin/env node

"use strict";

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const os = require("os");
const zlib = require("zlib");

const PACKAGE = require("./package.json");
const VERSION = PACKAGE.version;
const REPO = "postrv/forgemax";
const BIN_DIR = path.join(__dirname, "bin");

// Platform → release archive mapping
const PLATFORM_MAP = {
  "darwin-x64": "macos-x86_64",
  "darwin-arm64": "macos-aarch64",
  "linux-x64": "linux-x86_64",
  "win32-x64": "windows-x86_64",
};

function getPlatformKey() {
  const platform = os.platform();
  const arch = os.arch();
  return `${platform}-${arch}`;
}

function getDownloadUrl(platformKey) {
  const suffix = PLATFORM_MAP[platformKey];
  if (!suffix) {
    throw new Error(
      `Unsupported platform: ${platformKey}. ` +
        `Supported: ${Object.keys(PLATFORM_MAP).join(", ")}`
    );
  }
  const ext = platformKey.startsWith("win32") ? "zip" : "tar.gz";
  return `https://github.com/${REPO}/releases/download/v${VERSION}/forgemax-v${VERSION}-${suffix}.${ext}`;
}

function fetch(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("https") ? https : http;
    client
      .get(url, { headers: { "User-Agent": "forgemax-npm-installer" } }, (res) => {
        // Follow redirects
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return fetch(res.headers.location).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

function extractTarGz(buffer, destDir) {
  // Use tar command for extraction (available on macOS/Linux)
  const tmpFile = path.join(os.tmpdir(), `forgemax-${Date.now()}.tar.gz`);
  fs.writeFileSync(tmpFile, buffer);
  try {
    execSync(`tar xzf "${tmpFile}" -C "${destDir}"`, { stdio: "pipe" });
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

function extractZip(buffer, destDir) {
  const tmpFile = path.join(os.tmpdir(), `forgemax-${Date.now()}.zip`);
  fs.writeFileSync(tmpFile, buffer);
  try {
    if (os.platform() === "win32") {
      execSync(
        `powershell -Command "Expand-Archive -Path '${tmpFile}' -DestinationPath '${destDir}' -Force"`,
        { stdio: "pipe" }
      );
    } else {
      execSync(`unzip -o "${tmpFile}" -d "${destDir}"`, { stdio: "pipe" });
    }
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

async function install() {
  const platformKey = getPlatformKey();
  const url = getDownloadUrl(platformKey);
  const isWindows = platformKey.startsWith("win32");

  console.log(`Installing forgemax v${VERSION} for ${platformKey}...`);
  console.log(`Downloading from ${url}`);

  const buffer = await fetch(url);

  // Ensure bin directory exists
  fs.mkdirSync(BIN_DIR, { recursive: true });

  // Extract archive
  if (isWindows) {
    extractZip(buffer, BIN_DIR);
  } else {
    extractTarGz(buffer, BIN_DIR);
  }

  // Set executable permissions on Unix
  if (!isWindows) {
    const binaries = ["forgemax", "forgemax-worker"];
    for (const bin of binaries) {
      const binPath = path.join(BIN_DIR, bin);
      if (fs.existsSync(binPath)) {
        fs.chmodSync(binPath, 0o755);
      }
    }
  }

  // Verify installation
  const binaryName = isWindows ? "forgemax.exe" : "forgemax";
  const binaryPath = path.join(BIN_DIR, binaryName);

  if (!fs.existsSync(binaryPath)) {
    throw new Error(`Binary not found after extraction: ${binaryPath}`);
  }

  try {
    const version = execSync(`"${binaryPath}" --version`, {
      encoding: "utf-8",
      timeout: 10000,
    }).trim();
    console.log(`Installed: ${version}`);
  } catch {
    console.log("Installed forgemax (version check skipped)");
  }

  // Verify worker binary
  const workerName = isWindows ? "forgemax-worker.exe" : "forgemax-worker";
  const workerPath = path.join(BIN_DIR, workerName);
  if (fs.existsSync(workerPath)) {
    console.log(`Worker binary: ${workerPath}`);
  } else {
    console.warn("Warning: forgemax-worker not found in archive");
  }

  console.log(`
Quick start:
  1. Copy forge.toml.example to forge.toml and configure your tokens
  2. Add to your MCP client config:
     {
       "mcpServers": {
         "forge": {
           "command": "forgemax",
           "args": []
         }
       }
     }
`);
}

install().catch((err) => {
  console.error(`Failed to install forgemax: ${err.message}`);
  console.error(
    "\nFallback: install from source with `cargo install forge-cli`"
  );
  process.exit(1);
});
