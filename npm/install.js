#!/usr/bin/env node

"use strict";

const https = require("https");
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const os = require("os");
const zlib = require("zlib");

const PACKAGE = require("./package.json");
const VERSION = PACKAGE.version;
const REPO = "postrv/forgemax";
const VENDOR_DIR = path.join(__dirname, "vendor");

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

function flattenExtractedVendor(destDir, isWindows) {
  const expected = isWindows ? "forgemax.exe" : "forgemax";
  if (fs.existsSync(path.join(destDir, expected))) {
    return;
  }
  const entries = fs.readdirSync(destDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const nested = path.join(destDir, entry.name, expected);
    if (!fs.existsSync(nested)) {
      continue;
    }
    for (const file of fs.readdirSync(path.join(destDir, entry.name))) {
      const from = path.join(destDir, entry.name, file);
      const to = path.join(destDir, file);
      fs.renameSync(from, to);
    }
    return;
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

async function verifyChecksum(buffer, platformKey) {
  const suffix = PLATFORM_MAP[platformKey];
  const ext = platformKey.startsWith("win32") ? "zip" : "tar.gz";
  const filename = `forgemax-v${VERSION}-${suffix}.${ext}`;
  const checksumUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/SHA256SUMS.txt`;

  try {
    const checksumData = await fetch(checksumUrl);
    const lines = checksumData.toString("utf-8").split("\n");
    const line = lines.find((l) => l.includes(filename));
    if (!line) {
      console.warn("Checksum not found for platform — skipping verification");
      return;
    }
    const expected = line.split(/\s+/)[0];
    const actual = crypto.createHash("sha256").update(buffer).digest("hex");
    if (expected !== actual) {
      throw new Error(
        `SHA256 mismatch! Expected: ${expected}, got: ${actual}. ` +
          `The downloaded binary may be corrupted or tampered with.`
      );
    }
    console.log("SHA256 verified");
  } catch (err) {
    if (err.message.includes("SHA256 mismatch")) throw err;
    console.warn(`Could not verify checksum: ${err.message}`);
  }
}

async function install() {
  const platformKey = getPlatformKey();
  const url = getDownloadUrl(platformKey);
  const isWindows = platformKey.startsWith("win32");

  console.log(`Installing forgemax v${VERSION} for ${platformKey}...`);
  console.log(`Downloading from ${url}`);

  const buffer = await fetch(url);

  await verifyChecksum(buffer, platformKey);

  // Native binaries live in vendor/ so npm `bin` JS shims in bin/ are never overwritten.
  fs.mkdirSync(VENDOR_DIR, { recursive: true });

  if (isWindows) {
    extractZip(buffer, VENDOR_DIR);
  } else {
    extractTarGz(buffer, VENDOR_DIR);
  }

  flattenExtractedVendor(VENDOR_DIR, isWindows);

  if (!isWindows) {
    const binaries = ["forgemax", "forgemax-worker"];
    for (const bin of binaries) {
      const binPath = path.join(VENDOR_DIR, bin);
      if (fs.existsSync(binPath)) {
        fs.chmodSync(binPath, 0o755);
      }
    }
  }

  const binaryName = isWindows ? "forgemax.exe" : "forgemax";
  const binaryPath = path.join(VENDOR_DIR, binaryName);

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

  const workerName = isWindows ? "forgemax-worker.exe" : "forgemax-worker";
  const workerPath = path.join(VENDOR_DIR, workerName);
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
         "forgemax": {
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
    "\nFallback: install from source with `cargo install forgemax`"
  );
  process.exit(1);
});
