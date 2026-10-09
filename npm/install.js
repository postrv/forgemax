#!/usr/bin/env node
"use strict";

const https = require("https");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const os = require("os");

const VERSION = require("./package.json").version;
const REPO = "postrv/forgemax";
const BIN_DIR = path.join(__dirname, "native");
const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const PLATFORM_MAP = {
  "darwin-x64": "macos-x86_64",
  "darwin-arm64": "macos-aarch64",
  "linux-x64": "linux-x86_64",
  "win32-x64": "windows-x86_64",
};

function archiveName(platformKey) {
  const suffix = PLATFORM_MAP[platformKey];
  if (!suffix) {
    throw new Error(`Unsupported platform: ${platformKey}. Supported: ${Object.keys(PLATFORM_MAP).join(", ")}`);
  }
  const ext = platformKey.startsWith("win32") ? "zip" : "tar.gz";
  return `forgemax-v${VERSION}-${suffix}.${ext}`;
}

function getDownloadUrl(platformKey) {
  return `https://github.com/${REPO}/releases/download/v${VERSION}/${archiveName(platformKey)}`;
}

function fetch(url, maxBytes = MAX_ARCHIVE_BYTES, redirects = 0) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") {
      throw new Error("Installer downloads require HTTPS");
    }
    if (redirects > 5) throw new Error("Too many download redirects");
    const request = https.get(parsed, {
      headers: { "User-Agent": "forgemax-npm-installer" },
    }, (res) => {
      res.on("error", reject);
      res.on("aborted", () => reject(new Error("Download interrupted")));
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        let next;
        try {
          next = new URL(res.headers.location, parsed);
        } catch (err) {
          reject(err);
          return;
        }
        fetch(next, maxBytes, redirects + 1).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode} while downloading release assets`));
        return;
      }
      const chunks = [];
      let size = 0;
      res.on("data", (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          const err = new Error("Download exceeds size limit");
          reject(err);
          res.destroy(err);
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => resolve(Buffer.concat(chunks)));
    });
    request.setTimeout(30000, () => request.destroy(new Error("Download timed out")));
    request.on("error", reject);
  });
}

function checksumFor(checksumData, filename) {
  const matches = checksumData.toString("utf8").split(/\r?\n/)
    .map((line) => /^([0-9a-fA-F]{64})[ \t]+\*?([^\r\n]+)$/.exec(line))
    .filter((match) => match && match[2] === filename);
  if (matches.length !== 1) {
    throw new Error(`Expected exactly one valid SHA256 checksum for ${filename}`);
  }
  return matches[0][1].toLowerCase();
}

async function verifyChecksum(buffer, platformKey, download = fetch) {
  const filename = archiveName(platformKey);
  const checksumUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/SHA256SUMS.txt`;
  // Verification is mandatory, including for older releases and network failures.
  const expected = checksumFor(await download(checksumUrl, 1024 * 1024), filename);
  const actual = crypto.createHash("sha256").update(buffer).digest("hex");
  if (expected !== actual) throw new Error(`SHA256 mismatch for ${filename}`);
  console.log("SHA256 verified");
}

function extractTarGz(archivePath, destDir) {
  const entries = execFileSync("tar", ["-tzf", archivePath], {
    encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 30000,
  }).trimEnd().split("\n");
  for (const name of ["forgemax", "forgemax-worker"]) {
    const members = entries.filter((entry) => entry === name || entry === `./${name}`);
    if (members.length !== 1) throw new Error(`Archive must contain exactly one ${name}`);
    // Write contents to a fixed file ourselves, without applying archive paths,
    // ownership, links, or permissions to the filesystem.
    const contents = execFileSync("tar", ["-xOzf", archivePath, members[0]], {
      maxBuffer: MAX_ARCHIVE_BYTES, timeout: 30000,
    });
    if (contents.length === 0) throw new Error(`Empty binary: ${name}`);
    fs.writeFileSync(path.join(destDir, name), contents, { flag: "wx", mode: 0o755 });
  }
}

function extractZip(archivePath, destDir) {
  // A fixed PowerShell program receives paths as environment data. No user or
  // filesystem paths are interpolated into a command string.
  const script = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($env:FORGEMAX_ARCHIVE_PATH)
try {
  foreach ($name in @('forgemax.exe', 'forgemax-worker.exe')) {
    $entries = @($zip.Entries | Where-Object { $_.FullName -ceq $name -or $_.FullName -ceq "./$name" })
    if ($entries.Count -ne 1 -or $entries[0].Length -eq 0) { throw "Archive must contain one nonempty $name" }
    if ($entries[0].Length -gt 268435456) { throw "Binary exceeds size limit" }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], (Join-Path $env:FORGEMAX_STAGE_DIR $name))
  }
} finally { $zip.Dispose() }
`;
  execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    stdio: "pipe", timeout: 30000,
    env: { ...process.env, FORGEMAX_ARCHIVE_PATH: archivePath, FORGEMAX_STAGE_DIR: destDir },
  });
}

async function install({ platformKey = `${os.platform()}-${os.arch()}`, binDir = BIN_DIR, download = fetch } = {}) {
  const url = getDownloadUrl(platformKey);
  const isWindows = platformKey.startsWith("win32");
  console.log(`Installing forgemax v${VERSION} for ${platformKey}...`);
  const buffer = await download(url);
  await verifyChecksum(buffer, platformKey, download);

  // Stage beside the destination for same-filesystem renames, and clean up on
  // every failure. Existing installations survive verification/extraction errors.
  fs.mkdirSync(path.dirname(binDir), { recursive: true });
  const tempDir = fs.mkdtempSync(path.join(path.dirname(binDir), ".forgemax-install-"));
  const names = isWindows ? ["forgemax.exe", "forgemax-worker.exe"] : ["forgemax", "forgemax-worker"];
  let preserveTempDir = false;
  try {
    const archivePath = path.join(tempDir, isWindows ? "release.zip" : "release.tar.gz");
    fs.writeFileSync(archivePath, buffer, { flag: "wx", mode: 0o600 });
    if (isWindows) extractZip(archivePath, tempDir);
    else extractTarGz(archivePath, tempDir);

    const version = execFileSync(path.join(tempDir, names[0]), ["--version"], {
      encoding: "utf8", timeout: 10000,
    }).trim();
    if (version !== `forgemax ${VERSION}`) throw new Error("Downloaded binary version does not match package version");

    fs.mkdirSync(binDir, { recursive: true });
    if (!fs.lstatSync(binDir).isDirectory()) throw new Error("Binary destination must be a directory, not a link");
    const backupDir = path.join(tempDir, "previous");
    fs.mkdirSync(backupDir);
    const originals = new Set();
    // Back up both files before replacing either one. A busy Windows worker
    // or another publication error must not leave a mixed-version pair.
    for (const name of names) {
      const destination = path.join(binDir, name);
      const existing = fs.lstatSync(destination, { throwIfNoEntry: false });
      if (existing && !existing.isFile()) throw new Error(`Existing ${name} must be a regular file`);
      if (existing) {
        fs.copyFileSync(destination, path.join(backupDir, name), fs.constants.COPYFILE_EXCL);
        originals.add(name);
      }
    }
    const installed = [];
    try {
      for (const name of names) {
        fs.renameSync(path.join(tempDir, name), path.join(binDir, name));
        installed.push(name);
      }
    } catch (error) {
      const rollbackErrors = [];
      for (const name of installed.reverse()) {
        try {
          if (originals.has(name)) fs.renameSync(path.join(backupDir, name), path.join(binDir, name));
          else fs.unlinkSync(path.join(binDir, name));
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError.message);
        }
      }
      if (rollbackErrors.length) {
        preserveTempDir = true;
        throw new Error(`${error.message}; rollback incomplete, backups preserved at ${backupDir}: ${rollbackErrors.join("; ")}`);
      }
      throw error;
    }
    console.log(`Installed: ${version}`);
  } finally {
    if (!preserveTempDir) fs.rmSync(tempDir, { recursive: true, force: true });
  }
  console.log("Copy forge.toml.example to forge.toml, configure your tokens, and add forgemax to your MCP client.");
}

module.exports = { archiveName, checksumFor, extractTarGz, fetch, getDownloadUrl, install, verifyChecksum };
if (require.main === module) {
  install().catch((err) => {
    console.error(`Failed to install forgemax: ${err.message}`);
    console.error("Fallback: install from source with `cargo install --locked forgemax forge-sandbox-worker`");
    process.exitCode = 1;
  });
}
