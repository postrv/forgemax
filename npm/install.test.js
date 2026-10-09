"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { archiveName, checksumFor, fetch, install, verifyChecksum } = require("./install");
const version = require("./package.json").version;
const platform = "linux-x64";
const body = Buffer.from("verified release fixture");
const digest = crypto.createHash("sha256").update(body).digest("hex");
const filename = archiveName(platform);

for (const marker of ["  ", " *"]) {
  test(`recognizes exact SHA256 filename (${JSON.stringify(marker)})`, () => {
    assert.equal(checksumFor(`${digest.toUpperCase()}${marker}${filename}\r\n`, filename), digest);
  });
}
for (const [label, checksums] of [
  ["missing", ""],
  ["different filename", `${digest}  ${filename}.old\n`],
  ["malformed digest", `invalid  ${filename}\n`],
  ["duplicate entry", `${digest}  ${filename}\n${digest}  ${filename}\n`],
]) {
  test(`rejects ${label} checksums`, () => {
    assert.throws(() => checksumFor(checksums, filename), /exactly one valid SHA256/);
  });
}
test("verifies archive bytes and rejects checksum mismatch", async () => {
  const download = async () => Buffer.from(`${digest}  ${filename}\n`);
  await verifyChecksum(body, platform, download);
  await assert.rejects(verifyChecksum(Buffer.from("different release fixture"), platform, download), /SHA256 mismatch/);
});
test("checksum network failures stop installation", async () => {
  await assert.rejects(verifyChecksum(body, platform, async () => { throw new Error("offline"); }), /offline/);
});
test("rejects unsupported platforms", () => {
  assert.throws(() => archiveName("linux-arm64"), /Unsupported platform/);
});
test("requires HTTPS and bounds redirects before requesting", async () => {
  await assert.rejects(fetch("http://example.invalid/release"), /require HTTPS/);
  await assert.rejects(fetch("https://example.invalid/release", 1024, 6), /Too many/);
});

function fixture(t, { worker = true, outputVersion = version, dotPrefix = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "forgemax installer's "));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "source");
  fs.mkdirSync(source);
  fs.writeFileSync(path.join(source, "forgemax"), `#!/bin/sh\nprintf '%s\\n' 'forgemax ${outputVersion}'\n`);
  fs.writeFileSync(path.join(source, "forge.toml.example"), "release configuration\n");
  if (worker) fs.writeFileSync(path.join(source, "forgemax-worker"), "worker fixture\n");
  const archive = path.join(root, "release.tar.gz");
  const members = ["forgemax", "forge.toml.example", ...(worker ? ["forgemax-worker"] : [])];
  execFileSync("tar", ["-czf", archive, "-C", source, ...(dotPrefix ? ["."] : members)]);
  const bytes = fs.readFileSync(archive);
  const sha = crypto.createHash("sha256").update(bytes).digest("hex");
  const binDir = path.join(root, "bin");
  const download = async (url) => url.endsWith("SHA256SUMS.txt") ? Buffer.from(`${sha}  ${filename}\n`) : bytes;
  return { root, binDir, download };
}
for (const dotPrefix of [false, true]) {
  test(`installs both verified binaries from ${dotPrefix ? "dot-prefixed" : "plain"} archive paths`, { skip: os.platform() === "win32" }, async (t) => {
    const data = fixture(t, { dotPrefix });
    await install({ platformKey: platform, ...data });
    assert.deepEqual(fs.readdirSync(data.binDir).sort(), ["forgemax", "forgemax-worker"]);
    assert.equal(execFileSync(path.join(data.binDir, "forgemax"), ["--version"], { encoding: "utf8" }).trim(), `forgemax ${version}`);
    assert.equal(fs.readdirSync(data.root).some((name) => name.startsWith(".forgemax-install-")), false);
  });
}
for (const [label, options, message] of [
  ["missing worker", { worker: false }, /exactly one forgemax-worker/],
  ["incorrect binary version", { outputVersion: "0.0.0" }, /does not match/],
]) {
  test(`preserves existing installation on ${label}`, { skip: os.platform() === "win32" }, async (t) => {
    const data = fixture(t, options);
    fs.mkdirSync(data.binDir);
    fs.writeFileSync(path.join(data.binDir, "forgemax"), "existing binary");
    await assert.rejects(install({ platformKey: platform, ...data }), message);
    assert.equal(fs.readFileSync(path.join(data.binDir, "forgemax"), "utf8"), "existing binary");
    assert.equal(fs.readdirSync(data.root).some((name) => name.startsWith(".forgemax-install-")), false);
  });
}

test("restores both existing binaries when the worker replacement fails", { skip: os.platform() === "win32" }, async (t) => {
  const data = fixture(t);
  fs.mkdirSync(data.binDir);
  fs.writeFileSync(path.join(data.binDir, "forgemax"), "existing gateway");
  fs.writeFileSync(path.join(data.binDir, "forgemax-worker"), "existing worker");
  const rename = fs.renameSync;
  fs.renameSync = (source, destination) => {
    if (destination === path.join(data.binDir, "forgemax-worker")) throw new Error("worker is busy");
    return rename(source, destination);
  };
  try {
    await assert.rejects(install({ platformKey: platform, ...data }), /worker is busy/);
  } finally {
    fs.renameSync = rename;
  }
  assert.equal(fs.readFileSync(path.join(data.binDir, "forgemax"), "utf8"), "existing gateway");
  assert.equal(fs.readFileSync(path.join(data.binDir, "forgemax-worker"), "utf8"), "existing worker");
  assert.equal(fs.readdirSync(data.root).some((name) => name.startsWith(".forgemax-install-")), false);
});

test("preserves recovery backups if restoration fails", { skip: os.platform() === "win32" }, async (t) => {
  const data = fixture(t);
  fs.mkdirSync(data.binDir);
  fs.writeFileSync(path.join(data.binDir, "forgemax"), "existing gateway");
  fs.writeFileSync(path.join(data.binDir, "forgemax-worker"), "existing worker");
  const rename = fs.renameSync;
  fs.renameSync = (source, destination) => {
    if (destination === path.join(data.binDir, "forgemax-worker") || path.basename(path.dirname(source)) === "previous") {
      throw new Error("destination is busy");
    }
    return rename(source, destination);
  };
  try {
    await assert.rejects(install({ platformKey: platform, ...data }), /rollback incomplete, backups preserved/);
  } finally {
    fs.renameSync = rename;
  }
  const preserved = fs.readdirSync(data.root).filter((name) => name.startsWith(".forgemax-install-"));
  assert.equal(preserved.length, 1);
  assert.equal(fs.readFileSync(path.join(data.root, preserved[0], "previous", "forgemax"), "utf8"), "existing gateway");
  assert.equal(fs.readFileSync(path.join(data.binDir, "forgemax-worker"), "utf8"), "existing worker");
});

test("rejects a non-file binary destination before replacing the gateway", { skip: os.platform() === "win32" }, async (t) => {
  const data = fixture(t);
  fs.mkdirSync(data.binDir);
  fs.writeFileSync(path.join(data.binDir, "forgemax"), "existing gateway");
  fs.mkdirSync(path.join(data.binDir, "forgemax-worker"));
  await assert.rejects(install({ platformKey: platform, ...data }), /must be a regular file/);
  assert.equal(fs.readFileSync(path.join(data.binDir, "forgemax"), "utf8"), "existing gateway");
  assert.equal(fs.readdirSync(data.root).some((name) => name.startsWith(".forgemax-install-")), false);
});
