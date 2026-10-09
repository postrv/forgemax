"""Offline end-to-end installer checks with harmless release fixtures."""
import hashlib
import io
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[2] / "install.sh"
VERSION = "1.2.3"
PLATFORM = {"Darwin": "macos", "Linux": "linux"}[platform.system()] + "-" + {
    "arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"
}[platform.machine()]
FILENAME = f"forgemax-v{VERSION}-{PLATFORM}.tar.gz"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="forgemax installer's ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "forgemax").write_text("previous version")
        mocks = self.root / "mocks"
        mocks.mkdir()
        curl = mocks / "curl"
        curl.write_text("""#!/usr/bin/env python3
import os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
url = next(a for a in args if a.startswith('https://'))
dest = args[args.index('-o') + 1]
root = Path(os.environ['FIXTURE_DIR'])
if url.endswith('/releases/latest'):
    Path(dest).write_text('{"tag_name":"v1.2.3"}')
elif url.endswith('SHA256SUMS.txt'):
    source = root / 'SHA256SUMS.txt'
    if not source.exists(): sys.exit(22)
    shutil.copyfile(source, dest)
else:
    shutil.copyfile(root / 'release.tar.gz', dest)
""")
        curl.chmod(0o755)
        move = mocks / "mv"
        move.write_text("""#!/usr/bin/env python3
import os, sys
from pathlib import Path
source, destination = map(Path, sys.argv[-2:])
if (os.environ.get('FAIL_WORKER_PUBLISH') == '1'
        and destination == Path(os.environ['FORGEMAX_INSTALL_DIR']) / 'forgemax-worker'
        and source.parent.name != 'previous'):
    sys.exit(1)
os.execv('/bin/mv', ['mv', *sys.argv[1:]])
""")
        move.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{mocks}:{os.environ['PATH']}",
                        FIXTURE_DIR=str(self.root), FORGEMAX_VERSION=VERSION,
                        FORGEMAX_INSTALL_DIR=str(self.bin), TMPDIR=str(self.root))

    def release(self, worker=True, dot_prefix=False, output_version=VERSION):
        archive = self.root / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            files = {"forgemax": f"#!/bin/sh\nprintf '%s\\n' 'forgemax {output_version}'\n",
                     "forge.toml.example": "release configuration\n"}
            if worker:
                files["forgemax-worker"] = "worker fixture\n"
            for name, contents in files.items():
                encoded = contents.encode()
                member = tarfile.TarInfo(("./" if dot_prefix else "") + name)
                member.size = len(encoded)
                member.mode = 0o755
                tar.addfile(member, io.BytesIO(encoded))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / "SHA256SUMS.txt").write_text(f"{digest}  {FILENAME}\n")
        return digest

    def run_installer(self, succeeds=False):
        result = subprocess.run(["bash", str(INSTALLER)], env=self.env, text=True,
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)
        self.assertFalse(any(p.name.startswith("tmp.") for p in self.root.iterdir()))
        if not succeeds:
            self.assertEqual((self.bin / "forgemax").read_text(), "previous version")
        return result

    def test_valid_release(self):
        self.release()
        self.run_installer(succeeds=True)
        self.assertEqual(sorted(p.name for p in self.bin.iterdir()), ["forgemax", "forgemax-worker"])

    def test_dot_prefixed_archive_and_latest_version(self):
        self.release(dot_prefix=True)
        del self.env["FORGEMAX_VERSION"]
        self.run_installer(succeeds=True)

    def test_unavailable_checksums(self):
        self.release()
        (self.root / "SHA256SUMS.txt").unlink()
        self.run_installer()

    def test_invalid_checksums(self):
        digest = self.release()
        for contents in ["", f"{digest}  {FILENAME}.old\n", f"invalid  {FILENAME}\n",
                         f"{'0' * 64}  {FILENAME}\n", f"{digest}  {FILENAME}\n{digest}  {FILENAME}\n"]:
            with self.subTest(contents=contents):
                (self.root / "SHA256SUMS.txt").write_text(contents)
                self.run_installer()

    def test_missing_worker(self):
        self.release(worker=False)
        self.run_installer()

    def test_wrong_binary_version(self):
        self.release(output_version="0.0.0")
        self.run_installer()

    def test_invalid_version(self):
        self.env["FORGEMAX_VERSION"] = "latest"
        self.run_installer()

    def test_worker_publication_failure_restores_existing_pair(self):
        self.release()
        (self.bin / "forgemax-worker").write_text("previous worker")
        self.env["FAIL_WORKER_PUBLISH"] = "1"
        self.run_installer()
        self.assertEqual((self.bin / "forgemax-worker").read_text(), "previous worker")

    def test_nonregular_destination_preserves_installation(self):
        self.release()
        (self.bin / "forgemax-worker").mkdir()
        self.run_installer()


if __name__ == "__main__":
    unittest.main()
