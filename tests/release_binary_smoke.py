#!/usr/bin/env python3
"""Exercise the packaged gateway and its sibling worker without network access."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    binary_dir = args.bin_dir.resolve()
    suffix = ".exe" if os.name == "nt" else ""
    gateway = binary_dir / f"forgemax{suffix}"
    worker = binary_dir / f"forgemax-worker{suffix}"
    for binary in (gateway, worker):
        if not binary.is_file() or binary.stat().st_size == 0:
            raise RuntimeError(f"Missing release binary: {binary}")

    package = Path(__file__).resolve().parents[1] / "npm" / "package.json"
    expected_version = "forgemax " + json.loads(package.read_text())["version"]
    env = os.environ.copy()
    # Require the normal sibling-worker lookup used by an installed release.
    env.pop("FORGE_WORKER_BIN", None)
    with tempfile.TemporaryDirectory(prefix="forgemax release smoke ") as tmp:
        root = Path(tmp)
        config = root / "forge.toml"
        config.write_text(
            '[sandbox]\nexecution_mode = "child_process"\n'
            'timeout_secs = 10\nmax_heap_mb = 64\n',
            encoding="utf-8",
        )
        script = root / "smoke.js"
        script.write_text("async () => 42\n", encoding="utf-8")
        for arguments, expected, label in (
            ([str(gateway), "--version"], expected_version, "version"),
            ([str(gateway), "run", "--config", str(config), str(script)], 42, "child-process execution"),
        ):
            result = subprocess.run(
                arguments, cwd=root, env=env, text=True, capture_output=True, timeout=30
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Release {label} failed ({result.returncode}):\n"
                    f"{result.stdout}\n{result.stderr}"
                )
            actual = result.stdout.strip() if label == "version" else json.loads(result.stdout)
            if actual != expected:
                raise RuntimeError(f"Release {label}: expected {expected!r}, got {actual!r}")
            print(f"PASS: {label}: {actual}")
    print(f"Verified native gateway and sibling worker in {binary_dir}")


if __name__ == "__main__":
    main()
