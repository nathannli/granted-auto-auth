from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SIDECAR = ROOT / "scripts/granted_auto_auth.py"
LOCKFILE = ROOT / "scripts/granted_auto_auth.py.lock"


class LockedRuntimeTests(unittest.TestCase):
    def copy_runtime(self, directory: Path, *, include_lock: bool = True) -> Path:
        sidecar = directory / SIDECAR.name
        shutil.copy2(SIDECAR, sidecar)
        if include_lock:
            shutil.copy2(LOCKFILE, directory / LOCKFILE.name)
        return sidecar

    def test_runtime_is_locked_and_offline(self) -> None:
        shebang = SIDECAR.read_text().splitlines()[0]
        self.assertEqual(shebang, "#!/usr/bin/env -S uv run --script --locked --offline")

    def test_missing_lock_fails_before_script_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            sidecar = self.copy_runtime(directory, include_lock=False)
            home = directory / "home"
            home.mkdir()
            environment = os.environ.copy()
            environment.update(HOME=str(home), UV_CACHE_DIR=str(directory / "cache"), UV_PYTHON_PREFERENCE="only-system")
            result = subprocess.run(
                [str(sidecar), "https://oidc.us-east-1.amazonaws.com/authorize"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((home / ".config/granted-auto-auth").exists())

    def test_empty_package_cache_fails_before_secret_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            sidecar = self.copy_runtime(directory)
            home = directory / "home"
            home.mkdir()
            environment = os.environ.copy()
            environment.update(HOME=str(home), UV_CACHE_DIR=str(directory / "cache"), UV_PYTHON_PREFERENCE="only-system")
            result = subprocess.run(
                [str(sidecar), "https://oidc.us-east-1.amazonaws.com/authorize"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cache", result.stderr.lower())
            self.assertIn("network connectivity is disabled", result.stderr.lower())
            self.assertFalse((home / ".config/granted-auto-auth").exists())

    def test_lock_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            sidecar = self.copy_runtime(directory)
            sidecar.write_text(sidecar.read_text().replace('"pyotp==2.10.0"', '"pyotp==2.9.0"'))
            result = subprocess.run(
                ["uv", "lock", "--check", "--offline", "--script", str(sidecar)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
