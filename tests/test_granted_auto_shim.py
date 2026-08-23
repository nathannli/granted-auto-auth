from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "scripts/granted-auto-auth-bin/assumego"
SIDECAR = ROOT / "scripts/granted_auto_browser.py"


class ShimTests(unittest.TestCase):
    def helper(self, directory: Path, body: str) -> Path:
        path = directory / "real-assumego"
        path.write_text(f"#!/usr/bin/env python3\n{body}\n")
        path.chmod(0o755)
        return path

    def environment(self, real: Path, deadline: int) -> dict[str, str]:
        environment = os.environ.copy()
        environment["GRANTED_AUTO_AUTH_REAL_ASSUMEGO"] = str(real)
        environment["GRANTED_AUTO_AUTH_DEADLINE_NS"] = str(deadline)
        return environment

    def test_returns_real_process_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            real = self.helper(Path(temporary), "import sys; raise SystemExit(7)")
            result = subprocess.run(
                [str(SHIM)],
                env=self.environment(real, time.monotonic_ns() + 2_000_000_000),
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 7)

    def test_prebrowser_oidc_hang_is_hard_killed_at_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            real = self.helper(Path(temporary), "import time; time.sleep(30)")
            started = time.monotonic()
            result = subprocess.run(
                [str(SHIM)],
                env=self.environment(real, time.monotonic_ns() + 100_000_000),
                capture_output=True,
                text=True,
                timeout=3,
            )
            self.assertEqual(result.returncode, 124)
            self.assertLess(time.monotonic() - started, 1)

    def test_preexpired_deadline_does_not_start_real_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "started"
            real = self.helper(Path(temporary), f"from pathlib import Path; Path({str(marker)!r}).touch()")
            result = subprocess.run(
                [str(SHIM)],
                env=self.environment(real, time.monotonic_ns() - 1),
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 124)
            self.assertFalse(marker.exists())

    def test_signal_is_forwarded_to_real_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            real = self.helper(
                Path(temporary),
                "import signal, sys, time\n"
                "signal.signal(signal.SIGTERM, lambda *_: sys.exit(23))\n"
                "print('ready', flush=True)\n"
                "time.sleep(30)",
            )
            process = subprocess.Popen(
                [str(SHIM)],
                env=self.environment(real, time.monotonic_ns() + 5_000_000_000),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(process.stdout.readline().strip(), "ready")
                process.send_signal(signal.SIGTERM)
                self.assertEqual(process.wait(timeout=3), 23)
            finally:
                if process.poll() is None:
                    process.kill()
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

    def test_uv_nonstart_returns_without_secret_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = os.environ.copy()
            environment["PATH"] = temporary
            result = subprocess.run(
                [str(SIDECAR), "https://oidc.us-east-1.amazonaws.com/authorize"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=2,
            )
            self.assertEqual(result.returncode, 127)

    def test_rejects_recursive_real_path(self) -> None:
        result = subprocess.run(
            [str(SHIM)],
            env=self.environment(SHIM, time.monotonic_ns() + 1_000_000_000),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 126)


if __name__ == "__main__":
    unittest.main()
