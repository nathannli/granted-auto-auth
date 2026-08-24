from __future__ import annotations

import fcntl
import importlib.util
import os
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SIDECAR_PATH = ROOT / "scripts/granted_auto_browser.py"
SPEC = importlib.util.spec_from_file_location("granted_auto_browser", SIDECAR_PATH)
assert SPEC and SPEC.loader
sidecar = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sidecar
SPEC.loader.exec_module(sidecar)


class URLTests(unittest.TestCase):
    def test_accepts_pkce_and_device_hosts(self) -> None:
        accepted = (
            "https://oidc.us-east-1.amazonaws.com/authorize?secret=value",
            "https://device.sso.us-east-1.amazonaws.com/?user_code=ABCD-EFGH",
            "https://d-1234567890.awsapps.com/start/#/device?user_code=ABCD-EFGH",
        )
        for value in accepted:
            with self.subTest(value=value):
                self.assertEqual(sidecar.validate_initial_url(value), value)

    def test_rejects_non_https_and_unknown_hosts(self) -> None:
        for value in ("http://oidc.us-east-1.amazonaws.com/authorize", "https://example.com/authorize", "not-a-url"):
            with self.subTest(value=value):
                with self.assertRaises(sidecar.SetupError):
                    sidecar.validate_initial_url(value)

    def test_redacts_query_and_fragment(self) -> None:
        value = "https://oidc.us-east-1.amazonaws.com/authorize?code=secret#fragment"
        self.assertEqual(sidecar.redact_url(value), "https://oidc.us-east-1.amazonaws.com/authorize")

    def test_redirect_allowlist(self) -> None:
        self.assertEqual(sidecar.validate_redirect_url("https://us-east-1.signin.aws/path?state=secret"), "us-east-1.signin.aws")
        with self.assertRaises(sidecar.AutoAuthError):
            sidecar.validate_redirect_url("https://example.com/")

    def test_callback_requires_exact_loopback_path(self) -> None:
        self.assertTrue(sidecar.is_callback_url("http://127.0.0.1:1234/oauth/callback?code=redacted"))
        self.assertFalse(sidecar.is_callback_url("http://127.0.0.1:1234/username"))
        self.assertFalse(sidecar.is_callback_url("https://example.com/oauth/callback"))


class CredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "granted-auto-auth"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "credentials.toml"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, mode: int = 0o600) -> None:
        self.path.write_text(
            'username = "person@example.com"\npassword = "password"  # pragma: allowlist secret\n'
            'totp_secret = "JBSW Y3DP-EHPK3PXP"  # pragma: allowlist secret\nidp = "aws_identity_center"\n'
        )
        self.path.chmod(mode)

    def test_loads_and_normalizes_valid_credentials(self) -> None:
        self.write()
        credentials = sidecar.load_credentials(self.path)
        self.assertEqual(credentials.username, "person@example.com")
        self.assertEqual(credentials.totp_secret, "JBSWY3DPEHPK3PXP")

    def test_rejects_permissive_mode(self) -> None:
        self.write(0o644)
        with self.assertRaises(sidecar.SetupError):
            sidecar.load_credentials(self.path)

    def test_rejects_symlink(self) -> None:
        target = self.directory / "target.toml"
        target.write_text('username = "x"\n')
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(sidecar.SetupError):
            sidecar.load_credentials(self.path)

    def test_reports_missing_field_without_value(self) -> None:
        self.path.write_text('username = "person@example.com"\n')
        self.path.chmod(0o600)
        with self.assertRaisesRegex(sidecar.SetupError, "missing credential field: password"):
            sidecar.load_credentials(self.path)

    def test_rejects_inode_change_during_open(self) -> None:
        self.write()
        real_fstat = os.fstat

        def changed_inode(descriptor: int) -> os.stat_result:
            values = list(real_fstat(descriptor))
            values[1] += 1
            return os.stat_result(values)

        with mock.patch.object(sidecar.os, "fstat", side_effect=changed_inode):
            with self.assertRaisesRegex(sidecar.SetupError, "changed while opening"):
                sidecar.load_credentials(self.path)

    def test_install_state_requires_matching_chromium_revision(self) -> None:
        chromium = self.directory / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        state = self.directory / "install.toml"
        state.write_text(
            'phase = "configured"\nplaywright_version = "1.62.0"\n'
            f'chromium_path = "{chromium}"\nchromium_revision = "1234"\n'
        )
        state.chmod(0o600)
        self.assertEqual(sidecar.load_chromium_path(state), str(chromium))
        state.write_text(
            'phase = "configured"\nplaywright_version = "1.62.0"\n'
            f'chromium_path = "{chromium}"\nchromium_revision = "9999"\n'
        )
        with self.assertRaises(sidecar.SetupError):
            sidecar.load_chromium_path(state)

    def test_install_state_requires_matching_playwright_version(self) -> None:
        chromium = self.directory / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        state = self.directory / "install.toml"
        state.write_text(
            'phase = "configured"\nplaywright_version = "1.61.0"\n'
            f'chromium_path = "{chromium}"\nchromium_revision = "1234"\n'
        )
        state.chmod(0o600)
        with self.assertRaisesRegex(sidecar.SetupError, "not configured"):
            sidecar.load_chromium_path(state)


class DeadlineAndProcessTests(unittest.TestCase):
    def test_missing_deadline_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(sidecar.SetupError):
                sidecar.deadline_ns()

    def test_expired_deadline_is_timeout(self) -> None:
        with mock.patch.dict(os.environ, {"GRANTED_AUTO_AUTH_DEADLINE_NS": str(time.monotonic_ns() - 1)}):
            with self.assertRaises(sidecar.AuthTimeout):
                sidecar.deadline_ns()

    def test_profile_lock_times_out_while_owned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "browser.lock"
            first = sidecar.acquire_profile_lock(time.monotonic_ns() + 1_000_000_000, path)
            try:
                with self.assertRaises(sidecar.AuthTimeout):
                    sidecar.acquire_profile_lock(time.monotonic_ns() + 50_000_000, path)
            finally:
                fcntl.flock(first, fcntl.LOCK_UN)
                os.close(first)

    def test_process_identity_rejects_pid_reuse_shape(self) -> None:
        identity = sidecar.ProcessIdentity(os.getpid(), "wrong", os.path.realpath(sys.executable), None)
        self.assertFalse(sidecar.process_matches(identity))

    def test_process_identity_rejects_wrong_executable(self) -> None:
        _, start_time, _ = sidecar._process_info(os.getpid())
        identity = sidecar.ProcessIdentity(os.getpid(), start_time, os.path.realpath("/bin/true"), None)
        self.assertFalse(sidecar.process_matches(identity))

    def test_process_backend_reports_current_process(self) -> None:
        parent, start_time, executable = sidecar._process_info(os.getpid())
        self.assertEqual(parent, os.getppid())
        self.assertTrue(start_time)
        self.assertEqual(executable, os.path.realpath(sys.executable))

    def test_unsupported_process_platform_fails_closed(self) -> None:
        with mock.patch.object(sidecar.sys, "platform", "freebsd"):
            with self.assertRaisesRegex(sidecar.SetupError, "unsupported process platform"):
                sidecar._process_info(os.getpid())

    def test_cancel_process_terminates_verified_child(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            _, start_time, _ = sidecar._process_info(child.pid)
            identity = sidecar.ProcessIdentity(child.pid, start_time, os.path.realpath(sys.executable), None)
            sidecar.cancel_process(identity, time.monotonic_ns() + 2_000_000_000)
            child.wait(timeout=3)
            self.assertEqual(child.returncode, -signal.SIGTERM)
        finally:
            if child.poll() is None:
                child.kill()

    def test_cancel_process_escalates_after_ignored_sigterm(self) -> None:
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(30)",
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(child.stdout.readline().strip(), "ready")
            _, start_time, _ = sidecar._process_info(child.pid)
            identity = sidecar.ProcessIdentity(child.pid, start_time, os.path.realpath(sys.executable), None)
            sidecar.cancel_process(identity, time.monotonic_ns() + 150_000_000)
            child.wait(timeout=3)
            self.assertEqual(child.returncode, -signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill()
            if child.stdout is not None:
                child.stdout.close()

    def test_deadline_cancellation_skips_grace(self) -> None:
        identity = sidecar.ProcessIdentity(123, "start", "/real/assumego", None)
        with mock.patch.object(sidecar, "process_alive", return_value=True), mock.patch.object(
            sidecar, "_send_signal"
        ) as sender, mock.patch.object(sidecar.time, "monotonic_ns", return_value=2):
            sidecar.cancel_process(identity, 1)
        sender.assert_called_once_with(identity, signal.SIGKILL)

    def test_pidfd_signal_path_is_preferred(self) -> None:
        identity = sidecar.ProcessIdentity(123, "start", "/real/assumego", 99)
        with mock.patch.object(sidecar.signal, "pidfd_send_signal", create=True) as sender, mock.patch.object(
            sidecar.os, "kill"
        ) as fallback:
            sidecar._send_signal(identity, signal.SIGTERM)
        sender.assert_called_once_with(99, signal.SIGTERM)
        fallback.assert_not_called()

    def test_fallback_signal_revalidates_identity(self) -> None:
        identity = sidecar.ProcessIdentity(123, "start", "/real/assumego", None)
        with mock.patch.object(sidecar, "process_matches", side_effect=(False, True)), mock.patch.object(
            sidecar.os, "kill"
        ) as sender:
            sidecar._send_signal(identity, signal.SIGTERM)
            sidecar._send_signal(identity, signal.SIGKILL)
        sender.assert_called_once_with(123, signal.SIGKILL)

    def test_finds_verified_python_ancestor(self) -> None:
        code = f"""
import importlib.util, os, sys
p={str(SIDECAR_PATH)!r}
s=importlib.util.spec_from_file_location('ancestor_sidecar', p)
m=importlib.util.module_from_spec(s)
sys.modules[s.name]=m
s.loader.exec_module(m)
i=m.find_assumego_ancestor(sys.executable)
print(i.pid)
if i.pidfd is not None: os.close(i.pidfd)
"""
        result = subprocess.run([sys.executable, "-c", code], check=True, text=True, capture_output=True)
        self.assertEqual(int(result.stdout.strip()), os.getpid())

    def test_finds_verified_ancestor_through_intermediate_processes(self) -> None:
        code = f"""
import importlib.util, os, sys
p={str(SIDECAR_PATH)!r}
s=importlib.util.spec_from_file_location('intermediate_ancestor_sidecar', p)
m=importlib.util.module_from_spec(s)
sys.modules[s.name]=m
s.loader.exec_module(m)
i=m.find_assumego_ancestor({os.path.realpath(sys.executable)!r})
print(i.pid)
if i.pidfd is not None: os.close(i.pidfd)
"""
        command = f"{shlex.quote(sys.executable)} -c {shlex.quote(code)}"
        process = subprocess.Popen(["/bin/sh", "-c", command], stdout=subprocess.PIPE, text=True)
        try:
            output, _ = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(int(output.strip()), os.getpid())
        finally:
            if process.poll() is None:
                process.kill()

    def test_missing_and_wrong_ancestor_fail_before_browser(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaisesRegex(sidecar.SetupError, "executable is missing"):
                sidecar.find_assumego_ancestor(str(missing))
            wrong = Path(temporary) / "wrong-assumego"
            wrong.write_text("#!/bin/sh\nexit 0\n")
            wrong.chmod(0o755)
            with self.assertRaisesRegex(sidecar.SetupError, "ancestor is missing"):
                sidecar.find_assumego_ancestor(str(wrong))

    def test_main_cancels_assumego_for_terminal_browser_failures(self) -> None:
        failures = (
            sidecar.UnsupportedChallenge("unsupported authentication challenge"),
            sidecar.AutoAuthError("adapter failure"),
            sidecar.AutoAuthError("redirect host is not allowed"),
            sidecar.PlaywrightTimeoutError("browser timeout"),
            RuntimeError("browser crash"),
        )
        credentials = sidecar.Credentials("person@example.com", "password", "JBSWY3DPEHPK3PXP", "aws_identity_center")
        identity = sidecar.ProcessIdentity(123, "start", "/real/assumego", None)
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                descriptor = os.open(Path(temporary) / "browser.lock", os.O_RDWR | os.O_CREAT, 0o600)
                with mock.patch.object(sidecar, "deadline_ns", return_value=time.monotonic_ns() + 5_000_000_000), mock.patch.object(
                    sidecar, "find_assumego_ancestor", return_value=identity
                ), mock.patch.object(sidecar, "load_credentials", return_value=credentials), mock.patch.object(
                    sidecar, "load_chromium_path", return_value="/chromium"
                ), mock.patch.object(sidecar, "acquire_profile_lock", return_value=descriptor), mock.patch.object(
                    sidecar, "run_browser", side_effect=failure
                ), mock.patch.object(sidecar, "cancel_process") as cancel:
                    result = sidecar.main(["https://oidc.us-east-1.amazonaws.com/authorize"])
                self.assertNotEqual(result, 0)
                cancel.assert_called_once()
                self.assertEqual(cancel.call_args.kwargs["immediate"], isinstance(failure, sidecar.PlaywrightTimeoutError))

    def test_main_cancels_assumego_on_prebrowser_secret_failure(self) -> None:
        identity = sidecar.ProcessIdentity(123, "start", "/real/assumego", None)
        with mock.patch.object(sidecar, "deadline_ns", return_value=time.monotonic_ns() + 5_000_000_000), mock.patch.object(
            sidecar, "find_assumego_ancestor", return_value=identity
        ), mock.patch.object(sidecar, "load_credentials", side_effect=sidecar.SetupError("secret failure")), mock.patch.object(
            sidecar, "cancel_process"
        ) as cancel:
            result = sidecar.main(["https://oidc.us-east-1.amazonaws.com/authorize"])
        self.assertEqual(result, sidecar.EXIT_SETUP)
        cancel.assert_called_once_with(identity, mock.ANY, immediate=False)

    def test_profile_lock_held_through_target_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "browser.lock"
            descriptor = sidecar.acquire_profile_lock(time.monotonic_ns() + 1_000_000_000, path)
            competitor = os.open(path, os.O_RDWR)
            calls = 0

            def target_alive(_identity: sidecar.ProcessIdentity) -> bool:
                nonlocal calls
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                calls += 1
                return calls == 1

            credentials = sidecar.Credentials("person@example.com", "password", "JBSWY3DPEHPK3PXP", "aws_identity_center")
            identity = sidecar.ProcessIdentity(123, "start", "/real/assumego", None)
            try:
                with mock.patch.object(sidecar, "deadline_ns", return_value=time.monotonic_ns() + 5_000_000_000), mock.patch.object(
                    sidecar, "find_assumego_ancestor", return_value=identity
                ), mock.patch.object(sidecar, "load_credentials", return_value=credentials), mock.patch.object(
                    sidecar, "load_chromium_path", return_value="/chromium"
                ), mock.patch.object(sidecar, "acquire_profile_lock", return_value=descriptor), mock.patch.object(
                    sidecar, "run_browser"
                ), mock.patch.object(sidecar, "process_alive", side_effect=target_alive), mock.patch.object(
                    sidecar, "remaining_seconds", return_value=1.0
                ), mock.patch.object(sidecar.time, "sleep"):
                    self.assertEqual(sidecar.main(["https://oidc.us-east-1.amazonaws.com/authorize"]), 0)
                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(competitor)

    def test_profile_lock_held_through_failure_cancellation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "browser.lock"
            descriptor = sidecar.acquire_profile_lock(time.monotonic_ns() + 1_000_000_000, path)
            competitor = os.open(path, os.O_RDWR)

            def cancel_while_locked(_identity: sidecar.ProcessIdentity, _deadline: int, immediate: bool = False) -> None:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)

            credentials = sidecar.Credentials("person@example.com", "password", "JBSWY3DPEHPK3PXP", "aws_identity_center")
            identity = sidecar.ProcessIdentity(123, "start", "/real/assumego", None)
            try:
                with mock.patch.object(sidecar, "deadline_ns", return_value=time.monotonic_ns() + 5_000_000_000), mock.patch.object(
                    sidecar, "find_assumego_ancestor", return_value=identity
                ), mock.patch.object(sidecar, "load_credentials", return_value=credentials), mock.patch.object(
                    sidecar, "load_chromium_path", return_value="/chromium"
                ), mock.patch.object(sidecar, "acquire_profile_lock", return_value=descriptor), mock.patch.object(
                    sidecar, "run_browser", side_effect=RuntimeError("browser crash")
                ), mock.patch.object(sidecar, "cancel_process", side_effect=cancel_while_locked):
                    self.assertEqual(
                        sidecar.main(["https://oidc.us-east-1.amazonaws.com/authorize"]), sidecar.EXIT_FAILURE
                    )
                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(competitor)

    def test_totp_waits_for_next_window(self) -> None:
        fake_totp = mock.Mock()
        fake_totp.now.return_value = "123456"
        with mock.patch.object(sidecar.time, "time", return_value=29.0), mock.patch.object(
            sidecar.time, "sleep"
        ) as sleep, mock.patch.object(sidecar.pyotp, "TOTP", return_value=fake_totp):
            self.assertEqual(sidecar._totp_now("SECRET", time.monotonic_ns() + 5_000_000_000), "123456")
        sleep.assert_called_once_with(1.1)


class InterfaceTests(unittest.TestCase):
    def test_sidecar_rejects_unknown_shape(self) -> None:
        self.assertEqual(sidecar.main([]), sidecar.EXIT_USAGE)
        self.assertEqual(sidecar.main(["doctor"]), sidecar.EXIT_SETUP)

    def test_events_have_bounded_metadata(self) -> None:
        with mock.patch("builtins.print") as output:
            sidecar.emit("password", "x" * 100, "aws_identity_center")
        payload = output.call_args.args[0]
        self.assertNotIn("username", payload)
        self.assertLess(len(payload), 160)

    def test_unknown_control_stage_redacts_credentials(self) -> None:
        credentials = sidecar.Credentials("person@example.com", "password", "JBSWY3DPEHPK3PXP", "aws_identity_center")
        stage = sidecar.safe_control_stage(["button:Continue as person@example.com", "heading:password"], credentials)
        self.assertNotIn("person@example.com", stage)
        self.assertNotIn("password", stage)
        self.assertLessEqual(len(stage), 64)

    def test_aws_success_heading_variants_are_terminal(self) -> None:
        for value in ("Authentication Successful", "Authentication Succeeded", "Authorization succeeded"):
            with self.subTest(value=value):
                self.assertIsNotNone(sidecar.SUCCESS_TEXT.search(value))


if __name__ == "__main__":
    unittest.main()
