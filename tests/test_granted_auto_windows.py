from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import json
import re
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def managed_test_credential() -> tuple[str, bool]:
    import granted_auto_windows as windows

    value = windows.credential_read()
    if value is not None:
        return value, False
    value = windows.generate_keyring_password()
    windows.credential_create(value)
    return value, True


def remove_managed_test_credential(created: bool) -> None:
    if created:
        import granted_auto_windows as windows

        windows.credential_delete()


def configured_keyring_environment(directory: Path, value: str, environment: dict[str, str]) -> None:
    import hashlib
    import granted_auto_windows as windows

    profile = directory / "profile"
    state_dir = profile / ".config/granted-auto-auth"
    keyring_dir = profile / ".local/share/granted-auto-auth/granted-keyring"
    windows.ensure_restricted_directory(profile)
    windows.ensure_restricted_directory(state_dir)
    windows.ensure_restricted_directory(keyring_dir)
    state = (
        'phase = "configured"\n'
        f'installed_keyring_dir = {json.dumps(windows.canonical_path(keyring_dir))}\n'
        'keyring_credential_target = "granted-auto-auth/file-keyring-password/v1"\n'
        f'keyring_credential_hash = "{hashlib.sha256(value.encode()).hexdigest()}"\n'
    ).encode()
    windows.write_secure_bytes(state_dir / "install.toml", state)
    environment["USERPROFILE"] = str(profile)
    environment["HOME"] = str(profile)


@unittest.skipUnless(os.name == "nt", "Windows-only tests")
class WindowsPlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        global windows
        import granted_auto_windows as windows_module

        windows = windows_module

    def test_secure_write_reads_through_validated_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "state"
            path = directory / "install.toml"
            windows.write_secure_bytes(path, b'phase = "configured"\n')
            self.assertEqual(windows.read_secure_bytes(path), b'phase = "configured"\n')

    def test_secure_open_rejects_reparse_point(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / "target.toml"
            link = directory / "link.toml"
            windows.write_secure_bytes(target, b'x = "y"\n')
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            with self.assertRaises(PermissionError):
                windows.read_secure_bytes(link)

    def test_secure_open_rejects_directory_junction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / "target"
            junction = directory / "junction"
            target.mkdir()
            result = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)],
                text=True, capture_output=True,
            )
            if result.returncode != 0:
                self.skipTest(result.stderr or result.stdout)
            with self.assertRaises(PermissionError):
                windows.secure_open(junction, directory=True)

    def test_profile_lock_uses_shared_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "locks" / "browser.lock"
            windows.ensure_restricted_directory(path.parent)
            windows.write_secure_bytes(path, b"")
            first = windows.lock_file(path, time.monotonic_ns() + 1_000_000_000)
            try:
                with self.assertRaises(TimeoutError):
                    windows.lock_file(path, time.monotonic_ns() + 50_000_000)
            finally:
                windows.unlock_file(*first)

    def test_keyring_password_uses_url_safe_32_byte_entropy(self) -> None:
        value = windows.generate_keyring_password()
        self.assertGreaterEqual(len(value), 43)
        self.assertTrue(all(character.isalnum() or character in "-_" for character in value))

    def test_credential_manager_round_trip_and_no_overwrite(self) -> None:
        target = f"granted-auto-auth/test/{os.getpid()}-{time.monotonic_ns()}"
        value = windows.generate_keyring_password()
        self.assertIsNone(windows.credential_read(target))
        try:
            windows.credential_create(value, target)
            self.assertEqual(windows.credential_read(target), value)
            with self.assertRaises(FileExistsError):
                windows.credential_create(windows.generate_keyring_password(), target)
            self.assertEqual(windows.credential_read(target), value)
        finally:
            windows.credential_delete(target)
        self.assertIsNone(windows.credential_read(target))

    def test_process_handle_identity_survives_snapshot(self) -> None:
        parent, start, executable, handle = windows.process_info(os.getpid())
        try:
            self.assertEqual(parent, os.getppid())
            self.assertTrue(start)
            self.assertEqual(Path(executable).name.lower(), "python.exe")
            self.assertTrue(Path(executable).is_file())
            self.assertTrue(windows.process_alive(handle))
        finally:
            windows.close_handle(handle)


@unittest.skipUnless(os.name == "nt", "Windows-only tests")
class WindowsControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        loader = importlib.machinery.SourceFileLoader("windows_controller", str(SCRIPTS / "granted-auto-auth"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec and spec.loader
        cls.controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.controller)

    def test_launch_template_produces_exact_quoted_tokens(self) -> None:
        with mock.patch.object(self.controller.windows, "canonical_path", side_effect=lambda value: str(value)):
            command = self.controller._windows_launch_command(r"C:\Program Files\uv\uv.exe")
        self.assertEqual(
            command,
            '"C:\\Program Files\\uv\\uv.exe" run --script --locked --offline '
            f'"{self.controller.SIDECAR}" "{{{{.URL}}}}"',
        )
        rendered = command.replace("{{.URL}}", "https://oidc.us-east-1.amazonaws.com/authorize")
        parts = [quoted or bare for quoted, bare in re.findall(r'"([^"]+)"|(\S+)', rendered)]
        self.assertEqual(parts, [
            r"C:\Program Files\uv\uv.exe", "run", "--script", "--locked", "--offline",
            str(self.controller.SIDECAR), "https://oidc.us-east-1.amazonaws.com/authorize",
        ])

    def test_config_patch_preserves_unrelated_bytes(self) -> None:
        original = b'# keep\r\nUseAuthorizationCode = true\r\nCustomSSOBrowserPath = "old"\r\n[Other]\r\nValue = 7\r\n'
        template = self.controller._installed_template("command", "\r\n")
        keyring = self.controller._installed_keyring(r"C:\secure", "\r\n")
        result = self.controller._patch_owned_config(original, "", template, keyring).decode()
        self.assertIn("# keep\r\nUseAuthorizationCode = true\r\n", result)
        self.assertIn("[Other]\r\nValue = 7\r\n", result)
        self.assertNotIn("CustomSSOBrowserPath", result)
        self.assertIn('[SSOBrowserLaunchTemplate]\r\nCommand = "command"', result)
        self.assertIn('[Keyring]\r\nBackend = "file"', result)

    def test_config_patch_restores_owned_fragments(self) -> None:
        previous_custom = 'CustomSSOBrowserPath = "old"\n'
        previous_template = '[SSOBrowserLaunchTemplate]\nCommand = "old command"\nUseForkProcess = true\n'
        previous_keyring = '[Keyring]\nBackend = "wincred"\n'
        installed = self.controller._patch_owned_config(
            b'UseAuthorizationCode = true\n', "", self.controller._installed_template("new command"),
            self.controller._installed_keyring(r"C:\secure"),
        )
        restored = self.controller._patch_owned_config(
            installed, previous_custom, previous_template, previous_keyring
        ).decode()
        self.assertIn(previous_custom, restored)
        self.assertIn(previous_template, restored)
        self.assertIn(previous_keyring, restored)
        self.assertNotIn("new command", restored)

    def test_template_match_accepts_granted_omitted_false_value(self) -> None:
        with mock.patch.object(self.controller, "_windows_settings", return_value=("", {"Command": "command"}, None)):
            self.assertTrue(self.controller._windows_template_matches("command"))
        with mock.patch.object(
            self.controller, "_windows_settings", return_value=("", {"Command": "command", "UseForkProcess": True}, None)
        ):
            self.assertFalse(self.controller._windows_template_matches("command"))

    def test_config_recovery_rejects_newer_unowned_content(self) -> None:
        state = {
            "installed_launch_template": "installed command",
            "config_fingerprint": "old fingerprint",
            "previous_custom_fragment": "",
            "previous_template_fragment": "",
            "previous_keyring_fragment": "",
            "installed_keyring_dir": r"C:\secure",
        }
        with mock.patch.object(self.controller, "_config_snapshot", return_value=(b"new", "new fingerprint")), mock.patch.object(
            self.controller, "_windows_template_matches", return_value=False
        ), self.assertRaisesRegex(self.controller.ControllerError, "newer Granted config"):
            self.controller._windows_restore_config(state, require_installed=False)

    def test_doctor_rejects_non_file_backend(self) -> None:
        completed = mock.Mock(stdout="Granted version: 0.39.0")
        config = {
            "UseAuthorizationCode": True,
            "DisableCredentialProcessCache": False,
            "Keyring": {"Backend": "wincred"},
        }
        with mock.patch.object(self.controller, "_credential_health", return_value=[]), mock.patch.object(
            self.controller, "run_checked", return_value=completed
        ), mock.patch.object(self.controller, "granted_config", return_value=config), mock.patch.object(
            self.controller, "platform_health", return_value=[]
        ), mock.patch.object(self.controller, "enabled", return_value=True), mock.patch("builtins.print") as output:
            self.assertEqual(self.controller.doctor(), 1)
        messages = [str(call.args[0]) for call in output.call_args_list]
        self.assertTrue(any("Keyring Backend must be file" in message for message in messages))

    def test_sync_sidecar_runtime_uses_launch_canonical_paths(self) -> None:
        canonical = lambda value: f"canonical:{value}"
        with mock.patch.object(self.controller, "_windows_uv_path", return_value="uv.exe"), mock.patch.object(
            self.controller.windows, "canonical_path", side_effect=canonical
        ), mock.patch.object(self.controller, "run_checked") as run:
            self.controller.sync_sidecar_runtime()
        sidecar = canonical(self.controller.SIDECAR)
        supervisor = canonical(self.controller.SUPERVISOR)
        self.assertEqual(run.call_args_list, [
            mock.call(["uv.exe", "lock", "--check", "--script", sidecar]),
            mock.call(["uv.exe", "sync", "--locked", "--script", sidecar]),
            mock.call(["uv.exe", "lock", "--check", "--script", supervisor]),
            mock.call(["uv.exe", "sync", "--locked", "--script", supervisor]),
        ])

    def test_install_prepares_restricted_browser_state_before_readiness(self) -> None:
        with mock.patch.object(self.controller, "_windows_prepare_browser_state") as prepare, mock.patch.object(
            self.controller, "_windows_enabled", return_value=True
        ), mock.patch.object(self.controller, "sync_sidecar_runtime") as sync, mock.patch("builtins.print"):
            self.controller._windows_install_locked()
        prepare.assert_called_once_with()
        sync.assert_called_once_with()

    def test_install_resynchronizes_owned_configured_state(self) -> None:
        state = {
            "phase": "configured",
            "installed_launch_template": "recorded command",
            "installed_keyring_dir": "keyring-dir",
            "keyring_credential_target": self.controller.KEYRING_CREDENTIAL_TARGET,
        }
        with mock.patch.object(self.controller, "_windows_prepare_browser_state"), mock.patch.object(
            self.controller, "_windows_enabled", side_effect=[False, True]
        ), mock.patch.object(self.controller.Path, "exists", return_value=True), mock.patch.object(
            self.controller, "read_secure_toml", return_value=state
        ), mock.patch.object(self.controller, "_windows_template_matches", return_value=True), mock.patch.object(
            self.controller, "_windows_keyring_matches", return_value=True
        ), mock.patch.object(self.controller, "_windows_owned_settings_match", return_value=True), mock.patch.object(
            self.controller, "_windows_prepare_keyring_credential"
        ), mock.patch.object(self.controller.windows, "ensure_restricted_directory"), mock.patch.object(
            self.controller.windows, "canonical_path", return_value="keyring-dir"
        ), mock.patch.object(
            self.controller, "_windows_uv_path", return_value="uv.exe"
        ), mock.patch.object(self.controller, "_windows_launch_command", return_value="command"), mock.patch.object(
            self.controller, "provision_chromium", return_value=("chrome.exe", "1234")
        ), mock.patch.object(self.controller, "_config_snapshot", return_value=(b"config", "fingerprint")), mock.patch.object(
            self.controller, "write_state"
        ) as write, mock.patch("builtins.print"):
            self.controller._windows_install_locked()
        self.assertEqual(write.call_count, 2)
        self.assertEqual(state["installed_launch_template"], "command")
        self.assertEqual(state["chromium_path"], "chrome.exe")
        self.assertEqual(state["config_fingerprint"], "fingerprint")

    def test_legacy_install_migrates_wincred_to_managed_file_keyring(self) -> None:
        state = {"phase": "configured", "installed_launch_template": "recorded command"}
        config = b'[Keyring]\nBackend = "wincred"\n'
        with mock.patch.object(self.controller, "_windows_prepare_browser_state"), mock.patch.object(
            self.controller, "_windows_enabled", side_effect=[False, True]
        ), mock.patch.object(self.controller.Path, "exists", return_value=True), mock.patch.object(
            self.controller, "read_secure_toml", return_value=state
        ), mock.patch.object(self.controller, "_windows_template_matches", return_value=True), mock.patch.object(
            self.controller, "_windows_keyring_migration_allowed", return_value=True
        ), mock.patch.object(
            self.controller, "_windows_prepare_keyring_directory", return_value=("keyring-dir", True)
        ), mock.patch.object(self.controller, "_windows_prepare_keyring_credential") as prepare, mock.patch.object(
            self.controller, "_windows_uv_path", return_value="uv.exe"
        ), mock.patch.object(self.controller, "_windows_launch_command", return_value="command"), mock.patch.object(
            self.controller, "provision_chromium", return_value=("chrome.exe", "1234")
        ), mock.patch.object(
            self.controller, "_config_snapshot", return_value=(config, "fingerprint")
        ), mock.patch.object(self.controller, "_windows_owned_settings_match", return_value=False), mock.patch.object(
            self.controller, "_windows_apply_install_config"
        ) as apply_config, mock.patch.object(self.controller, "write_state"), mock.patch("builtins.print"):
            self.controller._windows_install_locked()
        self.assertEqual(state["previous_keyring_fragment"], config.decode())
        self.assertEqual(state["keyring_credential_target"], self.controller.KEYRING_CREDENTIAL_TARGET)
        prepare.assert_called_once_with(state, allow_existing=False)
        apply_config.assert_called_once_with(state, "command", "keyring-dir", "fingerprint")

    def test_missing_password_with_nonempty_cache_fails_without_generation(self) -> None:
        state = {"keyring_credential_target": self.controller.KEYRING_CREDENTIAL_TARGET}
        with mock.patch.object(self.controller.windows, "credential_read", return_value=None), mock.patch.object(
            self.controller, "_windows_keyring_directory_empty", return_value=False
        ), mock.patch.object(self.controller.windows, "generate_keyring_password") as generate:
            with self.assertRaisesRegex(self.controller.ControllerError, "encrypted cache is nonempty"):
                self.controller._windows_prepare_keyring_credential(state, allow_existing=False)
        generate.assert_not_called()

    def test_storage_cleanup_never_deletes_unowned_password(self) -> None:
        value = "A" * 43
        state = {"keyring_credential_created": False, "keyring_credential_hash": "not-owned"}
        with mock.patch.object(self.controller.windows, "credential_read", return_value=value), mock.patch.object(
            self.controller.windows, "credential_delete"
        ) as delete:
            self.controller._windows_cleanup_new_storage(state)
        delete.assert_not_called()

    def test_storage_cleanup_recovers_credential_written_before_owner_flag(self) -> None:
        import hashlib

        value = "A" * 43
        state = {
            "phase": "storage_prepared",
            "keyring_credential_created": False,
            "keyring_credential_hash": hashlib.sha256(value.encode()).hexdigest(),
        }
        with mock.patch.object(self.controller.windows, "credential_read", return_value=value), mock.patch.object(
            self.controller.windows, "credential_delete"
        ) as delete, mock.patch.object(self.controller, "KEYRING_DIR", Path("missing")):
            self.controller._windows_cleanup_new_storage(state)
        delete.assert_called_once_with(self.controller.KEYRING_CREDENTIAL_TARGET)

    def test_install_transaction_lock_rejects_concurrent_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            lock = state_dir / "install.lock"
            with mock.patch.object(self.controller, "STATE_DIR", state_dir), mock.patch.object(
                self.controller, "TRANSACTION_LOCK", lock
            ):
                with self.controller._windows_transaction():
                    with self.assertRaisesRegex(TimeoutError, "installation transaction lock timed out"):
                        with self.controller._windows_transaction():
                            pass

    def test_install_transaction_lock_allows_atomic_state_replacement(self) -> None:
        self.assertNotEqual(self.controller.TRANSACTION_LOCK.parent, self.controller.STATE_DIR)
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_file = state_dir / "install.toml"
            lock = state_dir / "locks/install.lock"
            with mock.patch.object(self.controller, "STATE_DIR", state_dir), mock.patch.object(
                self.controller, "STATE_FILE", state_file
            ), mock.patch.object(self.controller, "TRANSACTION_LOCK", lock):
                with self.controller._windows_transaction():
                    self.controller.write_state({"phase": "prepared"})
                    self.controller.write_state({"phase": "configured"})
            self.assertEqual(self.controller.read_secure_toml(state_file)["phase"], "configured")


@unittest.skipUnless(os.name == "nt", "Windows-only tests")
class WindowsSupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.keyring_password, cls.created_credential = managed_test_credential()

    @classmethod
    def tearDownClass(cls) -> None:
        remove_managed_test_credential(cls.created_credential)

    def test_supervisor_forwards_protocol_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "assumego.exe"
            shutil.copy2(Path(os.environ["WINDIR"]) / "System32/cmd.exe", fake)
            environment = os.environ.copy()
            configured_keyring_environment(Path(temporary), self.keyring_password, environment)
            environment["GRANTED_AUTO_AUTH_DEADLINE_NS"] = str(time.monotonic_ns() + 10_000_000_000)
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "granted_auto_auth_supervisor.py"), str(fake), "/d", "/c", "echo GrantedOutput ok"],
                text=True, capture_output=True, env=environment, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "GrantedOutput ok")

    def test_supervisor_replaces_inherited_password_and_restores_own_environment(self) -> None:
        loader = importlib.machinery.SourceFileLoader(
            "windows_supervisor_environment", str(SCRIPTS / "granted_auto_auth_supervisor.py")
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec and spec.loader
        supervisor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(supervisor)
        observed = []

        def capture(*_args) -> int:
            observed.append(os.environ.get("CF_KEYRING_FILE_PASSWORD"))
            return 0

        with mock.patch.dict(os.environ, {"CF_KEYRING_FILE_PASSWORD": "caller"}), mock.patch.object(
            supervisor, "managed_keyring_password", return_value="managed"
        ), mock.patch.object(supervisor, "run", side_effect=capture):
            self.assertEqual(supervisor.run_with_managed_keyring(Path(sys.executable), [], time.monotonic_ns()), 0)
            self.assertEqual(os.environ["CF_KEYRING_FILE_PASSWORD"], "caller")
        self.assertEqual(observed, ["managed"])

    def test_supervisor_enforces_expired_deadline_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "assumego.exe"
            shutil.copy2(Path(os.environ["WINDIR"]) / "System32/cmd.exe", fake)
            environment = os.environ.copy()
            configured_keyring_environment(Path(temporary), self.keyring_password, environment)
            environment["GRANTED_AUTO_AUTH_DEADLINE_NS"] = str(time.monotonic_ns() - 1)
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "granted_auto_auth_supervisor.py"), str(fake), "/d", "/c", "exit 0"],
                text=True, capture_output=True, env=environment, timeout=10,
            )
            self.assertEqual(result.returncode, 124)

    def test_supervisor_rejects_password_mismatch_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fake = directory / "assumego.exe"
            shutil.copy2(Path(os.environ["WINDIR"]) / "System32/cmd.exe", fake)
            environment = os.environ.copy()
            configured_keyring_environment(directory, self.keyring_password, environment)
            state = Path(environment["HOME"]) / ".config/granted-auto-auth/install.toml"
            original = state.read_text()
            windows = sys.modules["granted_auto_windows"]
            windows.write_secure_bytes(state, re.sub(r'keyring_credential_hash = "[^"]+"', 'keyring_credential_hash = "wrong"', original).encode())
            environment["GRANTED_AUTO_AUTH_DEADLINE_NS"] = str(time.monotonic_ns() + 10_000_000_000)
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "granted_auto_auth_supervisor.py"), str(fake), "/d", "/c", "echo launched"],
                text=True, capture_output=True, env=environment, timeout=10,
            )
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("launched", result.stdout)

    def test_oversized_fake_token_reuses_file_cache_without_second_browser_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fake = directory / "assumego.exe"
            base = Path(sys._base_executable)
            shutil.copy2(base, fake)
            for dll in (base.parent / "python312.dll", base.parent / "python3.dll"):
                if dll.exists():
                    shutil.copy2(dll, directory / dll.name)
            environment = os.environ.copy()
            configured_keyring_environment(directory, self.keyring_password, environment)
            environment["PYTHONHOME"] = sys.base_prefix
            environment["GRANTED_AUTO_AUTH_DEADLINE_NS"] = str(time.monotonic_ns() + 10_000_000_000)
            cache = Path(environment["HOME"]) / ".local/share/granted-auto-auth/granted-keyring/fake-token"
            marker = directory / "browser.marker"
            code = (
                "import os,pathlib;"
                f"cache=pathlib.Path({str(cache)!r});marker=pathlib.Path({str(marker)!r});"
                "cached=cache.exists();"
                "marker.write_text('launched') if not cached else None;"
                "password=os.environ['CF_KEYRING_FILE_PASSWORD'].encode();"
                "token=b'T'*3000;"
                "cache.write_bytes(bytes(value^password[index%len(password)] for index,value in enumerate(token))) if not cached else None;"
                "print('GrantedOutput cached' if cached else 'GrantedOutput login')"
            )
            command = [sys.executable, str(SCRIPTS / "granted_auto_auth_supervisor.py"), str(fake), "-c", code]
            first = subprocess.run(command, text=True, capture_output=True, env=environment, timeout=10)
            first_marker_time = marker.stat().st_mtime_ns
            second = subprocess.run(command, text=True, capture_output=True, env=environment, timeout=10)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertGreater(cache.stat().st_size, 2560)
            self.assertIn("GrantedOutput cached", second.stdout)
            self.assertEqual(marker.stat().st_mtime_ns, first_marker_time)

    def test_job_timeout_removes_descendant_tree(self) -> None:
        import granted_auto_windows as windows

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fake = directory / "assumego.exe"
            base = Path(sys._base_executable)
            shutil.copy2(base, fake)
            for dll in (base.parent / "python312.dll", base.parent / "python3.dll"):
                if dll.exists():
                    shutil.copy2(dll, directory / dll.name)
            child_pid = directory / "child.pid"
            code = (
                "import pathlib,subprocess,sys,time;"
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']);"
                f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid));"
                "time.sleep(30)"
            )
            environment = os.environ.copy()
            configured_keyring_environment(directory, self.keyring_password, environment)
            environment["PYTHONHOME"] = sys.base_prefix
            environment["GRANTED_AUTO_AUTH_DEADLINE_NS"] = str(time.monotonic_ns() + 5_000_000_000)
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "granted_auto_auth_supervisor.py"), str(fake), "-c", code],
                text=True, capture_output=True, env=environment, timeout=10,
            )
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertTrue(child_pid.exists())
            pid = int(child_pid.read_text())
            with self.assertRaises(ProcessLookupError):
                windows.process_info(pid)

    def test_successful_supervisor_preserves_detached_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fake = directory / "assumego.exe"
            base = Path(sys._base_executable)
            shutil.copy2(base, fake)
            for dll in (base.parent / "python312.dll", base.parent / "python3.dll"):
                if dll.exists():
                    shutil.copy2(dll, directory / dll.name)
            marker = directory / "browser.marker"
            child_code = f"import pathlib,time;time.sleep(0.5);pathlib.Path({str(marker)!r}).write_text('opened')"
            code = (
                "import subprocess,sys;"
                f"subprocess.Popen([sys.executable,'-c',{child_code!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
            )
            environment = os.environ.copy()
            configured_keyring_environment(directory, self.keyring_password, environment)
            environment["PYTHONHOME"] = sys.base_prefix
            environment["GRANTED_AUTO_AUTH_DEADLINE_NS"] = str(time.monotonic_ns() + 5_000_000_000)
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "granted_auto_auth_supervisor.py"), str(fake), "-c", code],
                text=True, capture_output=True, env=environment, timeout=10,
            )
            deadline = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(marker.exists())


@unittest.skipUnless(os.name == "nt", "Windows-only tests")
class PowerShellControllerLauncherTests(unittest.TestCase):
    def test_v63_symlinked_launcher_resolves_controller(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            launcher = SCRIPTS / "granted-auto-auth.ps1"
            linked_launcher = Path(temporary) / "granted-auto-auth.ps1"
            try:
                linked_launcher.symlink_to(launcher)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            result = subprocess.run(
                ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(linked_launcher), "invalid"],
                text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("usage: granted-auto-auth", result.stderr)


@unittest.skipUnless(os.name == "nt", "Windows-only tests")
class PowerShellAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.keyring_password, cls.created_credential = managed_test_credential()

    @classmethod
    def tearDownClass(cls) -> None:
        remove_managed_test_credential(cls.created_credential)

    def configured_environment(self, directory: Path) -> dict[str, str]:
        import granted_auto_windows as windows

        profile = directory / "profile"
        state_dir = profile / ".config/granted-auto-auth"
        granted_dir = profile / ".granted"
        bin_dir = directory / "bin"
        bin_dir.mkdir()
        fake_assumego = bin_dir / "assumego.exe"
        shutil.copy2(Path(os.environ["WINDIR"]) / "System32/cmd.exe", fake_assumego)
        chromium = profile / ".cache/ms-playwright/chromium-1234/chrome.exe"
        chromium.parent.mkdir(parents=True)
        shutil.copy2(Path(os.environ["WINDIR"]) / "System32/cmd.exe", chromium)
        uv = windows.canonical_path(shutil.which("uv.exe") or shutil.which("uv"))
        sidecar = SCRIPTS / "granted_auto_auth.py"
        supervisor = SCRIPTS / "granted_auto_auth_supervisor.py"
        command = f'"{uv}" run --script --locked --offline "{windows.canonical_path(sidecar)}" "{{{{.URL}}}}"'
        config = (
            'UseAuthorizationCode = true\nDisableCredentialProcessCache = false\n'
            '[SSOBrowserLaunchTemplate]\n'
            f'Command = {json.dumps(command)}\nUseForkProcess = false\n'
            '[Keyring]\nBackend = "file"\n'
        ).encode()
        keyring_dir = profile / ".local/share/granted-auto-auth/granted-keyring"
        windows.ensure_restricted_directory(keyring_dir)
        config = config.replace(
            b'[Keyring]\nBackend = "file"\n',
            f'[Keyring]\nBackend = "file"\nFileDir = {json.dumps(windows.canonical_path(keyring_dir))}\n'.encode(),
        )
        import hashlib
        state = (
            'phase = "configured"\n'
            f'installed_launch_template = {json.dumps(command)}\n'
            f'config_fingerprint = "unused"\nexecutable_path = {json.dumps(str(sidecar))}\n'
            f'supervisor_path = {json.dumps(str(supervisor))}\nuv_path = {json.dumps(uv)}\n'
            f'chromium_path = {json.dumps(str(chromium))}\nplaywright_version = "1.62.0"\n'
            'chromium_revision = "1234"\nprevious_custom_fragment = ""\nprevious_template_fragment = ""\n'
            f'installed_keyring_dir = {json.dumps(windows.canonical_path(keyring_dir))}\n'
            'keyring_credential_target = "granted-auto-auth/file-keyring-password/v1"\n'
            f'keyring_credential_hash = "{hashlib.sha256(self.keyring_password.encode()).hexdigest()}"\n'
            'keyring_credential_created = false\nkeyring_dir_created = true\nprevious_keyring_fragment = ""\n'
        ).encode()
        windows.ensure_restricted_directory(profile)
        windows.ensure_restricted_directory(state_dir)
        windows.ensure_restricted_directory(granted_dir)
        windows.write_secure_bytes(granted_dir / "config", config)
        windows.write_secure_bytes(state_dir / "install.toml", state)
        environment = os.environ.copy()
        environment["USERPROFILE"] = str(profile)
        environment["HOME"] = str(profile)
        environment["PATH"] = str(bin_dir) + os.pathsep + environment["PATH"]
        return environment

    def run_pwsh(self, command: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            text=True, capture_output=True, env=environment, timeout=30,
        )

    def test_v64_second_assume_uses_restored_helper_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.configured_environment(Path(temporary))
            environment.pop("GRANTED_AUTO_AUTH_REAL_ASSUMEGO", None)
            environment.pop("GRANTED_AUTO_AUTH_DEADLINE_NS", None)
            adapter = ROOT / "adapters/pwsh/assume.ps1"
            command = (
                f". '{adapter}'; $env:GRANTED_AUTO_AUTH_DRY_PROBE='1'; try {{"
                "assume __granted_auto_auth_dry_probe__ *> $null; "
                "$first=$env:ASSUME_STATUS; "
                "$firstReal=[Environment]::GetEnvironmentVariable('GRANTED_AUTO_AUTH_REAL_ASSUMEGO','Process') -eq $null; "
                "$firstDeadline=[Environment]::GetEnvironmentVariable('GRANTED_AUTO_AUTH_DEADLINE_NS','Process') -eq $null; "
                "assume __granted_auto_auth_dry_probe__ *> $null; "
                "$second=$env:ASSUME_STATUS} finally {Remove-Item Env:GRANTED_AUTO_AUTH_DRY_PROBE -ErrorAction SilentlyContinue}; "
                "@{first=$first; firstReal=$firstReal; firstDeadline=$firstDeadline; second=$second} | ConvertTo-Json -Compress"
            )
            result = self.run_pwsh(command, environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            values = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertEqual(values, {"first": "73", "firstReal": True, "firstDeadline": True, "second": "73"})

    def test_assume_applies_protocol_and_restores_scoped_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.configured_environment(Path(temporary))
            adapter = ROOT / "adapters/pwsh/assume.ps1"
            command = (
                f". '{adapter}'; $env:SSH_CLIENT='caller-ssh'; $env:CF_KEYRING_FILE_PASSWORD='caller-keyring'; "
                "assume /d /c 'echo GrantedAssume KEY SECRET TOKEN profile us-east-1 expiry sso start role region account None'; "
                "@{status=$env:ASSUME_STATUS; key=$env:AWS_ACCESS_KEY_ID; region=$env:AWS_DEFAULT_REGION; "
                "account=$env:GRANTED_SSO_ACCOUNT_ID; ssh=$env:SSH_CLIENT; filePassword=$env:CF_KEYRING_FILE_PASSWORD} | ConvertTo-Json -Compress"
            )
            result = self.run_pwsh(command, environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            values = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertEqual(values, {
                "status": "0", "key": "KEY", "region": "us-east-1",
                "account": "account", "ssh": "caller-ssh", "filePassword": "caller-keyring",
            }, result.stderr + result.stdout)

    def test_malformed_protocol_restores_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.configured_environment(Path(temporary))
            adapter = ROOT / "adapters/pwsh/assume.ps1"
            command = (
                f". '{adapter}'; $env:AWS_ACCESS_KEY_ID='original'; "
                "assume /d /c 'echo GrantedAssume incomplete'; "
                "@{status=$env:ASSUME_STATUS; key=$env:AWS_ACCESS_KEY_ID} | ConvertTo-Json -Compress"
            )
            result = self.run_pwsh(command, environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            values = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertEqual(values, {"status": "1", "key": "original"})

    def test_exec_is_emulated_without_forwarding_flag_to_granted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.configured_environment(Path(temporary))
            adapter = ROOT / "adapters/pwsh/assume.ps1"
            command = (
                f". '{adapter}'; $env:AWS_ACCESS_KEY_ID='original'; "
                "assume /d /c 'echo GrantedAssume KEY SECRET TOKEN profile us-east-1 expiry sso start role region account None' "
                "--exec -- pwsh -NoLogo -NoProfile -NonInteractive -Command 'Write-Output CHILD=$env:AWS_ACCESS_KEY_ID; exit 7'; "
                "@{status=$env:ASSUME_STATUS; key=$env:AWS_ACCESS_KEY_ID} | ConvertTo-Json -Compress"
            )
            result = self.run_pwsh(command, environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CHILD=KEY", result.stdout)
            values = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertEqual(values, {"status": "7", "key": "original"})

    def test_progress_output_does_not_corrupt_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.configured_environment(Path(temporary))
            adapter = ROOT / "adapters/pwsh/assume.ps1"
            command = (
                f". '{adapter}'; "
                "assume /d /c '(echo progress&& echo GrantedAssume KEY SECRET TOKEN profile us-east-1 expiry sso start role region account None)'; "
                "@{status=$env:ASSUME_STATUS; key=$env:AWS_ACCESS_KEY_ID} | ConvertTo-Json -Compress"
            )
            result = self.run_pwsh(command, environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            values = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertEqual(values, {"status": "0", "key": "KEY"})

    def test_v65_console_without_protocol_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.configured_environment(Path(temporary))
            adapter = ROOT / "adapters/pwsh/assume.ps1"
            command = (
                f". '{adapter}'; $env:AWS_ACCESS_KEY_ID='original'; "
                "assume -s rds /d /c 'echo [i] Opening a console for aprod in your browser...'; "
                "$service=$env:ASSUME_STATUS; "
                "assume --console /d /c 'echo [i] Opening a console for aprod in your browser...'; "
                "$console=$env:ASSUME_STATUS; "
                "@{service=$service; console=$console; key=$env:AWS_ACCESS_KEY_ID} | ConvertTo-Json -Compress"
            )
            result = self.run_pwsh(command, environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            values = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertEqual(values, {"service": "0", "console": "0", "key": "original"})

    def test_desume_clears_credentials_and_restores_scoped_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.configured_environment(Path(temporary))
            adapter = ROOT / "adapters/pwsh/assume.ps1"
            command = (
                f". '{adapter}'; $env:AWS_ACCESS_KEY_ID='original'; $env:CI='caller-ci'; "
                "assume /d /c 'echo GrantedDesume'; "
                "@{status=$env:ASSUME_STATUS; key=$env:AWS_ACCESS_KEY_ID; ci=$env:CI} | ConvertTo-Json -Compress"
            )
            result = self.run_pwsh(command, environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            values = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertEqual(values, {"status": "0", "key": "", "ci": "caller-ci"})

    def test_nested_half_context_fails_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.configured_environment(Path(temporary))
            environment["GRANTED_AUTO_AUTH_REAL_ASSUMEGO"] = str(Path(temporary) / "missing.exe")
            environment.pop("GRANTED_AUTO_AUTH_DEADLINE_NS", None)
            adapter = ROOT / "adapters/pwsh/assume.ps1"
            command = f". '{adapter}'; assume profile; $env:ASSUME_STATUS"
            result = self.run_pwsh(command, environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip().splitlines()[-1], "1")


if __name__ == "__main__":
    unittest.main()
