from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER_PATH = ROOT / "scripts/granted-auto-auth"
LOADER = importlib.machinery.SourceFileLoader("granted_auto_controller", str(CONTROLLER_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC
controller = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(controller)
real_platform_health = controller.platform_health


class ControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.state_dir = self.home / ".config/granted-auto-auth"
        self.state_file = self.state_dir / "install.toml"
        self.granted_config = self.home / ".granted/config"
        self.aws_config = self.home / ".aws/config"
        self.sidecar = self.home / "repo/granted_auto_auth.py"
        self.lockfile = self.home / "repo/granted_auto_auth.py.lock"
        self.sidecar.parent.mkdir(parents=True)
        self.sidecar.write_text("#!/bin/sh\n")
        self.sidecar.chmod(0o755)
        self.lockfile.write_text("version = 1\n")
        self.granted_config.parent.mkdir(mode=0o700)
        self.granted_config.write_text('CustomSSOBrowserPath = ""\nUseAuthorizationCode = true\n')
        self.patches = (
            mock.patch.object(controller, "STATE_DIR", self.state_dir),
            mock.patch.object(controller, "STATE_FILE", self.state_file),
            mock.patch.object(controller, "CREDENTIALS_FILE", self.state_dir / "credentials.toml"),
            mock.patch.object(controller, "GRANTED_CONFIG", self.granted_config),
            mock.patch.object(controller, "AWS_CONFIG", self.aws_config),
            mock.patch.object(controller, "SCRIPTS_DIR", self.sidecar.parent),
            mock.patch.object(controller, "SIDECAR", self.sidecar),
            mock.patch.object(controller, "LOCKFILE", self.lockfile),
            mock.patch.object(controller, "platform_health", return_value=[]),
        )
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def write_config(self, browser: str) -> None:
        self.granted_config.write_text(f'CustomSSOBrowserPath = "{browser}"\nUseAuthorizationCode = true\n')

    def configured_state(self, chromium: Path) -> dict[str, object]:
        return {
            "phase": "configured",
            "previous_browser_path": "",
            "executable_path": str(self.sidecar),
            "chromium_path": str(chromium),
            "playwright_version": controller.PLAYWRIGHT_VERSION,
            "chromium_revision": "1234",
        }

    def test_state_write_is_atomic_and_private(self) -> None:
        controller.write_state({"phase": "prepared"})
        self.assertEqual(self.state_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(controller.read_secure_toml(self.state_file)["phase"], "prepared")

    def test_enabled_requires_complete_matching_state(self) -> None:
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        controller.write_state(self.configured_state(chromium))
        self.write_config(str(self.sidecar))
        self.assertTrue(controller.enabled())
        chromium.unlink()
        self.assertFalse(controller.enabled())

    def test_enabled_rejects_partial_install(self) -> None:
        controller.write_state({"phase": "chromium_ready"})
        self.assertFalse(controller.enabled())

    def test_enabled_rejects_unsupported_process_backend(self) -> None:
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        controller.write_state(self.configured_state(chromium))
        self.write_config(str(self.sidecar))
        with mock.patch.object(controller, "platform_health", return_value=["unsupported process platform: plan9"]):
            self.assertFalse(controller.enabled())

    def test_platform_health_dispatches_to_darwin(self) -> None:
        with mock.patch.object(controller.sys, "platform", "darwin"), mock.patch.object(
            controller, "_darwin_process_health", return_value=[]
        ) as probe:
            self.assertEqual(real_platform_health(), [])
        probe.assert_called_once_with()

    def test_linux_platform_health_rejects_non_ubuntu(self) -> None:
        release = self.home / "os-release"
        release.write_text('ID="fedora"\n')
        with mock.patch.object(controller, "OS_RELEASE", release):
            self.assertEqual(controller._linux_process_health(), ["unsupported Linux distribution: Ubuntu is required"])

    def test_secret_service_health_accepts_unlocked_default_collection(self) -> None:
        outputs = ['s ":1.42"', "u 1234", "b false"]
        with mock.patch.object(controller, "_busctl", side_effect=outputs) as bus, mock.patch.object(
            controller, "_secret_service_process", return_value=("/usr/bin/gnome-keyring-daemon", os.getuid())
        ):
            self.assertEqual(controller._secret_service_health(), [])
        self.assertEqual(bus.call_count, 3)
        self.assertEqual(bus.call_args_list[2].args[0][0], "get-property")
        self.assertEqual(bus.call_args_list[2].args[0][1], ":1.42")

    def test_secret_service_health_rejects_missing_service(self) -> None:
        with mock.patch.object(controller, "_busctl", side_effect=controller.ControllerError("missing")):
            self.assertEqual(controller._secret_service_health(), ["Secret Service is unavailable"])

    def test_secret_service_health_rejects_wrong_owner(self) -> None:
        with mock.patch.object(controller, "_busctl", side_effect=['s ":1.42"', "u 1234"]), mock.patch.object(
            controller, "_secret_service_process", return_value=("/usr/bin/not-a-wallet", os.getuid())
        ):
            self.assertEqual(
                controller._secret_service_health(), ["Secret Service owner is not the user gnome-keyring-daemon"]
            )

    def test_secret_service_health_rejects_missing_default_alias(self) -> None:
        with mock.patch.object(
            controller, "_busctl", side_effect=['s ":1.42"', "u 1234", controller.ControllerError("missing alias")]
        ), mock.patch.object(
            controller, "_secret_service_process", return_value=("/usr/bin/gnome-keyring-daemon", os.getuid())
        ):
            self.assertEqual(
                controller._secret_service_health(), ["Secret Service default collection is unavailable"]
            )

    def test_secret_service_health_rejects_locked_default_collection(self) -> None:
        with mock.patch.object(controller, "_busctl", side_effect=['s ":1.42"', "u 1234", "b true"]), mock.patch.object(
            controller, "_secret_service_process", return_value=("/usr/bin/gnome-keyring-daemon", os.getuid())
        ):
            self.assertEqual(controller._secret_service_health(), ["Secret Service default collection is locked"])

    def test_macos_platform_health_does_not_probe_secret_service(self) -> None:
        with mock.patch.object(controller.sys, "platform", "darwin"), mock.patch.object(
            controller, "_darwin_process_health", return_value=[]
        ), mock.patch.object(controller, "_secret_service_health") as wallet:
            self.assertEqual(real_platform_health(), [])
        wallet.assert_not_called()

    def test_install_orders_browser_before_setting(self) -> None:
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        events: list[str] = []

        def set_browser(value: str) -> None:
            self.assertEqual(controller.read_secure_toml(self.state_file)["phase"], "chromium_ready")
            events.append(value)
            self.write_config(value)

        with mock.patch.object(controller, "provision_chromium", return_value=(str(chromium), "1234")), mock.patch.object(
            controller, "set_custom_browser", side_effect=set_browser
        ):
            controller.install()
        self.assertEqual(events, [str(self.sidecar)])
        self.assertEqual(controller.read_secure_toml(self.state_file)["phase"], "configured")

    def test_install_failure_preserves_previous_setting(self) -> None:
        self.write_config("/previous/browser")
        with mock.patch.object(controller, "provision_chromium", side_effect=controller.ControllerError("failed")):
            with self.assertRaises(controller.ControllerError):
                controller.install()
        self.assertEqual(controller.custom_sso_browser_path(), "/previous/browser")
        self.assertFalse(self.state_file.exists())

    def test_install_is_idempotent(self) -> None:
        with mock.patch.object(controller, "enabled", return_value=True), mock.patch.object(
            controller, "recover_install_state"
        ) as recover, mock.patch.object(controller, "provision_chromium") as provision, mock.patch.object(
            controller, "set_custom_browser"
        ) as set_browser, mock.patch.object(controller, "sync_sidecar_runtime") as sync:
            controller.install()
        sync.assert_called_once_with()
        recover.assert_not_called()
        provision.assert_not_called()
        set_browser.assert_not_called()

    def test_install_migrates_owned_sidecar_path(self) -> None:
        legacy_sidecar = self.sidecar.parent / "granted_auto_legacy.py"
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        state = self.configured_state(chromium)
        state["executable_path"] = str(legacy_sidecar)
        controller.write_state(state)
        self.write_config(str(legacy_sidecar))

        def set_browser(value: str) -> None:
            self.write_config(value)

        with mock.patch.object(controller, "sync_sidecar_runtime") as sync, mock.patch.object(
            controller, "set_custom_browser", side_effect=set_browser
        ):
            controller.install()
        sync.assert_called_once_with()
        self.assertEqual(controller.custom_sso_browser_path(), str(self.sidecar))
        self.assertEqual(controller.read_secure_toml(self.state_file)["executable_path"], str(self.sidecar))

    def test_sync_sidecar_runtime_uses_locked_script_environment(self) -> None:
        with mock.patch.object(controller, "run_checked") as run:
            controller.sync_sidecar_runtime()
        self.assertEqual(
            run.call_args_list,
            [
                mock.call(["uv", "lock", "--check", "--script", str(self.sidecar)]),
                mock.call(["uv", "sync", "--locked", "--script", str(self.sidecar)]),
            ],
        )

    def test_install_crash_recovers_from_each_phase(self) -> None:
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        real_write = controller.write_state

        for phase in ("prepared", "chromium_ready", "configured"):
            with self.subTest(phase=phase):
                self.state_file.unlink(missing_ok=True)
                self.write_config("/previous/browser")

                def crash_after_write(values: dict[str, object], target: str = phase) -> None:
                    real_write(values)
                    if values.get("phase") == target:
                        raise RuntimeError(f"crash after {target}")

                def set_browser(value: str) -> None:
                    self.write_config(value)

                with mock.patch.object(controller, "write_state", side_effect=crash_after_write), mock.patch.object(
                    controller, "provision_chromium", return_value=(str(chromium), "1234")
                ), mock.patch.object(controller, "set_custom_browser", side_effect=set_browser):
                    with self.assertRaisesRegex(RuntimeError, f"crash after {phase}"):
                        controller.install()
                self.assertEqual(controller.custom_sso_browser_path(), "/previous/browser")
                if self.state_file.exists():
                    with mock.patch.object(controller, "set_custom_browser", side_effect=set_browser):
                        self.assertEqual(controller.recover_install_state(), "/previous/browser")
                self.assertFalse(self.state_file.exists())

    def test_install_rolls_back_when_setting_mutates_then_errors(self) -> None:
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        self.write_config("/previous/browser")

        def mutate_then_fail(value: str) -> None:
            self.write_config(value)
            if value == str(self.sidecar):
                raise controller.ControllerError("setting verification failed")

        with mock.patch.object(controller, "provision_chromium", return_value=(str(chromium), "1234")), mock.patch.object(
            controller, "set_custom_browser", side_effect=mutate_then_fail
        ):
            with self.assertRaisesRegex(controller.ControllerError, "setting verification failed"):
                controller.install()
        self.assertEqual(controller.custom_sso_browser_path(), "/previous/browser")
        self.assertFalse(self.state_file.exists())

    def test_failed_rollback_preserves_recovery_state(self) -> None:
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        self.write_config("/previous/browser")
        calls = 0

        def fail_restore(value: str) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                self.write_config(value)
                return
            raise controller.ControllerError("restore failed")

        real_write = controller.write_state

        def fail_configured_write(values: dict[str, object]) -> None:
            if values.get("phase") == "configured":
                raise RuntimeError("configured write failed")
            real_write(values)

        with mock.patch.object(controller, "provision_chromium", return_value=(str(chromium), "1234")), mock.patch.object(
            controller, "set_custom_browser", side_effect=fail_restore
        ), mock.patch.object(controller, "write_state", side_effect=fail_configured_write):
            with self.assertRaisesRegex(RuntimeError, "configured write failed"):
                controller.install()
        self.assertEqual(controller.custom_sso_browser_path(), str(self.sidecar))
        self.assertEqual(controller.read_secure_toml(self.state_file)["phase"], "chromium_ready")

    def test_missing_script_disables_and_failed_repair_restores_previous(self) -> None:
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        state = self.configured_state(chromium)
        state["previous_browser_path"] = "/previous/browser"
        controller.write_state(state)
        self.write_config(str(self.sidecar))
        self.sidecar.unlink()
        self.assertFalse(controller.enabled())

        def set_browser(value: str) -> None:
            self.write_config(value)

        with mock.patch.object(controller, "provision_chromium", side_effect=controller.ControllerError("script missing")), mock.patch.object(
            controller, "set_custom_browser", side_effect=set_browser
        ):
            with self.assertRaisesRegex(controller.ControllerError, "script missing"):
                controller.install()
        self.assertEqual(controller.custom_sso_browser_path(), "/previous/browser")
        self.assertFalse(self.state_file.exists())

    def test_missing_chromium_is_repaired_explicitly(self) -> None:
        missing = self.home / "chromium-1234/chrome"
        repaired = self.home / "chromium-5678/chrome"
        repaired.parent.mkdir()
        repaired.write_text("binary")
        repaired.chmod(0o755)
        state = self.configured_state(missing)
        state["previous_browser_path"] = "/previous/browser"
        controller.write_state(state)
        self.write_config(str(self.sidecar))
        self.assertFalse(controller.enabled())

        def set_browser(value: str) -> None:
            self.write_config(value)

        with mock.patch.object(controller, "provision_chromium", return_value=(str(repaired), "5678")), mock.patch.object(
            controller, "set_custom_browser", side_effect=set_browser
        ):
            controller.install()
        repaired_state = controller.read_secure_toml(self.state_file)
        self.assertEqual(repaired_state["phase"], "configured")
        self.assertEqual(repaired_state["chromium_path"], str(repaired))
        self.assertEqual(repaired_state["chromium_revision"], "5678")
        self.assertEqual(repaired_state["previous_browser_path"], "/previous/browser")
        self.assertTrue(controller.enabled())

    def test_uninstall_refuses_config_mismatch(self) -> None:
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        controller.write_state(self.configured_state(chromium))
        self.write_config("/other/browser")
        with self.assertRaises(controller.ControllerError):
            controller.uninstall()
        self.assertTrue(self.state_file.exists())

    def test_uninstall_disables_before_restore(self) -> None:
        chromium = self.home / "chromium-1234/chrome"
        chromium.parent.mkdir()
        chromium.write_text("binary")
        chromium.chmod(0o755)
        controller.write_state(self.configured_state(chromium))
        self.write_config(str(self.sidecar))

        def restore(value: str) -> None:
            self.assertEqual(controller.read_secure_toml(self.state_file)["phase"], "uninstalling")
            self.write_config(value)

        with mock.patch.object(controller, "set_custom_browser", side_effect=restore):
            controller.uninstall()
        self.assertFalse(self.state_file.exists())

    def test_recovery_restores_prior_setting_after_config_mutation(self) -> None:
        state = controller.base_state("/previous/browser")
        state["phase"] = "chromium_ready"
        controller.write_state(state)
        self.write_config(str(self.sidecar))

        def restore(value: str) -> None:
            self.write_config(value)

        with mock.patch.object(controller, "set_custom_browser", side_effect=restore):
            self.assertEqual(controller.recover_install_state(), "/previous/browser")
        self.assertEqual(controller.custom_sso_browser_path(), "/previous/browser")
        self.assertFalse(self.state_file.exists())

    def test_recovery_refuses_conflicting_partial_state(self) -> None:
        controller.write_state(controller.base_state("/previous/browser"))
        self.write_config("/unrelated/browser")
        with self.assertRaises(controller.ControllerError):
            controller.recover_install_state()

    def test_v56_legacy_profile_detection_ignores_sso_sessions(self) -> None:
        self.aws_config.parent.mkdir(mode=0o700)
        self.aws_config.write_text(
            "[sso-session modern]\nsso_start_url = https://example.awsapps.com/start\n"
            "sso_region = us-east-1\n"
            "[profile legacy]\nsso_start_url = https://example.awsapps.com/start\n"
            "[profile modern]\nsso_session = modern\n"
            "[default]\nsso_start_url = https://example.awsapps.com/start\n"
        )
        self.assertEqual(controller._legacy_profiles(), ["legacy", "default"])

    def test_doctor_warns_for_container_device_flow(self) -> None:
        marker = self.home / ".dockerenv"
        marker.touch()
        with mock.patch.object(controller, "CONTAINER_MARKER", marker), mock.patch.object(
            controller, "_credential_health", return_value=[]
        ), mock.patch.object(controller, "run_checked", return_value=mock.Mock(stdout="Granted 0.39.2")), mock.patch.object(
            controller, "granted_config", return_value={"UseAuthorizationCode": True, "DisableCredentialProcessCache": False}
        ), mock.patch.object(controller, "enabled", return_value=True), mock.patch.object(
            controller, "_legacy_profiles", return_value=[]
        ), mock.patch.object(
            controller, "platform_health", return_value=[]
        ), mock.patch("builtins.print") as output:
            self.assertEqual(controller.doctor(), 0)
        messages = [call.args[0] for call in output.call_args_list]
        self.assertIn("WARN: container detected: Granted may use device flow with legacy scopes", messages)

    def test_doctor_reports_platform_backend_failure(self) -> None:
        with mock.patch.object(controller, "_credential_health", return_value=[]), mock.patch.object(
            controller, "run_checked", return_value=mock.Mock(stdout="Granted 0.39.2")
        ), mock.patch.object(
            controller, "granted_config", return_value={"UseAuthorizationCode": True, "DisableCredentialProcessCache": False}
        ), mock.patch.object(controller, "enabled", return_value=True), mock.patch.object(
            controller, "_legacy_profiles", return_value=[]
        ), mock.patch.object(
            controller, "platform_health", return_value=["unsupported process platform: plan9"]
        ), mock.patch("builtins.print") as output:
            self.assertEqual(controller.doctor(), 1)
        messages = [call.args[0] for call in output.call_args_list]
        self.assertIn("FAIL: unsupported process platform: plan9", messages)

    def test_unknown_command_returns_usage(self) -> None:
        self.assertEqual(controller.main(["unknown"]), 2)


if __name__ == "__main__":
    unittest.main()
