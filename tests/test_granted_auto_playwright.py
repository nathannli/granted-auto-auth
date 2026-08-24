from __future__ import annotations

import importlib.util
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
SIDECAR_PATH = ROOT / "scripts/granted_auto_browser.py"
SPEC = importlib.util.spec_from_file_location("granted_auto_browser_fixture", SIDECAR_PATH)
assert SPEC and SPEC.loader
sidecar = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sidecar
SPEC.loader.exec_module(sidecar)

from playwright.sync_api import Error as PlaywrightError, sync_playwright


PAGES = {
    "/username": """
        <label for="username">Username</label><input id="username">
        <button onclick="location='/password'">Next</button>
    """,
    "/password": """
        <label for="password">Password</label><input id="password" type="password">
        <button onclick="location='/totp'">Sign in</button>
    """,
    "/password-optional-challenge": """
        <p>You can use a security key instead.</p>
        <label for="password">Password</label><input id="password" type="password">
        <button onclick="sessionStorage.setItem('password_submit_count', Number(sessionStorage.getItem('password_submit_count') || 0) + 1); location='/approval-counted'">Sign in</button>
        <script>
            password.addEventListener('input', () => sessionStorage.setItem('password_fill_count', Number(sessionStorage.getItem('password_fill_count') || 0) + 1))
        </script>
    """,
    "/totp": """
        <label for="totp">MFA code</label><input id="totp">
        <button onclick="location='/approval'">Verify</button>
    """,
    "/combined": """
        <label for="username">Username</label><input id="username">
        <label for="password">Password</label><input id="password" type="password">
        <button onclick="location='/approval'">Sign in</button>
    """,
    "/approval": """
        <h1>Authorize Granted CLI</h1>
        <button onclick="location='/oauth/callback'">Allow access</button>
    """,
    "/approval-delayed": """
        <h1>Authorize Granted CLI</h1>
        <button onclick="location='/oauth/callback?delay=1'">Allow access</button>
    """,
    "/approval-status": """
        <h1>Authorize Granted CLI</h1>
        <button onclick="location='/authentication-status'">Allow access</button>
    """,
    "/approval-counted": """
        <h1>Authorize Granted CLI</h1>
        <p>A security key is another sign-in option.</p>
        <button onclick="sessionStorage.setItem('approval_count', Number(sessionStorage.getItem('approval_count') || 0) + 1); location='/oauth/callback'">Allow access</button>
    """,
    "/approval-expanded-name": """
        <h1>AWS access request</h1>
        <button>Show details</button>
        <button>Deny access</button>
        <button aria-label="Grant requested permissions to the application" onclick="location='/oauth/callback'">Allow access</button>
    """,
    "/authentication-status": """
        <h1>Authentication Status</h1>
        <script>setTimeout(() => location='/oauth/callback', 1000)</script>
    """,
    "/repeated-username": """
        <label for="username">Username</label><input id="username">
        <button onclick="location='/repeated-username'">Next</button>
    """,
    "/transient-unsupported": """
        <p>Checking security key availability.</p>
        <script>setTimeout(() => location='/approval', 100)</script>
    """,
    "/persistent-unsupported": """
        <p>Use your security key to continue.</p>
    """,
    "/unknown": "<h1>CAPTCHA required</h1>",
    "/timeout": "<h1>Waiting</h1>",
    "/oauth/callback": "<h1>Authentication Succeeded</h1>",
}


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/oauth/callback" and parsed.query == "delay=1":
            time.sleep(1)
        body = PAGES.get(path, "<h1>Unknown</h1>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class PlaywrightFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(headless=True)
        cls.credentials = sidecar.Credentials(
            "person@example.com", "password", "JBSWY3DPEHPK3PXP", "aws_identity_center"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def run_flow(self, path: str) -> None:
        page = self.browser.new_page()
        try:
            page.goto(self.base + path)
            sidecar.automate_aws_login(page, self.credentials, time.monotonic_ns() + 20_000_000_000)
            self.assertEqual(urlsplit(page.url).path, "/oauth/callback")
        finally:
            page.close()

    def test_fresh_username_password_totp_approval(self) -> None:
        self.run_flow("/username")

    def test_combined_username_password_form(self) -> None:
        self.run_flow("/combined")

    def test_remembered_username_password_form(self) -> None:
        self.run_flow("/password")

    def test_optional_challenge_copy_does_not_override_supported_controls(self) -> None:
        page = self.browser.new_page()
        try:
            page.goto(self.base + "/password-optional-challenge")
            original_context = page.context
            sidecar.automate_aws_login(page, self.credentials, time.monotonic_ns() + 20_000_000_000)
            self.assertIs(page.context, original_context)
            self.assertEqual(urlsplit(page.url).path, "/oauth/callback")
            self.assertEqual(page.evaluate("sessionStorage.getItem('password_fill_count')"), "1")
            self.assertEqual(page.evaluate("sessionStorage.getItem('password_submit_count')"), "1")
            self.assertEqual(page.evaluate("sessionStorage.getItem('approval_count')"), "1")
        finally:
            page.close()

    def test_optional_totp_is_skipped(self) -> None:
        self.run_flow("/combined")

    def test_existing_session_starts_at_approval(self) -> None:
        self.run_flow("/approval")

    def test_approval_accepts_visible_text_with_deny_control(self) -> None:
        self.run_flow("/approval-expanded-name")

    def test_delayed_callback_waits_after_approval(self) -> None:
        self.run_flow("/approval-delayed")

    def test_post_approval_intermediate_state_reaches_callback(self) -> None:
        self.run_flow("/approval-status")

    def test_repeated_state_fails_closed(self) -> None:
        page = self.browser.new_page()
        try:
            page.goto(self.base + "/repeated-username")
            with self.assertRaises(sidecar.AutoAuthError):
                sidecar.automate_aws_login(page, self.credentials, time.monotonic_ns() + 2_000_000_000)
        finally:
            page.close()

    def test_unknown_redirect_host_fails_closed(self) -> None:
        page = self.browser.new_page()
        try:
            page.route(
                "https://untrusted.example/**",
                lambda route: route.fulfill(content_type="text/html", body="<h1>Sign in</h1>"),
            )
            page.goto("https://untrusted.example/login")
            with self.assertRaises(sidecar.AutoAuthError):
                sidecar.automate_aws_login(page, self.credentials, time.monotonic_ns() + 5_000_000_000)
        finally:
            page.close()

    def test_browser_crash_propagates_failure(self) -> None:
        browser = self.playwright.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(self.base + "/timeout")
            browser.close(reason="simulated browser crash")
            with self.assertRaises(PlaywrightError):
                sidecar.automate_aws_login(page, self.credentials, time.monotonic_ns() + 5_000_000_000)
        finally:
            if browser.is_connected():
                browser.close()

    def test_adapter_error_propagates_failure(self) -> None:
        page = self.browser.new_page()
        try:
            page.goto(self.base + "/approval")
            with mock.patch.object(sidecar, "_click_approval", side_effect=sidecar.AutoAuthError("adapter failure")):
                with self.assertRaisesRegex(sidecar.AutoAuthError, "adapter failure"):
                    sidecar.automate_aws_login(page, self.credentials, time.monotonic_ns() + 5_000_000_000)
        finally:
            page.close()

    def test_unknown_challenge_fails_closed(self) -> None:
        page = self.browser.new_page()
        try:
            page.goto(self.base + "/unknown")
            with mock.patch.object(sidecar, "_wait_unsupported_candidate", wraps=sidecar._wait_unsupported_candidate) as wait:
                with self.assertRaises(sidecar.UnsupportedChallenge):
                    sidecar.automate_aws_login(page, self.credentials, time.monotonic_ns() + 5_000_000_000)
            wait.assert_not_called()
        finally:
            page.close()

    def test_transient_unsupported_candidate_recovers_in_place(self) -> None:
        page = self.browser.new_page()
        try:
            page.goto(self.base + "/transient-unsupported")
            deadline = time.monotonic_ns() + 20_000_000_000
            original_context = page.context
            with mock.patch.object(sidecar, "_wait_unsupported_candidate", wraps=sidecar._wait_unsupported_candidate) as wait:
                sidecar.automate_aws_login(page, self.credentials, deadline)
            wait.assert_called_once_with(page, deadline)
            self.assertIs(page.context, original_context)
            self.assertEqual(urlsplit(page.url).path, "/oauth/callback")
        finally:
            page.close()

    def test_persistent_unsupported_candidate_fails_after_one_recheck(self) -> None:
        page = self.browser.new_page()
        try:
            page.goto(self.base + "/persistent-unsupported")
            deadline = time.monotonic_ns() + 5_000_000_000
            with mock.patch.object(sidecar, "_wait_unsupported_candidate", wraps=sidecar._wait_unsupported_candidate) as wait:
                with self.assertRaises(sidecar.UnsupportedChallenge):
                    sidecar.automate_aws_login(page, self.credentials, deadline)
            wait.assert_called_once_with(page, deadline)
        finally:
            page.close()

    def test_v55_unknown_state_respects_shared_deadline(self) -> None:
        page = self.browser.new_page()
        try:
            page.goto(self.base + "/timeout")
            with self.assertRaises(sidecar.AuthTimeout):
                sidecar.automate_aws_login(page, self.credentials, time.monotonic_ns() + 100_000_000)
        finally:
            page.close()


if __name__ == "__main__":
    unittest.main()
