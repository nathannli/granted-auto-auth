#!/usr/bin/env -S uv run --script --locked --offline
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "playwright==1.62.0",
#   "pyotp==2.10.0",
# ]
# ///

from __future__ import annotations

import fcntl
import ctypes
import functools
import json
import os
import re
import signal
import stat
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pyotp
from playwright.sync_api import BrowserContext, Page, TimeoutError as PlaywrightTimeoutError, sync_playwright


EXIT_USAGE = 2
EXIT_SETUP = 3
EXIT_UNSUPPORTED = 4
EXIT_TIMEOUT = 5
EXIT_FAILURE = 6
PLAYWRIGHT_VERSION = "1.62.0"
EVENTS = {
    "start",
    "username",
    "password",
    "totp",
    "device_approve",
    "success",
    "unsupported_challenge",
    "timeout",
    "failure",
}
INITIAL_HOSTS = (
    re.compile(r"^oidc\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$"),
    re.compile(r"^device\.sso\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$"),
    re.compile(r"^d-[a-z0-9]+\.awsapps\.com$"),
)
REDIRECT_HOSTS = (
    re.compile(r"^[a-z0-9-]+\.signin\.aws$"),
    re.compile(r"^d-[a-z0-9]+\.awsapps\.com$"),
    re.compile(r"^oidc\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$"),
    re.compile(r"^device\.sso\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$"),
    re.compile(r"^(?:127\.0\.0\.1|localhost)$"),
)
UNSUPPORTED_TEXT = re.compile(
    r"captcha|security key|webauthn|push notification|device compliance|"
    r"reset your password|recover your account|change your password",
    re.IGNORECASE,
)
SUCCESS_TEXT = re.compile(
    r"authentication succe(?:ssful|eded)|authorization succe(?:ssful|eded)|"
    r"successfully authenticated|request (?:has been )?approved|access granted|"
    r"you can close (?:this )?(?:browser|window|tab)",
    re.IGNORECASE,
)
APPROVAL_BUTTON = re.compile(r"^(?:Confirm and continue|Allow access(?:\s+.*)?|Allow|Approve)$", re.IGNORECASE)
APPROVAL_CONTEXT = re.compile(r"authoriz|access request|requested access|approve", re.IGNORECASE)


class AutoAuthError(Exception):
    exit_code = EXIT_FAILURE
    event = "failure"


class SetupError(AutoAuthError):
    exit_code = EXIT_SETUP


class UnsupportedChallenge(AutoAuthError):
    exit_code = EXIT_UNSUPPORTED
    event = "unsupported_challenge"


class AuthTimeout(AutoAuthError):
    exit_code = EXIT_TIMEOUT
    event = "timeout"


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str
    totp_secret: str
    idp: str


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_time: str
    executable: str
    pidfd: int | None


class _DarwinBSDInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def emit(event: str, stage: str, adapter: str = "aws_identity_center") -> None:
    if event not in EVENTS:
        event = "failure"
    payload = {"event": event, "adapter": adapter, "stage": stage[:64]}
    print(json.dumps(payload, separators=(",", ":")), file=sys.stderr, flush=True)


def redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<redacted-url>"
    if not parsed.scheme or not parsed.netloc:
        return "<redacted-url>"
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def validate_initial_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise SetupError("invalid authorization URL") from error
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or not any(pattern.fullmatch(host) for pattern in INITIAL_HOSTS):
        raise SetupError("authorization URL host is not allowed")
    return value


def validate_redirect_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise AutoAuthError("invalid redirect URL") from error
    host = (parsed.hostname or "").lower()
    if not any(pattern.fullmatch(host) for pattern in REDIRECT_HOSTS):
        raise AutoAuthError("redirect host is not allowed")
    return host


def is_callback_url(value: str) -> bool:
    parsed = urlsplit(value)
    return (parsed.hostname or "").lower() in {"127.0.0.1", "localhost"} and parsed.path == "/oauth/callback"


def _validate_stat(path: Path, result: os.stat_result, allowed_mode: int) -> None:
    if not stat.S_ISREG(result.st_mode):
        raise SetupError(f"{path.name} is not a regular file")
    if result.st_uid != os.getuid():
        raise SetupError(f"{path.name} owner is invalid")
    if stat.S_IMODE(result.st_mode) & ~allowed_mode:
        raise SetupError(f"{path.name} permissions are too permissive")


def read_secure_toml(path: Path, allowed_mode: int = 0o600) -> dict[str, object]:
    parent = path.parent
    parent_stat = os.lstat(parent)
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise SetupError(f"{parent.name} is not a real directory")
    if parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & ~0o700:
        raise SetupError(f"{parent.name} permissions are too permissive")
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode):
        raise SetupError(f"{path.name} must not be a symlink")
    _validate_stat(path, before, allowed_mode)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        after = os.fstat(descriptor)
        _validate_stat(path, after, allowed_mode)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise SetupError(f"{path.name} changed while opening")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            return tomllib.load(stream)
    finally:
        os.close(descriptor)


def load_credentials(path: Path | None = None) -> Credentials:
    credentials_path = path or Path.home() / ".config/granted-auto-auth/credentials.toml"
    try:
        values = read_secure_toml(credentials_path)
    except (FileNotFoundError, tomllib.TOMLDecodeError) as error:
        raise SetupError(f"unable to load {credentials_path.name}") from error
    fields: dict[str, str] = {}
    for name in ("username", "password", "totp_secret", "idp"):
        value = values.get(name)
        if not isinstance(value, str) or not value.strip():
            raise SetupError(f"missing credential field: {name}")
        fields[name] = value.strip()
    if fields["idp"] != "aws_identity_center":
        raise SetupError("unsupported credential adapter")
    try:
        pyotp.TOTP(normalize_totp_secret(fields["totp_secret"])).at(0)
    except Exception as error:
        raise SetupError("invalid credential field: totp_secret") from error
    return Credentials(
        username=fields["username"],
        password=fields["password"],
        totp_secret=normalize_totp_secret(fields["totp_secret"]),
        idp=fields["idp"],
    )


def load_chromium_path(path: Path | None = None) -> str:
    state_path = path or Path.home() / ".config/granted-auto-auth/install.toml"
    try:
        state = read_secure_toml(state_path)
    except (FileNotFoundError, tomllib.TOMLDecodeError) as error:
        raise SetupError("unable to load install state") from error
    chromium = state.get("chromium_path")
    revision = state.get("chromium_revision")
    if state.get("phase") != "configured" or state.get("playwright_version") != PLAYWRIGHT_VERSION:
        raise SetupError("install state is not configured")
    if not isinstance(chromium, str) or not isinstance(revision, str) or not revision:
        raise SetupError("Chromium install state is invalid")
    executable = Path(chromium)
    if not executable.is_file() or not os.access(executable, os.X_OK) or f"chromium-{revision}" not in chromium:
        raise SetupError("Chromium revision does not match install state")
    return chromium


def normalize_totp_secret(value: str) -> str:
    return re.sub(r"[\s-]", "", value).upper()


def deadline_ns() -> int:
    value = os.environ.get("GRANTED_AUTO_AUTH_DEADLINE_NS", "")
    try:
        deadline = int(value)
    except ValueError as error:
        raise SetupError("shared authentication deadline is missing") from error
    if deadline <= time.monotonic_ns():
        raise AuthTimeout("authentication deadline expired")
    return deadline


def remaining_seconds(deadline: int) -> float:
    remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
    if remaining <= 0:
        raise AuthTimeout("authentication deadline expired")
    return remaining


def _proc_stat(pid: int) -> tuple[int, str]:
    raw = Path(f"/proc/{pid}/stat").read_text()
    tail = raw[raw.rfind(")") + 2 :].split()
    return int(tail[1]), tail[19]


@functools.lru_cache(maxsize=1)
def _darwin_libproc() -> ctypes.CDLL:
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    library.proc_pidinfo.restype = ctypes.c_int
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    return library


def _darwin_process_info(pid: int) -> tuple[int, str, str]:
    library = _darwin_libproc()
    info = _DarwinBSDInfo()
    size = ctypes.sizeof(info)
    if library.proc_pidinfo(pid, 3, 0, ctypes.byref(info), size) != size:
        raise ProcessLookupError(pid)
    path = ctypes.create_string_buffer(4096)
    if library.proc_pidpath(pid, path, len(path)) <= 0:
        raise ProcessLookupError(pid)
    executable = os.path.realpath(os.fsdecode(path.value))
    start_time = f"{info.pbi_start_tvsec}:{info.pbi_start_tvusec}"
    return int(info.pbi_ppid), start_time, executable


def _process_info(pid: int) -> tuple[int, str, str]:
    if sys.platform.startswith("linux"):
        parent, start_time = _proc_stat(pid)
        executable = os.path.realpath(os.readlink(f"/proc/{pid}/exe"))
        return parent, start_time, executable
    if sys.platform == "darwin":
        return _darwin_process_info(pid)
    raise SetupError(f"unsupported process platform: {sys.platform}")


def find_assumego_ancestor(expected_executable: str | None = None) -> ProcessIdentity:
    expected = os.path.realpath(expected_executable or os.environ.get("GRANTED_AUTO_AUTH_REAL_ASSUMEGO", ""))
    if not expected or not os.path.isfile(expected) or not os.access(expected, os.X_OK):
        raise SetupError("verified assumego executable is missing")
    pid = os.getppid()
    while pid > 1:
        try:
            parent, start_time, executable = _process_info(pid)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            break
        if executable == expected:
            try:
                pidfd = os.pidfd_open(pid) if sys.platform.startswith("linux") and hasattr(os, "pidfd_open") else None
            except OSError:
                pidfd = None
            return ProcessIdentity(pid, start_time, executable, pidfd)
        pid = parent
    raise SetupError("verified assumego ancestor is missing")


def process_matches(identity: ProcessIdentity) -> bool:
    try:
        _, start_time, executable = _process_info(identity.pid)
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return False
    return start_time == identity.start_time and executable == identity.executable


def process_alive(identity: ProcessIdentity) -> bool:
    if not process_matches(identity):
        return False
    try:
        os.kill(identity.pid, 0)
    except ProcessLookupError:
        return False
    return True


def _send_signal(identity: ProcessIdentity, sig: signal.Signals) -> None:
    if identity.pidfd is not None and hasattr(signal, "pidfd_send_signal"):
        signal.pidfd_send_signal(identity.pidfd, sig)
        return
    if process_matches(identity):
        os.kill(identity.pid, sig)


def cancel_process(identity: ProcessIdentity, deadline: int, immediate: bool = False) -> None:
    if not process_alive(identity):
        return
    if immediate or time.monotonic_ns() >= deadline:
        _send_signal(identity, signal.SIGKILL)
        return
    _send_signal(identity, signal.SIGTERM)
    stop = min(deadline, time.monotonic_ns() + 2_000_000_000)
    while process_alive(identity) and time.monotonic_ns() < stop:
        time.sleep(0.05)
    if process_alive(identity):
        _send_signal(identity, signal.SIGKILL)


def acquire_profile_lock(deadline: int, path: Path | None = None) -> int:
    lock_path = path or Path.home() / ".local/share/granted-auto-auth/browser.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(lock_path.parent, 0o700)
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            if remaining_seconds(deadline) <= 0.05:
                os.close(descriptor)
                raise AuthTimeout("browser profile lock timed out")
            time.sleep(min(0.05, remaining_seconds(deadline)))


def _visible(locator) -> bool:
    try:
        return locator.count() == 1 and locator.is_visible()
    except Exception:
        return False


def _any_visible(locator) -> bool:
    try:
        return any(locator.nth(index).is_visible() for index in range(locator.count()))
    except Exception:
        return False


def _blocking_unsupported_challenge(page: Page) -> bool:
    semantic_states = (
        page.get_by_role("heading").filter(has_text=UNSUPPORTED_TEXT),
        page.get_by_role("dialog").filter(has_text=UNSUPPORTED_TEXT),
        page.get_by_role("alert").filter(has_text=UNSUPPORTED_TEXT),
        page.get_by_label(UNSUPPORTED_TEXT),
    )
    return any(_any_visible(locator) for locator in semantic_states)


def _button_visible(page: Page, names: tuple[str, ...]) -> bool:
    return any(
        _visible(page.get_by_role("button", name=re.compile(rf"^{re.escape(name)}$", re.IGNORECASE)))
        for name in names
    )


def _click(page: Page, names: tuple[str, ...], deadline: int) -> bool:
    for name in names:
        locator = page.get_by_role("button", name=re.compile(rf"^{re.escape(name)}$", re.IGNORECASE))
        if _visible(locator):
            locator.click(timeout=min(5_000, remaining_seconds(deadline) * 1_000))
            return True
    return False


def _approval_visible(page: Page) -> bool:
    button = _approval_button(page)
    heading = page.get_by_role("heading").filter(has_text=APPROVAL_CONTEXT)
    deny = page.get_by_role("button", name=re.compile(r"^Deny access$", re.IGNORECASE))
    return button is not None and (_any_visible(heading) or _visible(deny))


def _approval_button(page: Page):
    named = page.get_by_role("button", name=APPROVAL_BUTTON)
    if _visible(named):
        return named
    visible_text = page.get_by_role("button").filter(
        has_text=re.compile(r"^\s*Allow access\s*$", re.IGNORECASE)
    )
    if _visible(visible_text):
        return visible_text
    return None


def _click_approval(page: Page, deadline: int) -> bool:
    button = _approval_button(page)
    heading = page.get_by_role("heading").filter(has_text=APPROVAL_CONTEXT)
    deny = page.get_by_role("button", name=re.compile(r"^Deny access$", re.IGNORECASE))
    if button is None or not (_any_visible(heading) or _visible(deny)):
        return False
    button.click(timeout=min(5_000, remaining_seconds(deadline) * 1_000))
    return True


def _wait_page(page: Page, deadline: int) -> None:
    page.wait_for_timeout(min(500, max(50, remaining_seconds(deadline) * 1_000)))
    validate_redirect_url(page.url)


def _wait_unsupported_candidate(page: Page, deadline: int) -> None:
    if remaining_seconds(deadline) < 0.5:
        raise AuthTimeout("not enough time to recheck unsupported challenge")
    page.wait_for_timeout(500)
    remaining_seconds(deadline)
    validate_redirect_url(page.url)


def _totp_now(secret: str, deadline: int) -> str:
    interval = 30
    remaining_window = interval - (time.time() % interval)
    if remaining_window < 5:
        wait = remaining_window + 0.1
        if wait >= remaining_seconds(deadline):
            raise AuthTimeout("not enough time for next TOTP window")
        time.sleep(wait)
    return pyotp.TOTP(secret).now()


def safe_control_stage(labels: list[str], credentials: Credentials) -> str:
    secrets = (credentials.username, credentials.password, credentials.totp_secret)
    cleaned: list[str] = []
    for label in labels[:4]:
        value = re.sub(r"[\r\n\t]+", " ", label).strip()
        for secret in secrets:
            if secret:
                value = value.replace(secret, "<redacted>")
        value = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "<redacted>", value, flags=re.IGNORECASE)
        value = re.sub(r"\s+", " ", value)[:48]
        if value:
            cleaned.append(value)
    return ("unknown_controls:" + ",".join(cleaned))[:64]


def automate_aws_login(page: Page, credentials: Credentials, deadline: int) -> None:
    page.goto(page.url, wait_until="domcontentloaded", timeout=remaining_seconds(deadline) * 1_000)
    completed: set[str] = set()
    unsupported_candidate = False
    for _ in range(12):
        if remaining_seconds(deadline) < 0.05:
            raise AuthTimeout("not enough time for next browser action")
        host = validate_redirect_url(page.url)
        if host in {"127.0.0.1", "localhost"} and is_callback_url(page.url):
            emit("success", "callback", credentials.idp)
            return
        body_text = page.locator("body").inner_text(timeout=min(3_000, remaining_seconds(deadline) * 1_000))
        username = page.get_by_label(re.compile(r"^Username$", re.IGNORECASE))
        password = page.get_by_label(re.compile(r"^Password$", re.IGNORECASE))
        totp = page.get_by_label(
            re.compile(r"^(MFA code|Authenticator code|Authentication code|One-time password|Verification code)$", re.IGNORECASE)
        )
        if _blocking_unsupported_challenge(page):
            raise UnsupportedChallenge("unsupported authentication challenge")
        supported_control = (
            ("username" not in completed and _visible(username))
            or ("password" not in completed and _visible(password))
            or ("totp" not in completed and _visible(totp))
            or ("approval" not in completed and _approval_visible(page))
        )
        if not supported_control and UNSUPPORTED_TEXT.search(body_text):
            if unsupported_candidate:
                raise UnsupportedChallenge("unsupported authentication challenge")
            unsupported_candidate = True
            _wait_unsupported_candidate(page, deadline)
            continue
        unsupported_candidate = False
        if "username" not in completed and _visible(username):
            emit("username", "username", credentials.idp)
            username.fill(credentials.username, timeout=min(5_000, remaining_seconds(deadline) * 1_000))
            if "password" not in completed and _visible(password):
                emit("password", "password", credentials.idp)
                password.fill(credentials.password, timeout=min(5_000, remaining_seconds(deadline) * 1_000))
                completed.add("password")
                submit_names = ("Sign in", "Next", "Continue")
            else:
                submit_names = ("Next", "Continue")
            if not _click(page, submit_names, deadline):
                raise AutoAuthError("username submit control is missing")
            completed.add("username")
            _wait_page(page, deadline)
            continue
        if "password" not in completed and _visible(password):
            emit("password", "password", credentials.idp)
            password.fill(credentials.password, timeout=min(5_000, remaining_seconds(deadline) * 1_000))
            if not _click(page, ("Sign in", "Next", "Continue"), deadline):
                raise AutoAuthError("password submit control is missing")
            completed.add("password")
            _wait_page(page, deadline)
            continue
        if "totp" not in completed and _visible(totp):
            emit("totp", "totp", credentials.idp)
            totp.fill(_totp_now(credentials.totp_secret, deadline), timeout=min(5_000, remaining_seconds(deadline) * 1_000))
            if not _click(page, ("Sign in", "Verify", "Next", "Continue"), deadline):
                raise AutoAuthError("TOTP submit control is missing")
            completed.add("totp")
            _wait_page(page, deadline)
            continue
        if "approval" not in completed and _click_approval(page, deadline):
            completed.add("approval")
            emit("device_approve", "approval", credentials.idp)
            try:
                page.wait_for_url(
                    re.compile(r"^http://(?:127\.0\.0\.1|localhost):\d+/"),
                    wait_until="domcontentloaded",
                    timeout=min(15_000, remaining_seconds(deadline) * 1_000),
                )
            except PlaywrightTimeoutError:
                _wait_page(page, deadline)
            continue
        if SUCCESS_TEXT.search(body_text):
            emit("success", "approval", credentials.idp)
            return
        page.wait_for_timeout(min(500, remaining_seconds(deadline) * 1_000))
    labels = [f"button:{value}" for value in page.get_by_role("button").all_inner_texts()]
    labels.extend(f"heading:{value}" for value in page.get_by_role("heading").all_inner_texts())
    raise UnsupportedChallenge(safe_control_stage(labels, credentials))


def run_browser(url: str, credentials: Credentials, deadline: int, chromium_path: str) -> None:
    profile = Path.home() / ".local/share/granted-auto-auth/browser"
    profile.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(profile, 0o700)
    with sync_playwright() as playwright:
        options: dict[str, object] = {
            "headless": True,
            "accept_downloads": False,
            "timeout": min(15_000, remaining_seconds(deadline) * 1_000),
        }
        options["executable_path"] = chromium_path
        context: BrowserContext = playwright.chromium.launch_persistent_context(profile, **options)
        try:
            page = context.pages[0] if context.pages else context.new_page()
            page.set_default_timeout(min(10_000, remaining_seconds(deadline) * 1_000))
            page.goto(url, wait_until="domcontentloaded", timeout=remaining_seconds(deadline) * 1_000)
            automate_aws_login(page, credentials, deadline)
        finally:
            context.close()


def close_identity(identity: ProcessIdentity | None) -> None:
    if identity and identity.pidfd is not None:
        os.close(identity.pidfd)


def main(argv: list[str]) -> int:
    # TODO: Revisit URL transport when Granted supports a non-argv custom-browser handoff.
    if len(argv) != 1:
        print("usage: granted_auto_browser.py <authorization-url>", file=sys.stderr)
        return EXIT_USAGE
    identity: ProcessIdentity | None = None
    lock_descriptor: int | None = None
    deadline = 0
    adapter = "aws_identity_center"
    try:
        try:
            url = validate_initial_url(argv[0])
            deadline = deadline_ns()
            identity = find_assumego_ancestor()
            emit("start", "launch", adapter)
            credentials = load_credentials()
            adapter = credentials.idp
            chromium_path = load_chromium_path()
            lock_descriptor = acquire_profile_lock(deadline)
            run_browser(url, credentials, deadline, chromium_path)
            while process_alive(identity):
                if remaining_seconds(deadline) <= 0.05:
                    raise AuthTimeout("Granted did not finish before deadline")
                time.sleep(min(0.05, remaining_seconds(deadline)))
            return 0
        except PlaywrightTimeoutError:
            error: AutoAuthError = AuthTimeout("browser action timed out")
        except AutoAuthError as caught:
            error = caught
        except Exception:
            error = AutoAuthError("unclassified browser automation failure")
        emit(error.event, str(error), adapter)
        if identity is not None:
            cancel_process(identity, deadline, immediate=isinstance(error, AuthTimeout))
        return error.exit_code
    finally:
        if lock_descriptor is not None:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            os.close(lock_descriptor)
        close_identity(identity)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
