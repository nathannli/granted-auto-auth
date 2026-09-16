#!/usr/bin/env -S uv run --script --locked --offline
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
import sys
import threading
import time
import tomllib
from ctypes import wintypes
from pathlib import Path

if os.name == "nt":
    import granted_auto_windows as windows


CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_UNICODE_ENVIRONMENT = 0x00000400
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
STILL_ACTIVE = 259
ERROR_BROKEN_PIPE = 109
KEYRING_CREDENTIAL_TARGET = "granted-auto-auth/file-keyring-password/v1"
KEYRING_PASSWORD_ENV = "CF_KEYRING_FILE_PASSWORD"


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateJobObjectW.restype = wintypes.HANDLE
kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID,
    wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
    wintypes.LPVOID, wintypes.LPVOID,
]
kernel32.GetStdHandle.restype = wintypes.HANDLE
kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
kernel32.CreatePipe.argtypes = [
    ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE), wintypes.LPVOID, wintypes.DWORD,
]
kernel32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
    )]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def close(handle: int | None) -> None:
    if handle:
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def fail(message: str) -> OSError:
    return OSError(ctypes.get_last_error(), message)


def set_job_limits(handle: int, flags: int) -> None:
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = flags
    if not kernel32.SetInformationJobObject(
        wintypes.HANDLE(handle), JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise fail("unable to configure process Job Object")


def create_job() -> int:
    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise fail("unable to create process Job Object")
    try:
        set_job_limits(int(handle), JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    except OSError:
        close(int(handle))
        raise
    return int(handle)


def create_pipe() -> tuple[int, int]:
    attributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
    read = wintypes.HANDLE()
    write = wintypes.HANDLE()
    if not kernel32.CreatePipe(ctypes.byref(read), ctypes.byref(write), ctypes.byref(attributes), 0):
        raise fail("unable to create process pipe")
    if not kernel32.SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0):
        close(int(read.value))
        close(int(write.value))
        raise fail("unable to protect process pipe")
    return int(read.value), int(write.value)


def copy_pipe(handle: int, stream) -> None:
    buffer = ctypes.create_string_buffer(65536)
    read = wintypes.DWORD()
    try:
        while kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None):
            if read.value:
                stream.write(buffer.raw[: read.value])
                stream.flush()
    finally:
        if ctypes.get_last_error() not in (0, ERROR_BROKEN_PIPE):
            pass
        close(handle)


def deadline_ns() -> int:
    try:
        value = int(os.environ["GRANTED_AUTO_AUTH_DEADLINE_NS"])
    except (KeyError, ValueError) as error:
        raise ValueError("shared authentication deadline is invalid") from error
    if value <= time.monotonic_ns():
        raise TimeoutError("authentication deadline expired")
    return value


def managed_keyring_password() -> str:
    state_path = Path.home() / ".config/granted-auto-auth/install.toml"
    try:
        state = tomllib.loads(windows.read_secure_bytes(state_path).decode())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise PermissionError("managed keyring install state is unavailable") from error
    if state.get("phase") != "configured" or state.get("keyring_credential_target") != KEYRING_CREDENTIAL_TARGET:
        raise PermissionError("managed keyring install state is invalid")
    configured_dir = state.get("installed_keyring_dir")
    if not isinstance(configured_dir, str):
        raise PermissionError("managed keyring directory is invalid")
    directory = windows.secure_open(Path(configured_dir), directory=True)
    try:
        if windows.canonical_handle_path(directory) != configured_dir:
            raise PermissionError("managed keyring directory identity changed")
    finally:
        windows.close_handle(directory)
    value = windows.credential_read(KEYRING_CREDENTIAL_TARGET)
    expected_hash = state.get("keyring_credential_hash")
    if not value or not isinstance(expected_hash, str) or hashlib.sha256(value.encode()).hexdigest() != expected_hash:
        raise PermissionError("managed keyring password is unavailable")
    return value


def run_with_managed_keyring(real: Path, arguments: list[str], deadline: int) -> int:
    existed = KEYRING_PASSWORD_ENV in os.environ
    previous = os.environ.get(KEYRING_PASSWORD_ENV)
    password = managed_keyring_password()
    try:
        os.environ[KEYRING_PASSWORD_ENV] = password
        return run(real, arguments, deadline)
    finally:
        if existed:
            os.environ[KEYRING_PASSWORD_ENV] = previous or ""
        else:
            os.environ.pop(KEYRING_PASSWORD_ENV, None)


def run(real: Path, arguments: list[str], deadline: int) -> int:
    job = create_job()
    stdout_read = stdout_write = stderr_read = stderr_write = None
    process = thread = None
    try:
        stdout_read, stdout_write = create_pipe()
        stderr_read, stderr_write = create_pipe()
        startup = STARTUPINFOW()
        startup.cb = ctypes.sizeof(startup)
        startup.dwFlags = STARTF_USESTDHANDLES
        startup.hStdInput = kernel32.GetStdHandle(-10)
        startup.hStdOutput = wintypes.HANDLE(stdout_write)
        startup.hStdError = wintypes.HANDLE(stderr_write)
        info = PROCESS_INFORMATION()
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(real), *arguments]))
        if not kernel32.CreateProcessW(
            str(real), command, None, None, True,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            None, str(real.parent), ctypes.byref(startup), ctypes.byref(info)
        ):
            raise fail("unable to create Granted process")
        process, thread = int(info.hProcess), int(info.hThread)
        if not kernel32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(process)):
            raise fail("unable to assign Granted process tree")
        if kernel32.ResumeThread(wintypes.HANDLE(thread)) == 0xFFFFFFFF:
            raise fail("unable to resume Granted process")
        close(thread)
        thread = None
        close(stdout_write)
        close(stderr_write)
        stdout_write = stderr_write = None
        readers = [
            threading.Thread(target=copy_pipe, args=(stdout_read, sys.stdout.buffer), daemon=True),
            threading.Thread(target=copy_pipe, args=(stderr_read, sys.stderr.buffer), daemon=True),
        ]
        stdout_read = stderr_read = None
        for reader in readers:
            reader.start()
        while True:
            remaining = deadline - time.monotonic_ns()
            if remaining <= 0:
                kernel32.TerminateJobObject(wintypes.HANDLE(job), 124)
                print("granted-auto-auth: authentication exceeded 180 seconds", file=sys.stderr)
                return 124
            wait = kernel32.WaitForSingleObject(wintypes.HANDLE(process), min(50, max(1, remaining // 1_000_000)))
            if wait == WAIT_OBJECT_0:
                status = wintypes.DWORD()
                if not kernel32.GetExitCodeProcess(wintypes.HANDLE(process), ctypes.byref(status)):
                    raise fail("unable to read Granted status")
                signed_status = ctypes.c_int32(status.value).value
                if signed_status == 0:
                    set_job_limits(job, 0)
                for reader in readers:
                    reader.join(timeout=1)
                return signed_status
            if wait != WAIT_TIMEOUT:
                raise fail("unable to wait for Granted process")
    except KeyboardInterrupt:
        kernel32.TerminateJobObject(wintypes.HANDLE(job), 130)
        return 130
    finally:
        close(thread)
        close(process)
        close(stdout_read)
        close(stdout_write)
        close(stderr_read)
        close(stderr_write)
        close(job)


def main(argv: list[str]) -> int:
    if os.name != "nt":
        print("granted-auto-auth: Windows supervisor requires Windows", file=sys.stderr)
        return 1
    if not argv:
        print("usage: granted_auto_auth_supervisor.py <absolute-assumego.exe> [args...]", file=sys.stderr)
        return 2
    real = Path(argv[0])
    if not real.is_absolute() or real.name.lower() != "assumego.exe" or not real.is_file():
        print("granted-auto-auth: invalid real assumego executable", file=sys.stderr)
        return 126
    try:
        deadline = deadline_ns()
        return run_with_managed_keyring(real.resolve(strict=True), argv[1:], deadline)
    except TimeoutError as error:
        print(f"granted-auto-auth: {error}", file=sys.stderr)
        return 124
    except Exception as error:
        print(f"granted-auto-auth: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
