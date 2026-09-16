from __future__ import annotations

import ctypes
import os
import secrets
import time
from ctypes import wintypes
from pathlib import Path


if os.name != "nt":
    raise ImportError("granted_auto_windows is available only on Windows")


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.GetFileType.argtypes = [wintypes.HANDLE]
kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
kernel32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
kernel32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID]
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.LocalFree.restype = wintypes.HLOCAL
kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
advapi32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
advapi32.GetLengthSid.argtypes = [wintypes.LPVOID]
advapi32.GetLengthSid.restype = wintypes.DWORD
advapi32.GetSecurityInfo.argtypes = [
    wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
]
advapi32.GetSecurityInfo.restype = wintypes.DWORD
advapi32.GetAclInformation.argtypes = [wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_int]
advapi32.GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.DWORD),
]
advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID]

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
READ_CONTROL = 0x00020000
SYNCHRONIZE = 0x00100000
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
CREATE_NEW = 1
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_TYPE_DISK = 0x0001
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SE_FILE_OBJECT = 1
ACL_SIZE_INFORMATION_CLASS = 2
ACCESS_ALLOWED_ACE_TYPE = 0
INHERITED_ACE = 0x10
TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1
TH32CS_SNAPPROCESS = 0x00000002
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
ERROR_NO_MORE_FILES = 18
ERROR_LOCK_VIOLATION = 33
LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2
ERROR_NOT_FOUND = 1168
ERROR_FILE_EXISTS = 80
ERROR_ALREADY_EXISTS = 183
KEYRING_CREDENTIAL_TARGET = "granted-auto-auth/file-keyring-password/v1"


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]


class ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]


class ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [("Header", ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]


class TOKEN_USER(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


class CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", wintypes.LPVOID),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


advapi32.CredReadW.restype = wintypes.BOOL
advapi32.CredReadW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(ctypes.POINTER(CREDENTIALW)),
]
advapi32.CredWriteW.restype = wintypes.BOOL
advapi32.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIALW), wintypes.DWORD]
advapi32.CredDeleteW.restype = wintypes.BOOL
advapi32.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
advapi32.CredFree.argtypes = [wintypes.LPVOID]


def _raise_last_error(message: str) -> None:
    raise OSError(ctypes.get_last_error(), message)


def close_handle(handle: int | None) -> None:
    if handle not in (None, 0, INVALID_HANDLE_VALUE):
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def _open(
    path: Path, access: int, creation: int, directory: bool = False, share: int | None = None,
    inspect_reparse: bool = True,
) -> int:
    flags = (FILE_FLAG_OPEN_REPARSE_POINT if inspect_reparse else 0) | (
        FILE_FLAG_BACKUP_SEMANTICS if directory else FILE_ATTRIBUTE_NORMAL
    )
    sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE if share is None else share
    handle = kernel32.CreateFileW(
        str(path), access, sharing, None, creation, flags, None
    )
    if handle == INVALID_HANDLE_VALUE:
        _raise_last_error(f"unable to open {path.name}")
    return int(handle)


def _file_info(handle: int) -> BY_HANDLE_FILE_INFORMATION:
    info = BY_HANDLE_FILE_INFORMATION()
    if not kernel32.GetFileInformationByHandle(wintypes.HANDLE(handle), ctypes.byref(info)):
        _raise_last_error("unable to inspect file identity")
    return info


def file_identity(handle: int) -> tuple[int, int]:
    info = _file_info(handle)
    return info.dwVolumeSerialNumber, (info.nFileIndexHigh << 32) | info.nFileIndexLow


def canonical_handle_path(handle: int) -> str:
    size = kernel32.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), None, 0, 0)
    if not size:
        _raise_last_error("unable to resolve handle path")
    buffer = ctypes.create_unicode_buffer(size + 1)
    if not kernel32.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), buffer, len(buffer), 0):
        _raise_last_error("unable to resolve handle path")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.abspath(value))


def canonical_path(path: str | Path) -> str:
    handle = _open(Path(path), 0, OPEN_EXISTING, Path(path).is_dir(), inspect_reparse=False)
    try:
        return canonical_handle_path(handle)
    finally:
        close_handle(handle)


def _reject_reparse(handle: int) -> None:
    tag = FILE_ATTRIBUTE_TAG_INFO()
    if not kernel32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle), FILE_ATTRIBUTE_TAG_INFO_CLASS, ctypes.byref(tag), ctypes.sizeof(tag)
    ):
        _raise_last_error("unable to inspect reparse state")
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise PermissionError("reparse points are not allowed")


def _sid_bytes(sid: int) -> bytes:
    length = advapi32.GetLengthSid(wintypes.LPVOID(sid))
    if not length:
        _raise_last_error("unable to inspect SID")
    return ctypes.string_at(sid, length)


def _current_user_sid() -> bytes:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        _raise_last_error("unable to open process token")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, buffer, len(buffer), ctypes.byref(needed)):
            _raise_last_error("unable to read process token")
        return _sid_bytes(ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents.Sid)
    finally:
        close_handle(int(token.value))


def current_sid_string() -> str:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        _raise_last_error("unable to open process token")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, buffer, len(buffer), ctypes.byref(needed)):
            _raise_last_error("unable to read process token")
        text = wintypes.LPWSTR()
        sid = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents.Sid
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            _raise_last_error("unable to format current SID")
        try:
            return text.value
        finally:
            kernel32.LocalFree(text)
    finally:
        close_handle(int(token.value))


def _well_known_sid(value: str) -> bytes:
    pointer = wintypes.LPVOID()
    if not advapi32.ConvertStringSidToSidW(value, ctypes.byref(pointer)):
        _raise_last_error("unable to create trusted SID")
    try:
        return _sid_bytes(int(pointer.value))
    finally:
        kernel32.LocalFree(pointer)


def validate_acl(handle: int) -> None:
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    status = advapi32.GetSecurityInfo(
        wintypes.HANDLE(handle), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)
    )
    if status:
        raise OSError(status, "unable to read security descriptor")
    try:
        current = _current_user_sid()
        if _sid_bytes(int(owner.value)) != current:
            raise PermissionError("owner SID is invalid")
        if not dacl.value:
            raise PermissionError("null DACL is not allowed")
        trusted = {current, _well_known_sid("S-1-5-18"), _well_known_sid("S-1-5-32-544")}
        size = ACL_SIZE_INFORMATION()
        if not advapi32.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), ACL_SIZE_INFORMATION_CLASS):
            _raise_last_error("unable to inspect DACL")
        for index in range(size.AceCount):
            ace = wintypes.LPVOID()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                _raise_last_error("unable to inspect DACL entry")
            header = ctypes.cast(ace, ctypes.POINTER(ACE_HEADER)).contents
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE:
                continue
            allowed = ctypes.cast(ace, ctypes.POINTER(ACCESS_ALLOWED_ACE)).contents
            sid_address = int(ace.value) + ACCESS_ALLOWED_ACE.SidStart.offset
            if allowed.Mask and _sid_bytes(sid_address) not in trusted:
                raise PermissionError("DACL grants access to an untrusted principal")
    finally:
        kernel32.LocalFree(descriptor)


def secure_open(
    path: Path, *, directory: bool = False, writable: bool = False,
    create: bool = False, share_write: bool = False,
) -> int:
    access = READ_CONTROL | GENERIC_READ | (GENERIC_WRITE if writable else 0)
    sharing = FILE_SHARE_READ | (FILE_SHARE_WRITE if share_write else 0)
    handle = _open(path, access, OPEN_ALWAYS if create else OPEN_EXISTING, directory, sharing)
    try:
        if kernel32.GetFileType(wintypes.HANDLE(handle)) != FILE_TYPE_DISK:
            raise PermissionError("path is not a disk file")
        info = _file_info(handle)
        if bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory:
            raise PermissionError("path type is invalid")
        _reject_reparse(handle)
        validate_acl(handle)
        return handle
    except Exception:
        close_handle(handle)
        raise


def restrict_path(path: Path) -> None:
    descriptor = wintypes.LPVOID()
    sddl = f"O:{current_sid_string()}D:P(A;;FA;;;{current_sid_string()})(A;;FA;;;SY)(A;;FA;;;BA)"
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        _raise_last_error("unable to build restricted security descriptor")
    try:
        if not advapi32.SetFileSecurityW(
            str(path), OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor
        ):
            _raise_last_error(f"unable to restrict {path.name}")
    finally:
        kernel32.LocalFree(descriptor)


def ensure_restricted_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    restrict_path(path)
    handle = secure_open(path, directory=True)
    close_handle(handle)


def ensure_restricted_file(path: Path) -> None:
    ensure_restricted_directory(path.parent)
    created = False
    try:
        handle = _open(path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, CREATE_NEW, False, FILE_SHARE_READ | FILE_SHARE_WRITE)
        created = True
    except OSError as error:
        if (error.winerror or error.errno) not in (ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS):
            raise
        handle = secure_open(path, writable=True, share_write=True)
    try:
        if created:
            restrict_path(path)
            validate_acl(handle)
    finally:
        close_handle(handle)


def generate_keyring_password() -> str:
    return secrets.token_urlsafe(32)


def credential_read(target: str = KEYRING_CREDENTIAL_TARGET) -> str | None:
    pointer = ctypes.POINTER(CREDENTIALW)()
    if not advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
        error = ctypes.get_last_error()
        if error == ERROR_NOT_FOUND:
            return None
        raise OSError(error, "unable to read managed Windows credential")
    try:
        credential = pointer.contents
        if credential.Type != CRED_TYPE_GENERIC or credential.Persist != CRED_PERSIST_LOCAL_MACHINE:
            raise PermissionError("managed Windows credential metadata is invalid")
        if credential.UserName:
            raise PermissionError("managed Windows credential username is invalid")
        if not credential.CredentialBlob or not credential.CredentialBlobSize:
            raise PermissionError("managed Windows credential payload is invalid")
        data = ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
        try:
            value = data.decode("ascii")
        except UnicodeDecodeError as error:
            raise PermissionError("managed Windows credential payload is invalid") from error
        if len(value) < 43 or len(data) >= 2560 or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
            raise PermissionError("managed Windows credential payload is invalid")
        return value
    finally:
        advapi32.CredFree(pointer)


def credential_create(value: str, target: str = KEYRING_CREDENTIAL_TARGET) -> None:
    if credential_read(target) is not None:
        raise FileExistsError("managed Windows credential already exists")
    try:
        data = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("managed Windows credential payload is invalid") from error
    if len(value) < 43 or len(data) >= 2560 or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
        raise ValueError("managed Windows credential payload is invalid")
    blob = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    credential = CREDENTIALW()
    credential.Type = CRED_TYPE_GENERIC
    credential.TargetName = target
    credential.CredentialBlobSize = len(data)
    credential.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte))
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE
    credential.UserName = None
    if not advapi32.CredWriteW(ctypes.byref(credential), 0):
        _raise_last_error("unable to create managed Windows credential")


def credential_delete(target: str = KEYRING_CREDENTIAL_TARGET) -> None:
    if not advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
        error = ctypes.get_last_error()
        if error != ERROR_NOT_FOUND:
            raise OSError(error, "unable to delete managed Windows credential")


def write_secure_bytes(path: Path, data: bytes) -> None:
    ensure_restricted_directory(path.parent)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
    handle = _open(temporary, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, CREATE_NEW, False, FILE_SHARE_READ)
    try:
        restrict_path(temporary)
        written = wintypes.DWORD()
        if data and not kernel32.WriteFile(wintypes.HANDLE(handle), data, len(data), ctypes.byref(written), None):
            _raise_last_error(f"unable to write {path.name}")
        if written.value != len(data):
            raise OSError("short state write")
        if not kernel32.FlushFileBuffers(wintypes.HANDLE(handle)):
            _raise_last_error(f"unable to flush {path.name}")
    finally:
        close_handle(handle)
    try:
        os.replace(temporary, path)
        restrict_path(path)
        verified = secure_open(path)
        close_handle(verified)
    finally:
        temporary.unlink(missing_ok=True)


def read_secure_bytes(path: Path) -> bytes:
    parent = secure_open(path.parent, directory=True)
    handle: int | None = None
    try:
        expected_parent = canonical_handle_path(parent)
        if os.path.normcase(os.path.abspath(str(path.parent))) != expected_parent:
            raise PermissionError("parent path identity changed")
        handle = secure_open(path)
        size = _file_info(handle)
        length = (size.nFileSizeHigh << 32) | size.nFileSizeLow
        buffer = ctypes.create_string_buffer(length)
        read = wintypes.DWORD()
        if length and not kernel32.ReadFile(wintypes.HANDLE(handle), buffer, length, ctypes.byref(read), None):
            _raise_last_error(f"unable to read {path.name}")
        return buffer.raw[: read.value]
    finally:
        close_handle(handle)
        close_handle(parent)


def process_info(pid: int) -> tuple[int, str, str, int]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        _raise_last_error("unable to snapshot processes")
    parent = 0
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        found = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            if entry.th32ProcessID == pid:
                parent = int(entry.th32ParentProcessID)
                break
            found = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        close_handle(int(snapshot))
    if not parent and pid != 0:
        raise ProcessLookupError(pid)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, False, pid)
    if not handle:
        raise ProcessLookupError(pid)
    try:
        size = wintypes.DWORD(32768)
        path = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
            _raise_last_error("unable to read process image")
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time)):
            _raise_last_error("unable to read process creation time")
        stamp = f"{creation.dwHighDateTime}:{creation.dwLowDateTime}"
        return parent, stamp, canonical_path(path.value), int(handle)
    except Exception:
        close_handle(int(handle))
        raise


def process_handle_identity(handle: int) -> tuple[str, str]:
    size = wintypes.DWORD(32768)
    path = ctypes.create_unicode_buffer(size.value)
    if not kernel32.QueryFullProcessImageNameW(wintypes.HANDLE(handle), 0, path, ctypes.byref(size)):
        _raise_last_error("unable to read process image")
    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    if not kernel32.GetProcessTimes(
        wintypes.HANDLE(handle), ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time)
    ):
        _raise_last_error("unable to read process creation time")
    return f"{creation.dwHighDateTime}:{creation.dwLowDateTime}", canonical_path(path.value)


def process_alive(handle: int) -> bool:
    return kernel32.WaitForSingleObject(wintypes.HANDLE(handle), 0) == WAIT_TIMEOUT


def terminate_process(handle: int, status: int = 1) -> None:
    if process_alive(handle) and not kernel32.TerminateProcess(wintypes.HANDLE(handle), status):
        _raise_last_error("unable to terminate process")


def lock_file(path: Path, deadline: int, purpose: str = "browser profile") -> tuple[int, OVERLAPPED, int]:
    parent = secure_open(path.parent, directory=True)
    try:
        handle = secure_open(path, writable=True, share_write=True)
    except Exception:
        close_handle(parent)
        raise
    overlapped = OVERLAPPED()
    try:
        while True:
            if kernel32.LockFileEx(
                wintypes.HANDLE(handle), LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0, 1, 0, ctypes.byref(overlapped)
            ):
                return handle, overlapped, parent
            if ctypes.get_last_error() != ERROR_LOCK_VIOLATION:
                _raise_last_error(f"unable to lock {purpose}")
            remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise TimeoutError(f"{purpose} lock timed out")
            time.sleep(min(0.05, remaining))
    except Exception:
        close_handle(handle)
        close_handle(parent)
        raise


def unlock_file(handle: int, overlapped: OVERLAPPED, parent: int) -> None:
    kernel32.UnlockFileEx(wintypes.HANDLE(handle), 0, 1, 0, ctypes.byref(overlapped))
    close_handle(handle)
    close_handle(parent)
