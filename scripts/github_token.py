"""Load a GitHub token for local scripts. Never print the value."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
_ROOT = _SCRIPTS.parent
SECRETS_REL = Path(".secrets") / "github.json"
TOKEN_ENV = ("GITHUB_TOKEN", "GH_TOKEN", "ORCHESTRATOR_PAT")
CRED_TARGET = "defrances/Orchestrator/review-pat"
CRED_USERNAME = "github-pat"


def secrets_path(root: Path | None = None) -> Path:
    return (root or _ROOT) / SECRETS_REL


def _from_mapping(payload: object) -> str:
    if isinstance(payload, str):
        return payload.strip()
    if not isinstance(payload, dict):
        return ""
    for key in ("token", "github_token", "pat"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    return ""


def _os_read() -> str:
    if sys.platform != "win32":
        return ""
    try:
        return _windows_cred_read(CRED_TARGET)
    except OSError:
        return ""


def _os_write(token: str) -> bool:
    if sys.platform != "win32":
        return False
    text = str(token or "").strip()
    try:
        if not text:
            return _windows_cred_delete(CRED_TARGET)
        return _windows_cred_write(CRED_TARGET, CRED_USERNAME, text)
    except OSError:
        return False


def _windows_cred_write(target: str, username: str, secret: str) -> bool:
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    cred_type_generic = 1
    cred_persist_local_machine = 2
    blob = secret.encode("utf-16-le")
    blob_buf = ctypes.create_string_buffer(blob, len(blob))
    cred = CREDENTIAL()
    cred.Type = cred_type_generic
    cred.TargetName = target
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(blob_buf, ctypes.POINTER(ctypes.c_char))
    cred.Persist = cred_persist_local_machine
    cred.UserName = username
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    ok = advapi32.CredWriteW(ctypes.byref(cred), 0)
    return bool(ok)


def _windows_cred_read(target: str) -> str:
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    cred_type_generic = 1
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    ptr = ctypes.c_void_p()
    ok = advapi32.CredReadW(target, cred_type_generic, 0, ctypes.byref(ptr))
    if not ok or not ptr.value:
        return ""
    try:
        cred = ctypes.cast(ptr, ctypes.POINTER(CREDENTIAL)).contents
        size = int(cred.CredentialBlobSize)
        if size <= 0 or not cred.CredentialBlob:
            return ""
        raw = ctypes.string_at(cred.CredentialBlob, size)
        if len(raw) >= 2 and raw[1:2] == b"\x00":
            return raw.decode("utf-16-le").rstrip("\x00").strip()
        return raw.decode("utf-8").rstrip("\x00").strip()
    finally:
        advapi32.CredFree(ptr)


def _windows_cred_delete(target: str) -> bool:
    import ctypes

    cred_type_generic = 1
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    return bool(advapi32.CredDeleteW(target, cred_type_generic, 0))


def _from_json(root: Path | None) -> str:
    path = secrets_path(root)
    if not path.is_file():
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ""
    return _from_mapping(payload)


def load(root: Path | None = None) -> str:
    for name in TOKEN_ENV:
        value = str(os.environ.get(name) or "").strip()
        if value:
            return value
    if root is None:
        stored = _os_read()
        if stored:
            return stored
    return _from_json(root)


def write(token: str, root: Path | None = None) -> Path:
    path = secrets_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = str(token or "").strip()
    path.write_text(json.dumps({"token": text}, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    if root is None:
        _os_write(text)
    return path
