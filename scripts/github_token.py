"""Load a GitHub token for local scripts. Never print the value."""

from __future__ import annotations

import json
import os
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
_ROOT = _SCRIPTS.parent
SECRETS_REL = Path(".secrets") / "github.json"
TOKEN_ENV = ("GITHUB_TOKEN", "GH_TOKEN", "ORCHESTRATOR_PAT")


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


def load(root: Path | None = None) -> str:
    for name in TOKEN_ENV:
        value = str(os.environ.get(name) or "").strip()
        if value:
            return value
    path = secrets_path(root)
    if not path.is_file():
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ""
    return _from_mapping(payload)


def write(token: str, root: Path | None = None) -> Path:
    path = secrets_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = str(token or "").strip()
    path.write_text(json.dumps({"token": text}, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path
