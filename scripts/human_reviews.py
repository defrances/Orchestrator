"""Append-only human review overlay for GitHub Pages. Not an install authorization."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RISK_LETTERS = frozenset({"C", "H", "M", "L"})
REVIEWS_REL = Path("data") / "reviews.json"
REVIEWS_JS_REL = Path("assets") / "reviews.js"


def empty_store() -> dict[str, Any]:
    return {"entries": []}


def _iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def reviews_json_path(site: Path) -> Path:
    return site / REVIEWS_REL


def reviews_js_path(site: Path) -> Path:
    return site / REVIEWS_JS_REL


def find_reviews_file(history_dir: Path | None) -> Path | None:
    if history_dir is None:
        return None
    for candidate in (history_dir / REVIEWS_REL, history_dir / "reviews.json"):
        if candidate.is_file():
            return candidate
    return None


def load_store(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return empty_store()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"reviews JSON is invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("reviews JSON must be an object")
    entries = payload.get("entries")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise ValueError("reviews.entries must be a list")
    cleaned: list[dict[str, Any]] = []
    for item in entries:
        if isinstance(item, dict):
            cleaned.append(item)
    return {"entries": cleaned}


def write_store(site: Path, store: dict[str, Any]) -> None:
    json_path = reviews_json_path(site)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")
    js_path = reviews_js_path(site)
    js_path.parent.mkdir(parents=True, exist_ok=True)
    js_path.write_text(
        "window.SITE_REVIEWS = " + json.dumps(store) + ";\n",
        encoding="utf-8",
    )


def _letter(value: object, *, field: str, required: bool = False) -> str:
    raw = str(value or "").strip().upper()
    if raw in {"", "NA", "N/A", "—", "-"}:
        if required:
            raise ValueError(f"{field} is required")
        return ""
    if raw not in RISK_LETTERS:
        raise ValueError(f"{field} must be C, H, M, or L")
    return raw


def normalize_event(
    raw: dict[str, Any],
    *,
    previous: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    kb = str(raw.get("kb") or "").strip().upper()
    config = str(raw.get("config") or "").strip()
    comment = str(raw.get("comment") or "").strip()
    actor = str(raw.get("actor") or "").strip()
    run_id = str(raw.get("run_id") or "").strip()
    if not kb:
        raise ValueError("kb is required")
    if not config:
        raise ValueError("config is required")
    if not comment:
        raise ValueError("comment is required")
    if not actor:
        raise ValueError("actor is required")
    reviewed_raw = raw.get("reviewed", False)
    if isinstance(reviewed_raw, str):
        reviewed = reviewed_raw.strip().lower() in {"1", "true", "yes", "on"}
    else:
        reviewed = bool(reviewed_raw)
    risk_from = _letter(raw.get("product_risk_from"), field="product_risk_from")
    risk_to = _letter(raw.get("product_risk_to"), field="product_risk_to")
    if not risk_to:
        risk_to = risk_from
    risk_changed = risk_from != risk_to
    unreview = bool(previous and previous.get("reviewed") and not reviewed)
    if not reviewed and not risk_changed and not unreview:
        raise ValueError("mark Human reviewed or change Product risk")
    event_id = str(raw.get("id") or "").strip() or uuid.uuid4().hex
    stamp = str(raw.get("at") or "").strip() or (now or _iso())
    return {
        "id": event_id,
        "kb": kb,
        "config": config,
        "run_id": run_id,
        "reviewed": reviewed,
        "product_risk_from": risk_from,
        "product_risk_to": risk_to,
        "comment": comment,
        "actor": actor,
        "at": stamp,
    }


def append_event(store: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    entries = list(store.get("entries") or [])
    entries.append(event)
    return {"entries": entries}


def latest_for(store: dict[str, Any], kb: str, config: str) -> dict[str, Any] | None:
    needle_kb = str(kb or "").strip().upper()
    needle_cfg = str(config or "").strip()
    found: dict[str, Any] | None = None
    for item in store.get("entries") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("kb") or "").strip().upper() != needle_kb:
            continue
        if str(item.get("config") or "").strip() != needle_cfg:
            continue
        found = item
    return found
