#!/usr/bin/env python3
"""Append one human-review event on a gh-pages checkout. Never logs tokens."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
import human_reviews


def _payload(args: argparse.Namespace) -> dict[str, object]:
    if args.payload_file:
        text = Path(args.payload_file).read_text(encoding="utf-8")
    elif args.payload_env:
        text = os.environ.get(args.payload_env) or ""
        if not text.strip():
            raise SystemExit(f"{args.payload_env} is empty")
    else:
        raise SystemExit("pass --payload-file, --payload-env, or --inbox")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise SystemExit("payload must be a JSON object")
    return data


def _ingest_inbox(site: Path, inbox: Path) -> int:
    actor = (os.environ.get("GITHUB_ACTOR") or "").strip()
    processed, errors = human_reviews.ingest_inbox(site, inbox, actor=actor)
    for line in errors:
        print(line, file=sys.stderr)
    for path in processed:
        path.unlink()
        print("ingested " + path.name, flush=True)
    print("ingested_count=" + str(len(processed)), flush=True)
    if errors and not processed:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", required=True, help="gh-pages checkout directory")
    parser.add_argument("--payload-file", default="")
    parser.add_argument("--payload-env", default="")
    parser.add_argument("--inbox", default="")
    args = parser.parse_args()
    site = Path(args.site).resolve()
    if args.inbox:
        if args.payload_file or args.payload_env:
            raise SystemExit("use --inbox alone")
        return _ingest_inbox(site, Path(args.inbox).resolve())
    raw = _payload(args)
    if not str(raw.get("actor") or "").strip():
        raw["actor"] = (os.environ.get("GITHUB_ACTOR") or "").strip()
    store = human_reviews.load_store(human_reviews.find_reviews_file(site))
    previous = human_reviews.latest_for(
        store,
        str(raw.get("kb") or ""),
        str(raw.get("config") or ""),
    )
    try:
        event = human_reviews.normalize_event(raw, previous=previous)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    store = human_reviews.append_event(store, event)
    human_reviews.write_store(site, store)
    print(
        f"recorded kb={event['kb']} config={event['config']} entries={len(store['entries'])}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
