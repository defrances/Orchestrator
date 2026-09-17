#!/usr/bin/env python3
"""Create DesktopApplication issues from Copilot JSON under issues-out/."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

APP_REPO = os.environ.get("APP_REPO", "defrances/DesktopApplication")
MAX_ISSUES = int(os.environ.get("MAX_ISSUES", "8"))
OUT_DIR = Path(os.environ.get("ISSUES_OUT_DIR", "issues-out"))
IMPACT_LABEL = "vendor-update-impact"
FINGERPRINT_RE = re.compile(r"<!--\s*impact:([^:]+):([^>]+?)\s*-->")


def gh(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    result = subprocess.run(
        ["gh", *args],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )
    if check and result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        result.check_returncode()
    return result


def ensure_label(name: str, color: str, description: str) -> None:
    result = gh(
        "label",
        "create",
        name,
        "--repo",
        APP_REPO,
        "--color",
        color,
        "--description",
        description,
        check=False,
    )
    if result.returncode != 0 and "already exists" not in (result.stderr + result.stdout).lower():
        # Updating an existing label is optional; ignore duplicate/permission noise.
        sys.stderr.write(result.stderr)


def load_issue_payloads(directory: Path) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    if not directory.is_dir():
        raise SystemExit(f"missing issue output directory: {directory}")

    files = sorted(directory.glob("*.json"))
    if not files:
        raise SystemExit(f"no JSON issue files in {directory}")

    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path} is not valid JSON: {exc}") from exc

        if isinstance(data, dict) and isinstance(data.get("issues"), list):
            items = data["issues"]
        elif isinstance(data, list):
            items = data
        else:
            items = [data]

        for item in items:
            if not isinstance(item, dict):
                raise SystemExit(f"{path} contains a non-object issue")
            if "token" in item:
                raise SystemExit(f"{path} contains a token field; refusing to publish")
            payloads.append(item)
    return payloads


def fingerprint(item: dict[str, object]) -> str:
    body = str(item.get("body") or "")
    match = FINGERPRINT_RE.search(body)
    if match:
        return f"{match.group(1).strip()}:{match.group(2).strip()}"
    cluster = str(item.get("cluster_key") or item.get("advisory_id") or "").strip()
    device = str(item.get("device_id") or "").strip()
    if cluster and device:
        return f"{cluster}:{device}"
    title = str(item.get("title") or "").strip()
    return title or json.dumps(item, sort_keys=True)


def existing_fingerprints() -> set[str]:
    result = gh(
        "issue",
        "list",
        "--repo",
        APP_REPO,
        "--label",
        IMPACT_LABEL,
        "--state",
        "all",
        "--limit",
        "200",
        "--json",
        "title,body",
    )
    found: set[str] = set()
    issues = json.loads(result.stdout or "[]")
    for issue in issues:
        title = str(issue.get("title") or "")
        body = str(issue.get("body") or "")
        match = FINGERPRINT_RE.search(body)
        if match:
            found.add(f"{match.group(1).strip()}:{match.group(2).strip()}")
            continue
        found.add(title.strip())
    return found


def workstation_label(device_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._:-]+", "-", device_id).strip("-")
    return f"workstation:{safe}"


def create_issue(item: dict[str, object]) -> str:
    title = str(item.get("title") or "").strip()
    body = str(item.get("body") or "").strip()
    advisory = str(item.get("cluster_key") or item.get("advisory_id") or "").strip()
    device = str(item.get("device_id") or "").strip()
    if not title or not body:
        raise SystemExit(f"issue is missing title or body: {item!r}")
    if advisory and device and f"<!-- impact:{advisory}:{device} -->" not in body:
        body = f"<!-- impact:{advisory}:{device} -->\n\n{body}"

    labels = {IMPACT_LABEL}
    raw_labels = item.get("labels") or []
    if isinstance(raw_labels, list):
        labels.update(str(label) for label in raw_labels if str(label).strip())
    if device:
        labels.add(workstation_label(device))

    for name in sorted(labels):
        color = "B60205" if name == IMPACT_LABEL else "0E8A16"
        ensure_label(name, color, "Created by Orchestrator vendor-impact analysis")

    args = [
        "issue",
        "create",
        "--repo",
        APP_REPO,
        "--title",
        title,
        "--body",
        body,
    ]
    labeled_args = list(args)
    for name in sorted(labels):
        labeled_args.extend(["--label", name])
    result = gh(*labeled_args, check=False)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        result = gh(*args)
    url = (result.stdout or "").strip()
    print(url)
    return url


def create_summary(overflow: list[dict[str, object]]) -> None:
    rows = []
    for item in overflow:
        rows.append(
            f"- `{item.get('advisory_id', '')}` on `{item.get('device_id', '')}`: "
            f"{item.get('title', '')}"
        )
    body = (
        "<!-- impact:summary:overflow -->\n\n"
        "These additional vendor-update impacts were identified in the same Orchestrator run "
        f"but exceeded the per-run cap of {MAX_ISSUES} individual issues.\n\n"
        "This is not an authorization to install, approve, or deploy. "
        "HOLD and BLOCK stay HOLD and BLOCK.\n\n"
        + "\n".join(rows)
    )
    create_issue(
        {
            "title": "[Impact] Additional vendor-update clusters not filed individually",
            "advisory_id": "summary",
            "device_id": "overflow",
            "labels": [IMPACT_LABEL],
            "body": body,
        }
    )


def main() -> int:
    if not os.environ.get("GH_TOKEN") and not os.environ.get("ORCHESTRATOR_PAT"):
        print("GH_TOKEN / ORCHESTRATOR_PAT is required to create issues.", file=sys.stderr)
        return 1

    ensure_label(
        IMPACT_LABEL,
        "B60205",
        "Vendor update may affect DesktopApplication on a workstation",
    )
    payloads = load_issue_payloads(OUT_DIR)
    if not payloads:
        print("No issue payloads from Copilot. Nothing to publish.")
        return 0
    seen_existing = existing_fingerprints()
    unique: list[dict[str, object]] = []
    seen_this_run: set[str] = set()
    for item in payloads:
        key = fingerprint(item)
        if key in seen_existing or key in seen_this_run:
            print(f"skip duplicate {key}")
            continue
        seen_this_run.add(key)
        unique.append(item)

    to_create = unique[:MAX_ISSUES]
    overflow = unique[MAX_ISSUES:]
    created = 0
    for item in to_create:
        create_issue(item)
        created += 1
    if overflow:
        create_summary(overflow)
        created += 1
    print(f"created={created} skipped={len(payloads) - len(unique)} overflow={len(overflow)}")
    if created == 0:
        print("No new impact issues. Copilot found no new workstation/application risks, or all were duplicates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
