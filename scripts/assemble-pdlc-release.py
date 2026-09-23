#!/usr/bin/env python3
"""Build PDLC_REPORT.md and a release zip from analysis + published app."""

from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ANALYSIS = Path("pdlc-out/analysis.json")
APP_DIR = Path("artifacts/app")
RELEASE_DIR = Path("artifacts/release")
REPORT = Path("pdlc-out/PDLC_REPORT.md")


def release_label() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = (os.environ.get("GITHUB_RUN_ID") or "").strip()
    return f"{stamp}-{run_id}" if run_id else stamp


def main() -> int:
    if not ANALYSIS.exists():
        raise SystemExit(f"missing {ANALYSIS}")
    data = json.loads(ANALYSIS.read_text(encoding="utf-8"))
    findings = data.get("findings") or []
    advice = data.get("os_kb_advice") or []
    sha = data.get("sha") or "unknown"
    version = release_label()

    lines = [
        "# PDLC report",
        "",
        f"- Product: `{data.get('product')}`",
        f"- Branch: `{data.get('branch')}`",
        f"- SHA: `{sha}`",
        f"- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"- Tests filter: `{data.get('tests_filter')}`",
        "",
        "## Findings",
        "",
    ]
    for item in findings:
        lines.extend(
            [
                f"### {item.get('id')} — {item.get('title')}",
                "",
                f"- Countermeasure: `{item.get('countermeasure')}`",
                f"- Patch plan: {item.get('patch_plan')}",
                f"- Tests: {', '.join(item.get('tests_to_run') or [])}",
                f"- Evidence: {item.get('evidence')}",
                "",
            ]
        )
    lines.extend(["## OS KB advice (not packaged)", "", *[f"- {row}" for row in advice], ""])
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    notes = [
        f"# DesktopApplication {version}",
        "",
        f"Tree from DesktopApplication `{sha}`.",
        "",
        "This zip is the application patch/release package.",
        "It does not contain Windows OS KBs.",
        "",
        "## Product findings",
    ]
    for item in findings:
        notes.append(f"- `{item.get('id')}`: countermeasure `{item.get('countermeasure')}`")
    notes.extend(["", "## OS KB advice", *[f"- {row}" for row in advice], ""])

    test_results = Path("artifacts/TEST_RESULTS.md")
    test_text = (
        test_results.read_text(encoding="utf-8")
        if test_results.exists()
        else "See the PDLC workflow log for `dotnet test` output.\n"
    )

    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = RELEASE_DIR / f"DesktopApplication-{version}-win-x64.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("PDLC_REPORT.md", REPORT.read_text(encoding="utf-8"))
        archive.writestr("RELEASE_NOTES.md", "\n".join(notes))
        archive.writestr("TEST_RESULTS.md", test_text)
        if APP_DIR.is_dir():
            for path in APP_DIR.rglob("*"):
                if path.is_file():
                    archive.write(path, arcname=path.name)
    print(f"wrote {REPORT} and {zip_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
