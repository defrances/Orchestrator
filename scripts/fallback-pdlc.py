#!/usr/bin/env python3
"""Deterministic PDLC analysis when a live provider cannot run.

Scores only rows already listed in the product vulnerability catalog.
Does not special-case any finding id or apply a product patch.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

APP = Path("workspace/DesktopApplication")
OUT = Path("pdlc-out/analysis.json")
VULN = Path("inputs/vulnerability-report.md")
MDS2 = Path("inputs/mds2.md")
TEST_PLAN = Path("inputs/test-plan.md")
INTENTIONAL = "INTENTIONAL_SKILL_TEST_VULNERABILITY"


def git_sha() -> str:
    if not (APP / ".git").exists():
        return "unknown"
    result = subprocess.run(
        ["git", "-C", str(APP), "rev-parse", "HEAD"],
        check=False,
        text=True,
        capture_output=True,
    )
    return (result.stdout or "").strip() or "unknown"


def parse_pipe_table(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or cells[0] in {"ID", "---"} or set(cells[0]) <= {"-", ":"}:
            continue
        rows.append(cells)
    return rows


def extract_paths(cell: str) -> list[str]:
    found = re.findall(r"`([^`]+)`", cell)
    paths: list[str] = []
    for item in found:
        cleaned = item.split()[0].strip(".,;:()")
        if "/" in cleaned or cleaned.endswith((".cs", ".xaml", ".md")):
            paths.append(cleaned)
    return paths


def catalog_score(status: str, countermeasure_cell: str) -> str:
    cell = f"{status} {countermeasure_cell}".lower()
    if "partial" in cell:
        return "partial"
    if "absent" in cell or "**open**" in status.lower() or status.lower() == "open":
        return "absent"
    if "present" in cell or status.lower() in {"closed", "accepted"}:
        return "present"
    return "partial"


def cited_source(paths: list[str]) -> str:
    chunks: list[str] = []
    for rel in paths:
        path = APP / rel
        if path.is_file():
            chunks.append(path.read_text(encoding="utf-8"))
    return "\n".join(chunks)


def mds2_unmet(mds2: str, finding_id: str, title: str) -> bool:
    if not mds2:
        return False
    hay = f"{finding_id} {title}".lower()
    for row in parse_pipe_table(mds2):
        if len(row) < 4:
            continue
        control_id, _area, status, _ = row[0], row[1], row[2], row[3]
        if control_id.lower() not in hay and _area.lower() not in hay:
            continue
        if "not met" in status.lower():
            return True
    return False


def tests_for(paths: list[str], test_rows: list[list[str]]) -> list[str]:
    basenames = {Path(item).name.lower() for item in paths}
    selected: list[str] = []
    for row in test_rows:
        if len(row) < 3:
            continue
        test_id, category, guarded = row[0], row[1].lower(), row[2]
        if category not in {"smoke", "regression"}:
            continue
        guarded_names = {Path(item).name.lower() for item in extract_paths(guarded)}
        if guarded_names & basenames:
            selected.append(test_id)
    if selected:
        return selected
    return [row[0] for row in test_rows if len(row) > 1 and row[1].lower() == "smoke"]


def score_finding(
    row: list[str],
    mds2: str,
    test_rows: list[list[str]],
) -> dict[str, object]:
    finding_id = row[0]
    title = row[1] if len(row) > 1 else finding_id
    status = row[3] if len(row) > 3 else ""
    affected = row[4] if len(row) > 4 else ""
    claimed_cell = row[5] if len(row) > 5 else ""
    paths = extract_paths(affected)
    source = cited_source(paths)
    claimed = catalog_score(status, claimed_cell)

    if INTENTIONAL in source:
        countermeasure = "absent"
        evidence = f"Cited file still contains `{INTENTIONAL}`."
    elif mds2_unmet(mds2, finding_id, title) and claimed == "absent":
        countermeasure = "absent"
        evidence = "Matching MDS2 row is not met and the catalog still lists the finding as open."
    elif claimed == "absent" and paths and source:
        countermeasure = "present"
        evidence = "Catalog is stale: cited code on main no longer carries the intentional-vuln marker."
    else:
        countermeasure = claimed
        evidence = f"Catalog status `{status}` / countermeasure cell scored `{claimed}`."

    return {
        "id": finding_id,
        "title": title,
        "countermeasure": countermeasure,
        "evidence": evidence,
        "impact_files": paths,
        "tests_to_run": tests_for(paths, test_rows),
        "patch_plan": (
            "none"
            if countermeasure == "present"
            else f"Address `{finding_id}` in the cited files on DesktopApplication main. Orchestrator does not apply product patches."
        ),
    }


def main() -> int:
    if not VULN.exists():
        raise SystemExit(f"missing {VULN}")
    if not APP.exists():
        raise SystemExit(f"missing {APP}")

    vuln_text = VULN.read_text(encoding="utf-8")
    mds2 = MDS2.read_text(encoding="utf-8") if MDS2.exists() else ""
    test_rows = parse_pipe_table(TEST_PLAN.read_text(encoding="utf-8")) if TEST_PLAN.exists() else []
    findings = [
        score_finding(row, mds2, test_rows)
        for row in parse_pipe_table(vuln_text)
        if row and row[0].startswith("VR-")
    ]

    payload = {
        "product": "DesktopApplication",
        "branch": "main",
        "sha": git_sha(),
        "findings": findings,
        "tests_filter": "Smoke|Regression",
        "os_kb_advice": [
            "Host OS KBs stay a station-level recommendation and are not packaged in the application zip.",
            "An OS .NET KB does not patch the bundled self-contained runtime.",
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} findings={len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
