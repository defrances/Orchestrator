#!/usr/bin/env python3
"""Build issue payloads from FindUpdates report.json when Copilot CLI cannot run."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPORT = Path("inputs/report.json")
OUT_DIR = Path("issues-out")
APP_DIR = Path("workspace/DesktopApplication")
MAX_ISSUES = 20
CANDIDATE = "candidate_for_validation"


def git_log() -> str:
    if not (APP_DIR / ".git").exists():
        return "(DesktopApplication checkout not available)"
    result = subprocess.run(
        ["git", "-C", str(APP_DIR), "log", "--oneline", "-12"],
        check=False,
        text=True,
        capture_output=True,
    )
    return (result.stdout or result.stderr or "").strip() or "(no git log)"


def app_notes() -> str:
    csproj = APP_DIR / "src" / "DesktopApplication" / "DesktopApplication.csproj"
    notes = ["DesktopApplication is a self-contained WPF client targeting net9.0-windows / win-x64."]
    if csproj.exists():
        text = csproj.read_text(encoding="utf-8")
        tfm = re.search(r"<TargetFramework>([^<]+)</TargetFramework>", text)
        if tfm:
            notes.append(f"Project TargetFramework is `{tfm.group(1)}`.")
    sbom = (
        Path("workspace/sbom/DesktopApplication.sbom.spdx.json")
        if Path("workspace/sbom/DesktopApplication.sbom.spdx.json").exists()
        else APP_DIR / "artifacts" / "DesktopApplication.sbom.spdx.json"
    )
    if sbom.exists():
        notes.append(f"SBOM present at `{sbom.as_posix()}`.")
    return " ".join(notes)


def relevant(item: dict[str, object]) -> bool:
    action = str(item.get("action") or "")
    os_product = str(item.get("os_product") or "").lower()
    title = f"{item.get('title', '')} {item.get('package', '')} {item.get('vendor', '')}".lower()
    if "windows" not in os_product and "windows" not in title and "microsoft" not in title:
        return False
    if action == CANDIDATE:
        return True
    if action == "do_not_install" and any(
        token in title for token in ("windows", ".net", "framework", "runtime", "reboot")
    ):
        return True
    return False


def issue_body(item: dict[str, object], evidence: str, log: str) -> str:
    advisory = str(item.get("advisory_id") or "")
    device = str(item.get("device_id") or "")
    cves = item.get("cve_ids") or []
    cve_text = ", ".join(str(cve) for cve in cves) if isinstance(cves, list) else str(cves)
    return f"""<!-- impact:{advisory}:{device} -->

## Update

- Advisory: `{advisory}`
- Title: {item.get("title")}
- Vendor: {item.get("vendor")}
- Package: `{item.get("package")}`
- CVEs: {cve_text or "none"}
- Action from FindUpdates: `{item.get("action")}`
- Policy: `{item.get("policy_result")}` (score {item.get("risk_score")}, severity `{item.get("severity")}`)
- Official source: {item.get("official_url") or "none"}

This issue is **not** an authorization to install, approve, or deploy. HOLD and BLOCK stay HOLD and BLOCK.

## Workstation

- Device: `{device}`
- Model / role: {item.get("model")} / {item.get("device_role")}
- Deployment group: `{item.get("deployment_group")}`
- OS: {item.get("os_product")} build {item.get("os_build")}
- Clinical criticality: {item.get("clinical_criticality")}
- Network exposure: {item.get("network_exposure")}

## How this can affect DesktopApplication

{item.get("explanation")}

{evidence}

A Windows / .NET OS update on this station can change the runtime, reboot behavior, or Win32/WPF stack used by the self-contained `DesktopApplication.exe`.

## Recent code that raises or lowers the risk

```
{log}
```

## Recommended reviewer action

Validate the published win-x64 build on `{device}` after the vendor package in a lab ring. Do not install from this issue.
"""


def main() -> int:
    if not REPORT.exists():
        raise SystemExit(f"missing {REPORT}")
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    items = [item for item in payload.get("items") or [] if isinstance(item, dict) and relevant(item)]
    items.sort(key=lambda item: (item.get("action") != CANDIDATE, -int(item.get("risk_score") or 0)))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    evidence = app_notes()
    log = git_log()
    written = 0
    seen: set[str] = set()
    for item in items:
        advisory = str(item.get("advisory_id") or "unknown")
        device = str(item.get("device_id") or "unknown")
        key = f"{advisory}:{device}:{item.get('title')}"
        if key in seen:
            continue
        seen.add(key)
        if written >= MAX_ISSUES:
            overflow = {
                "title": "[Impact] Additional vendor updates not filed individually",
                "advisory_id": "summary",
                "device_id": "overflow",
                "labels": ["vendor-update-impact"],
                "body": "Overflow from fallback analysis. See orchestrator-analysis artifact.",
            }
            (OUT_DIR / "summary.json").write_text(json.dumps(overflow, indent=2) + "\n", encoding="utf-8")
            break
        written += 1
        short = str(item.get("title") or "vendor update")[:80]
        issue = {
            "title": f"[Impact] {advisory} on {device} — {short}",
            "advisory_id": advisory,
            "device_id": device,
            "labels": ["vendor-update-impact", f"workstation:{device}"],
            "body": issue_body(item, evidence, log),
        }
        name = f"{written:02d}-{re.sub(r'[^A-Za-z0-9._-]+', '-', advisory)}-{device}.json"
        (OUT_DIR / name).write_text(json.dumps(issue, indent=2) + "\n", encoding="utf-8")

    if written == 0:
        (OUT_DIR / "none.json").write_text(json.dumps({"issues": []}, indent=2) + "\n", encoding="utf-8")
    print(f"fallback wrote {written} issue payloads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
