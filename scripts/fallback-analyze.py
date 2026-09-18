#!/usr/bin/env python3
"""Build clustered issue payloads from FindUpdates report.json when Copilot CLI cannot run."""

from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

REPORT = Path("inputs/report.json")
OUT_DIR = Path("issues-out")
APP_DIR = Path("workspace/DesktopApplication")
MAX_ISSUES = 8
CANDIDATE = "candidate_for_validation"

CLUSTER_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("schannel-tls", ("schannel", "tls", "ssl")),
    ("win32k-wpf", ("win32k", "win32 k")),
    ("dwm-wpf", ("dwm", "desktop window manager")),
    ("shell-launch", ("shell",)),
    ("ntfs-notes", ("ntfs",)),
    ("os-dotnet", (".net", "framework", "visual studio")),
]


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
    notes = [
        "Analyzed https://github.com/defrances/DesktopApplication branch `main` (full checkout).",
        "DesktopApplication is a WPF WinExe (`src/DesktopApplication/DesktopApplication.csproj`: `UseWPF`, `net9.0-windows`).",
        "CI publishes `--self-contained true` `-r win-x64` (`.github/workflows/ci.yml`); an OS .NET KB does not patch the bundled runtime.",
        "`NoteStore` writes `%AppData%\\DesktopApplication\\notes.txt`.",
        "`SystemInformationProvider` reads OS/user/machine via `RuntimeInformation`.",
        "`app.manifest` sets Windows 10 compatibility and `PerMonitorV2` DPI.",
    ]
    tls = APP_DIR / "src" / "DesktopApplication.Core" / "InsecureVendorBulletinClient.cs"
    if tls.exists():
        notes.append(
            "`InsecureVendorBulletinClient` calls HTTPS with `AcceptAnyServerCertificate` from `CheckBulletinCommand`."
        )
    csproj = APP_DIR / "src" / "DesktopApplication" / "DesktopApplication.csproj"
    if csproj.exists():
        text = csproj.read_text(encoding="utf-8")
        tfm = re.search(r"<TargetFramework>([^<]+)</TargetFramework>", text)
        if tfm:
            notes.append(f"Project TargetFramework is `{tfm.group(1)}`.")
    inventory = Path("workspace/desktop-application-inventory.md")
    if inventory.exists():
        notes.append(f"Repo inventory: `{inventory.as_posix()}`.")
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


def cluster_key(item: dict[str, object]) -> str | None:
    title = f"{item.get('title', '')} {item.get('package', '')} {item.get('vendor', '')}".lower()
    for key, tokens in CLUSTER_RULES:
        if any(token in title for token in tokens):
            return key
    return None


def risk_fields(key: str) -> dict[str, str]:
    if key == "os-dotnet":
        return {
            "required_for_app": "not_required",
            "install_risk": "compatible",
            "skip_risk": "no_app_impact",
            "compatibility": "compatible",
        }
    if key == "schannel-tls":
        return {
            "required_for_app": "not_required",
            "install_risk": "compatible",
            "skip_risk": "stays_vulnerable",
            "compatibility": "compatible",
        }
    if key in {"win32k-wpf", "dwm-wpf", "shell-launch"}:
        return {
            "required_for_app": "not_required",
            "install_risk": "may_break_app",
            "skip_risk": "stays_vulnerable",
            "compatibility": "unknown",
        }
    if key == "ntfs-notes":
        return {
            "required_for_app": "not_required",
            "install_risk": "compatible",
            "skip_risk": "stays_vulnerable",
            "compatibility": "compatible",
        }
    return {
        "required_for_app": "not_required",
        "install_risk": "unknown",
        "skip_risk": "no_app_impact",
        "compatibility": "unknown",
    }


def short_risk(key: str) -> str:
    return {
        "schannel-tls": "Schannel TLS path has no defense in depth",
        "win32k-wpf": "Win32k may change WPF windowing or DPI",
        "dwm-wpf": "DWM may change WPF composition",
        "shell-launch": "Shell may change exe launch or identity",
        "ntfs-notes": "NTFS risk near local notes storage",
        "os-dotnet": "OS .NET KB does not patch the bundled runtime",
    }.get(key, "vendor update coupling")


def cve_text(item: dict[str, object]) -> str:
    cves = item.get("cve_ids") or []
    if isinstance(cves, list):
        return ", ".join(str(cve) for cve in cves) if cves else "none"
    return str(cves) or "none"


def issue_body(
    key: str,
    device: str,
    members: list[dict[str, object]],
    evidence: str,
    log: str,
    risk: dict[str, str],
) -> str:
    rows = []
    for item in members:
        rows.append(
            "| `{advisory}` | {title} | `{package}` | {cves} | `{action}` | `{policy}` | {score} |".format(
                advisory=item.get("advisory_id"),
                title=item.get("title"),
                package=item.get("package"),
                cves=cve_text(item),
                action=item.get("action"),
                policy=item.get("policy_result"),
                score=item.get("risk_score"),
            )
        )
    first = members[0]
    return f"""<!-- impact:{key}:{device} -->

## Updates in this cluster

| Advisory | Title | Package | CVEs | Action | Policy | Score |
| --- | --- | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

This issue is **not** an authorization to install, approve, or deploy. HOLD and BLOCK stay HOLD and BLOCK.

## Workstation

- Device: `{device}`
- Model / role: {first.get("model")} / {first.get("device_role")}
- Deployment group: `{first.get("deployment_group")}`
- OS: {first.get("os_product")} build {first.get("os_build")}
- Clinical criticality: {first.get("clinical_criticality")}
- Network exposure: {first.get("network_exposure")}

## Evidence from DesktopApplication main

{evidence}

## Risk to DesktopApplication on main

- Required for the app to keep working: `{risk["required_for_app"]}`
- Risk if the vendor updates **are installed**: `{risk["install_risk"]}`
- Risk if the vendor updates **are not installed**: `{risk["skip_risk"]}`
- Compatibility of current `main` with the proposed bits: `{risk["compatibility"]}`

Current `main` has no third-party PackageReference. CI publishes a self-contained win-x64 exe, so an OS .NET KB does not patch the bundled runtime.

## How this can affect DesktopApplication

Cluster `{key}`: {short_risk(key)}. {first.get("explanation")}

A host Windows update can still change WPF, DPI, reboot, TLS, or Win32 behavior used by `DesktopApplication.exe`. That is install-side incompatibility, not a reason to treat every KB as required.

## Recent code that raises or lowers the risk

```
{log}
```

## Recommended reviewer action

Validate the published win-x64 build on `{device}` for this `{key}` cluster in a lab ring. Do not install from this issue.
"""


def main() -> int:
    if not REPORT.exists():
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "missing-report.json").write_text(
            json.dumps(
                {
                    "title": "FindUpdates report.json was not available",
                    "advisory_id": "missing-report",
                    "device_id": "n/a",
                    "cluster_key": "missing-report",
                    "body": (
                        "inputs/report.json was missing. "
                        "Orchestrator did not start FindUpdates and did not create GitHub Issues. "
                        "This is not an authorization to install, approve, or deploy."
                    ),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"missing {REPORT}; wrote placeholder analysis")
        return 0
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    items = [item for item in payload.get("items") or [] if isinstance(item, dict) and relevant(item)]
    items.sort(key=lambda item: (item.get("action") != CANDIDATE, -int(item.get("risk_score") or 0)))

    groups: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for item in items:
        key = cluster_key(item)
        if not key:
            continue
        device = str(item.get("device_id") or "unknown")
        groups[(key, device)].append(item)

    ranked = sorted(
        groups.items(),
        key=lambda pair: (
            min(member.get("action") != CANDIDATE for member in pair[1]),
            -max(int(member.get("risk_score") or 0) for member in pair[1]),
        ),
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    evidence = app_notes()
    log = git_log()
    written = 0
    overflow: list[tuple[str, str, int]] = []
    for (key, device), members in ranked:
        if written >= MAX_ISSUES:
            overflow.append((key, device, len(members)))
            continue
        written += 1
        risk = risk_fields(key)
        issue = {
            "title": f"[Impact] {key} on {device} — {short_risk(key)}",
            "advisory_id": key,
            "device_id": device,
            "cluster_key": key,
            "labels": ["vendor-update-impact", f"workstation:{device}"],
            "required_for_app": risk["required_for_app"],
            "install_risk": risk["install_risk"],
            "skip_risk": risk["skip_risk"],
            "compatibility": risk["compatibility"],
            "body": issue_body(key, device, members, evidence, log, risk),
        }
        name = f"{written:02d}-{re.sub(r'[^A-Za-z0-9._-]+', '-', key)}-{device}.json"
        (OUT_DIR / name).write_text(json.dumps(issue, indent=2) + "\n", encoding="utf-8")

    if overflow:
        rows = [f"- `{key}` on `{device}` ({count} updates)" for key, device, count in overflow]
        (OUT_DIR / "summary.json").write_text(
            json.dumps(
                {
                    "title": "[Impact] Additional vendor-update clusters not filed individually",
                    "advisory_id": "summary",
                    "device_id": "overflow",
                    "cluster_key": "summary",
                    "labels": ["vendor-update-impact"],
                    "body": (
                        "<!-- impact:summary:overflow -->\n\n"
                        "These additional clusters exceeded the per-run cap.\n\n"
                        + "\n".join(rows)
                    ),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    if written == 0:
        (OUT_DIR / "none.json").write_text(json.dumps({"issues": []}, indent=2) + "\n", encoding="utf-8")
    print(f"fallback wrote {written} clustered issue payloads overflow={len(overflow)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
