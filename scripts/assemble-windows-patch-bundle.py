#!/usr/bin/env python3
"""Build a Windows patch bundle from a FindUpdates station_report.

The zip is a deployable *bundle* of host KBs (Linda's wording): one manifest,
per-KB descriptors, station lists, and APPLY.ps1. Official Microsoft/Intel
binaries are not redistributed; APPLY.ps1 opens the vendor URL or prints the
catalog id. HOLD/BLOCK rows stay out of the deploy set.
"""

from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPORT = Path(os.environ.get("REPORT_JSON", "inputs/report.json"))
OUT_DIR = Path(os.environ.get("BUNDLE_DIR", "artifacts/windows-bundle"))
FU_RUN = (os.environ.get("FU_RUN_ID") or "").strip()
FU_SOURCE = (os.environ.get("FU_SOURCE") or "").strip()
FU_URL = (os.environ.get("FU_HTML_URL") or "").strip()

CANDIDATE = "candidate_for_validation"
DO_NOT_INSTALL = "do_not_install"

APPLY_PS1 = r"""# Windows patch bundle applicator (PoC).
# Default is inventory-only. This is not an authorization to install.
param(
    [switch]$WhatIf = $true,
    [switch]$Apply
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifestPath = Join-Path $here "BUNDLE_MANIFEST.json"
$manifest = Get-Content -Raw -Path $manifestPath | ConvertFrom-Json

Write-Host "Bundle $($manifest.bundle_id)"
Write-Host "Authorization: $($manifest.authorization)"
Write-Host "Packages: $($manifest.counts.packages)  deploy=$($manifest.counts.deploy)  hold=$($manifest.counts.do_not_install)"

foreach ($pkg in $manifest.packages) {
    $mark = if ($pkg.include_in_deploy) { "DEPLOY" } else { "HOLD" }
    Write-Host ("[{0}] {1}  {2}  stations={3}" -f $mark, $pkg.kb, $pkg.action, ($pkg.stations -join ","))
    if ($pkg.official_url) {
        Write-Host ("        {0}" -f $pkg.official_url)
    }
}

if (-not $Apply) {
    Write-Host "WhatIf only. Re-run with -Apply to open official URLs for DEPLOY rows."
    exit 0
}

if ($manifest.authorization -ne "not_an_authorization") {
    throw "Refusing to apply: unexpected authorization field."
}

foreach ($pkg in $manifest.packages) {
    if (-not $pkg.include_in_deploy) { continue }
    if (-not $pkg.official_url) {
        Write-Host "Skip $($pkg.kb): no official_url"
        continue
    }
    Write-Host "Opening $($pkg.official_url)"
    Start-Process $pkg.official_url
}

Write-Host "Opened vendor pages. Install still requires a human and station policy."
"""


def _load_report(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"missing {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path} is not a JSON object")
    return data


def _items(report: dict) -> list[dict]:
    raw = report.get("items") or []
    return [row for row in raw if isinstance(row, dict)]


def _group_packages(items: list[dict]) -> list[dict]:
    buckets: dict[tuple[str, str], dict] = {}
    for row in items:
        kb = str(row.get("package") or "").strip() or "UNKNOWN"
        action = str(row.get("action") or DO_NOT_INSTALL).strip()
        key = (kb, action)
        slot = buckets.get(key)
        if slot is None:
            slot = {
                "kb": kb,
                "title": str(row.get("title") or kb),
                "vendor": str(row.get("vendor") or ""),
                "advisory_id": str(row.get("advisory_id") or ""),
                "official_url": row.get("official_url") or None,
                "cve_ids": [],
                "action": action,
                "include_in_deploy": action == CANDIDATE,
                "severity": str(row.get("severity") or ""),
                "stations": [],
                "deployment_groups": [],
                "os_products": [],
            }
            buckets[key] = slot
        device = str(row.get("device_id") or "").strip()
        if device and device not in slot["stations"]:
            slot["stations"].append(device)
        group = str(row.get("deployment_group") or "").strip()
        if group and group not in slot["deployment_groups"]:
            slot["deployment_groups"].append(group)
        product = str(row.get("os_product") or "").strip()
        if product and product not in slot["os_products"]:
            slot["os_products"].append(product)
        for cve in row.get("cve_ids") or []:
            text = str(cve).strip()
            if text and text not in slot["cve_ids"]:
                slot["cve_ids"].append(text)
    return sorted(buckets.values(), key=lambda item: (not item["include_in_deploy"], item["kb"]))


def _stations(items: list[dict]) -> list[dict]:
    by_device: dict[str, dict] = {}
    for row in items:
        device = str(row.get("device_id") or "").strip()
        if not device:
            continue
        slot = by_device.setdefault(
            device,
            {
                "device_id": device,
                "model": str(row.get("model") or ""),
                "device_role": str(row.get("device_role") or ""),
                "os_product": str(row.get("os_product") or ""),
                "os_build": row.get("os_build"),
                "deployment_group": str(row.get("deployment_group") or ""),
                "packages": [],
            },
        )
        kb = str(row.get("package") or "").strip()
        action = str(row.get("action") or "")
        if kb:
            entry = {"kb": kb, "action": action}
            if entry not in slot["packages"]:
                slot["packages"].append(entry)
    return sorted(by_device.values(), key=lambda item: item["device_id"])


def _readme(manifest: dict) -> str:
    lines = [
        "# Windows patch bundle",
        "",
        "This is the deployable **host patch bundle** for WBS item 3",
        "(`Create a patch package which needs to be deployed`): Windows KBs",
        "grouped the way Linda described — one bundle, not a client exe.",
        "",
        f"- Bundle id: `{manifest['bundle_id']}`",
        f"- Source: `{manifest.get('source') or 'unknown'}`",
        f"- FindUpdates run: `{manifest.get('findupdates_run_id') or 'n/a'}`",
        f"- Authorization: `{manifest['authorization']}`",
        "",
        "## Contents",
        "",
        "| File | Role |",
        "| --- | --- |",
        "| `BUNDLE_MANIFEST.json` | All KBs, stations, deploy vs hold |",
        "| `packages/*.json` | One descriptor per KB + action |",
        "| `stations/*.json` | Per-workstation list |",
        "| `APPLY.ps1` | Inventory (default) or open official URLs (`-Apply`) |",
        "",
        "Microsoft `.msu` / `.cab` files are **not** copied into this zip.",
        "The bundle points at official URLs. HOLD/BLOCK (`do_not_install`)",
        "stay in the manifest with `include_in_deploy: false`.",
        "",
        "## Deploy set",
        "",
    ]
    deploy = [pkg for pkg in manifest["packages"] if pkg["include_in_deploy"]]
    hold = [pkg for pkg in manifest["packages"] if not pkg["include_in_deploy"]]
    if deploy:
        for pkg in deploy:
            stations = ", ".join(pkg["stations"]) or "(none)"
            lines.append(f"- `{pkg['kb']}` — {pkg['title']} — {stations}")
    else:
        lines.append("- (no `candidate_for_validation` rows)")
    lines.extend(["", "## Held / do not install", ""])
    if hold:
        for pkg in hold:
            lines.append(f"- `{pkg['kb']}` — `{pkg['action']}`")
    else:
        lines.append("- (none)")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    report = _load_report(REPORT)
    items = _items(report)
    packages = _group_packages(items)
    stations = _stations(items)
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    source = FU_SOURCE or str(report.get("source") or "unknown")
    bundle_id = f"windows-patch-bundle-{source}-{stamp}"
    deploy = sum(1 for pkg in packages if pkg["include_in_deploy"])
    hold = len(packages) - deploy
    manifest = {
        "kind": "windows_patch_bundle",
        "schema_version": "1.0",
        "bundle_id": bundle_id,
        "generated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "authorization": "not_an_authorization",
        "source": source,
        "findupdates_run_id": FU_RUN or None,
        "findupdates_html_url": FU_URL or None,
        "report_kind": report.get("kind"),
        "report_item_count": report.get("item_count"),
        "counts": {
            "report_rows": len(items),
            "packages": len(packages),
            "deploy": deploy,
            "do_not_install": hold,
            "stations": len(stations),
        },
        "packages": packages,
        "stations": [row["device_id"] for row in stations],
    }

    staging = OUT_DIR / bundle_id
    if staging.exists():
        raise SystemExit(f"refusing to overwrite {staging}")
    (staging / "packages").mkdir(parents=True)
    (staging / "stations").mkdir(parents=True)
    (staging / "BUNDLE_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    (staging / "README.md").write_text(_readme(manifest), encoding="utf-8")
    (staging / "APPLY.ps1").write_text(APPLY_PS1, encoding="utf-8")
    for pkg in packages:
        name = f"{pkg['kb']}-{pkg['action']}.json".replace("/", "_")
        (staging / "packages" / name).write_text(
            json.dumps(pkg, indent=2) + "\n", encoding="utf-8"
        )
    for station in stations:
        (staging / "stations" / f"{station['device_id']}.json").write_text(
            json.dumps(station, indent=2) + "\n", encoding="utf-8"
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = OUT_DIR / f"{bundle_id}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in staging.rglob("*"):
            if path.is_file():
                archive.write(path, arcname=str(path.relative_to(staging)))
    print(f"wrote {zip_path} deploy={deploy} hold={hold} stations={len(stations)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
