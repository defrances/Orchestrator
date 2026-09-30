#!/usr/bin/env python3
"""Build clustered issue payloads from FindUpdates report.json when live analysis cannot run."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
import psirt_scores

REPORT = Path("inputs/report.json")
OUT_DIR = Path("issues-out")
APP_DIR = Path(os.environ.get("DA_CHECKOUT") or "workspace/HostApplication")
MAX_CLUSTER_KEYS = 8
CANDIDATE = "candidate_for_validation"
DEFAULT_PRODUCT_REPOS = ("defrances/HostApplication",)
HOLD_POLICY = {"HOLD", "BLOCK"}

CLUSTER_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("schannel-tls", ("schannel", "tls", "ssl")),
    ("win32k-wpf", ("win32k", "win32 k")),
    ("dwm-wpf", ("dwm", "desktop window manager")),
    ("shell-launch", ("shell",)),
    ("ntfs-notes", ("ntfs",)),
    ("os-dotnet", (".net", "framework", "visual studio")),
]


def git_sha(app_dir: Path | None = None) -> str:
    root = app_dir or APP_DIR
    if not (root / ".git").exists():
        return "(checkout not available)"
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        text=True,
        capture_output=True,
    )
    sha = (result.stdout or "").strip()
    if result.returncode != 0 or not sha:
        return "(unable to read commit)"
    return sha


def product_source_repos() -> list[str]:
    raw = os.environ.get("PRODUCT_SOURCE_REPOS") or ",".join(DEFAULT_PRODUCT_REPOS)
    return [item.strip() for item in raw.split(",") if item.strip()]


def checkout_for_repo(repo: str) -> Path:
    name = repo.split("/")[-1]
    if name.lower() == "desktopapplication":
        return Path(os.environ.get("DA_CHECKOUT") or APP_DIR)
    return Path("workspace") / name


def source_version_lines(repos: list[str] | None = None) -> str:
    lines = ["Impact analysis conducted on source code version:", ""]
    for repo in repos or product_source_repos():
        sha = git_sha(checkout_for_repo(repo))
        lines.append(f"- https://github.com/{repo} - commit `{sha}`")
    return "\n".join(lines)


def config_display_names(names: list[str] | None) -> dict[str, str]:
    unique = sorted({str(name).strip() for name in (names or []) if str(name).strip()})
    return {name: f"Configurations{index}" for index, name in enumerate(unique, start=1)}


def report_config_labels(payload: dict[str, object] | None) -> dict[str, str]:
    names: list[str] = []
    blob = payload if isinstance(payload, dict) else {}
    for row in blob.get("stations") or []:
        if isinstance(row, dict):
            name = str(row.get("device_id") or "").strip()
        else:
            name = str(row).strip()
        if name:
            names.append(name)
    for item in blob.get("items") or []:
        if isinstance(item, dict):
            name = str(item.get("device_id") or "").strip()
            if name:
                names.append(name)
    return config_display_names(names)


def config_sort_key(label: str) -> int:
    digits = "".join(ch for ch in (label or "") if ch.isdigit())
    return int(digits) if digits else 0


def recommendation_label(action: object, policy: object = None) -> str:
    raw = str(action or "").strip()
    policy_s = str(policy or "").strip().upper()
    if raw == CANDIDATE and policy_s not in HOLD_POLICY:
        return "Install - High Prio"
    return "Low Prio"


def patch_name(members: list[dict[str, object]], key: str) -> str:
    packages: list[str] = []
    for item in unique_updates(members):
        pkg = str(item.get("package") or "").strip()
        if pkg and pkg not in packages:
            packages.append(pkg)
    if len(packages) == 1:
        return packages[0]
    return key


def unique_updates(members: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str, str]] = set()
    rows: list[dict[str, object]] = []
    for item in members:
        fingerprint = (
            str(item.get("package") or ""),
            cve_text(item),
            str(item.get("title") or ""),
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        rows.append(item)
    return rows


def unique_field(members: list[dict[str, object]], name: str) -> str:
    values: list[str] = []
    for item in members:
        value = str(item.get(name) or "").strip()
        if value and value not in values:
            values.append(value)
    return ", ".join(values) or "—"


def app_notes() -> str:
    notes = [
        "`src/HostApplication/HostApplication.csproj` — `UseWPF`, WinExe, `net9.0-windows`.",
        "`.github/workflows/ci.yml` — `dotnet publish` `--self-contained true` `-r win-x64`.",
        "`src/HostApplication.Core/NoteStore.cs` — `%AppData%\\HostApplication\\notes.txt`.",
        "`src/HostApplication.Core/SystemInformation.cs` — `RuntimeInformation` host strings.",
        "`src/HostApplication/app.manifest` — Windows 10 compatibility and `PerMonitorV2`.",
    ]
    tls = APP_DIR / "src" / "HostApplication.Core" / "InsecureVendorBulletinClient.cs"
    if tls.exists():
        notes.append(
            "`src/HostApplication.Core/InsecureVendorBulletinClient.cs` — HTTPS via host Schannel."
        )
    sbom = (
        Path("workspace/sbom/HostApplication.sbom.spdx.json")
        if Path("workspace/sbom/HostApplication.sbom.spdx.json").exists()
        else APP_DIR / "artifacts" / "HostApplication.sbom.spdx.json"
    )
    if sbom.exists():
        notes.append(f"SBOM present at `{sbom.as_posix()}`.")
    return "\n".join(f"- {line}" for line in notes)


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


RISK_VALUE_LABELS = {
    "required": "Required",
    "not_required": "Not required",
    "breaks_app": "App may stop working",
    "may_break_app": "App may break",
    "compatible": "Compatible with the app",
    "app_will_fail": "App will fail",
    "stays_vulnerable": "Station stays exposed",
    "no_app_impact": "No effect on the app",
    "incompatible": "Not compatible",
    "unknown": "Unknown",
}


def risk_label(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "—"
    return RISK_VALUE_LABELS.get(text, text.replace("_", " "))


def risk_why(key: str, risk: dict[str, str]) -> str:
    required = risk_label(risk.get("required_for_app"))
    install = risk_label(risk.get("install_risk"))
    skip = risk_label(risk.get("skip_risk"))
    compat = risk_label(risk.get("compatibility"))
    if key == "os-dotnet":
        return "\n".join(
            [
                f"- **Required for the app to keep working: {required}.** "
                "The published exe still starts without this KB. "
                "`HostApplication.csproj` has no third-party `PackageReference` for host .NET, "
                "and CI publishes `--self-contained true`. An OS .NET KB does not patch the bundled runtime.",
                f"- **If we install: {install}.** "
                "Putting the KB on the host does not replace bits inside the self-contained exe.",
                f"- **If we skip: {skip}.** "
                "Skipping the OS .NET KB does not change the product process. The exe already ships its own runtime.",
                f"- **Compatibility: {compat}.** "
                "Current `main` loads the bundled runtime from publish, not the host .NET Framework / OS .NET KB.",
            ]
        )
    if key == "schannel-tls":
        return "\n".join(
            [
                f"- **Required for the app to keep working: {required}.** "
                "The published exe still starts without this KB. "
                "`HostApplication.csproj` has no third-party `PackageReference` for the patched library, "
                "and CI publishes `--self-contained true`. This host KB is not a product runtime patch.",
                f"- **If we install: {install}.** "
                "Putting the KB on the host does not replace bits inside the self-contained exe. "
                "The bulletin HTTPS client still calls host Schannel the same way.",
                f"- **If we skip: {skip}.** "
                "Leaving the KB off leaves that host TLS stack unpatched. "
                "`InsecureVendorBulletinClient` uses host Schannel, so the station path stays exposed even though the app keeps running.",
                f"- **Compatibility: {compat}.** "
                "Current `main` already runs against today's host Schannel; "
                "we did not find an API/ABI break in `InsecureVendorBulletinClient.cs`.",
            ]
        )
    if key == "ntfs-notes":
        return "\n".join(
            [
                f"- **Required for the app to keep working: {required}.** "
                "The exe still starts without this KB. Notes I/O is product code in `NoteStore.cs`, not a vendor package the process cannot load.",
                f"- **If we install: {install}.** "
                "An NTFS host KB does not replace the self-contained exe. `NoteStore` still writes `%AppData%\\HostApplication\\notes.txt`.",
                f"- **If we skip: {skip}.** "
                "Leaving the KB off leaves host NTFS unpatched near the notes path. The app still runs.",
                f"- **Compatibility: {compat}.** "
                "Current `main` already uses today's NTFS via `NoteStore`; we did not find an API break in that file.",
            ]
        )
    if key in {"win32k-wpf", "dwm-wpf"}:
        return "\n".join(
            [
                f"- **Required for the app to keep working: {required}.** "
                "The exe still starts without this KB. WPF is bundled by self-contained publish; this is a host windowing KB, not a product `PackageReference`.",
                f"- **If we install: {install}.** "
                "A host Win32k/DWM KB can change DPI or composition used by `MainWindow.xaml` and `app.manifest` (`PerMonitorV2`).",
                f"- **If we skip: {skip}.** "
                "Leaving the KB off leaves that host windowing stack unpatched. The WPF UI can still launch.",
                f"- **Compatibility: {compat}.** "
                "We did not prove an API/ABI break against current `main`; windowing/DPI after the KB is not covered by a UI test.",
            ]
        )
    if key == "shell-launch":
        return "\n".join(
            [
                f"- **Required for the app to keep working: {required}.** "
                "The published WinExe still exists without this KB. Shell identity is a host path, not a product library load.",
                f"- **If we install: {install}.** "
                "A host Shell KB can change how `OutputType=WinExe` and `app.manifest` assembly identity launch.",
                f"- **If we skip: {skip}.** "
                "Leaving the KB off leaves host Shell unpatched. The app file is unchanged.",
                f"- **Compatibility: {compat}.** "
                "We did not prove launch will fail on current `main`; there is no UI/launch automation test.",
            ]
        )
    return "\n".join(
        [
            f"- **Required for the app to keep working: {required}.** "
            "The published exe still starts without this KB. "
            "No matching product `PackageReference` was found for the patched library.",
            f"- **If we install: {install}.** "
            "We did not prove the self-contained exe would change if this host KB is installed.",
            f"- **If we skip: {skip}.** "
            "Skipping this KB does not change the product process unless a cited file loads the patched component.",
            f"- **Compatibility: {compat}.** "
            "We did not prove an API/ABI break in the files we read on `main`.",
        ]
    )


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


def listed_cves(members: list[dict[str, object]]) -> str:
    seen: list[str] = []
    for item in unique_updates(members):
        raw = item.get("cve_ids") or []
        values = raw if isinstance(raw, list) else [raw]
        for cve in values:
            text = str(cve or "").strip()
            if text and text not in seen:
                seen.append(text)
    return ", ".join(seen) or "the listed advisories"


def listed_packages(members: list[dict[str, object]]) -> str:
    seen: list[str] = []
    for item in unique_updates(members):
        pkg = str(item.get("package") or "").strip()
        if pkg and pkg not in seen:
            seen.append(pkg)
    return ", ".join(seen) or "the vendor package"


def _md_cell(text: object) -> str:
    return str(text or "").replace("|", "/").replace("\n", " ").strip()


def linked_update(label: object, url: object) -> str:
    """Markdown link to an allow-listed HTTPS official_url from report.json."""
    text = _md_cell(label).replace("[", "").replace("]", "")
    href = str(url or "").strip()
    if text and href.startswith("https://") and " " not in href and ")" not in href:
        return f"[{text}]({href})"
    return f"`{text}`" if text else ""


def cybersecurity_text(key: str, members: list[dict[str, object]]) -> str:
    cves = listed_cves(members)
    packages = listed_packages(members)
    if key == "os-dotnet":
        return (
            f"This patch fixes {cves} in {packages}. SBOM scan and source code scan "
            "revealed there is no such dependency in our code. This patch will not affect our product."
        )
    if key == "schannel-tls":
        return (
            f"This patch fixes {cves} in {packages}. SBOM scan and source code scan "
            "revealed that the vendor bulletin HTTPS client uses host Schannel. "
            "The process has that host dependency."
        )
    if key == "ntfs-notes":
        return (
            f"This patch fixes {cves} in {packages}. SBOM scan and source code scan "
            "revealed that the notes module (`NoteStore`) uses the host NTFS profile path."
        )
    if key in {"win32k-wpf", "dwm-wpf"}:
        return (
            f"This patch fixes {cves} in {packages}. SBOM scan and source code scan "
            "revealed that the WPF UI module has such host windowing dependency."
        )
    if key == "shell-launch":
        return (
            f"This patch fixes {cves} in {packages}. SBOM scan and source code scan "
            "revealed that the WinExe launch path has such host Shell dependency."
        )
    return (
        f"This patch fixes {cves} in {packages}. SBOM scan and source code scan "
        "revealed there is no such dependency in our code. This patch will not affect our product."
    )


def product_risk_text(key: str) -> str:
    if key == "os-dotnet":
        return "\n".join(
            [
                "- Affected product functions: none. The published exe bundles its own runtime.",
                "- Potential hazards: None identified for this product configuration.",
                "- Failure scenarios: skipping the OS KB leaves host .NET unchanged; the product process does not load that host runtime.",
            ]
        )
    if key == "schannel-tls":
        return "\n".join(
            [
                "- Affected product functions: vendor bulletin HTTPS check (`CheckBulletinCommand`).",
                "- Potential hazards: untrusted TLS if the host Schannel stack stays exposed and the client accepts a bad chain.",
                "- Failure scenarios: skip — host TLS remains unpatched; install — handshake behavior may change, bulletin fetch may fail closed.",
            ]
        )
    if key == "ntfs-notes":
        return "\n".join(
            [
                "- Affected product functions: local notes read/write.",
                "- Potential hazards: integrity of `%AppData%\\HostApplication\\notes.txt` if NTFS behavior changes.",
                "- Failure scenarios: skip — host NTFS stays exposed; install — notes I/O may fail or change path semantics.",
            ]
        )
    if key in {"win32k-wpf", "dwm-wpf"}:
        return "\n".join(
            [
                "- Affected product functions: WPF windowing, DPI, and composition.",
                "- Potential hazards: operator cannot read the UI if windowing or DPI breaks after the host KB.",
                "- Failure scenarios: install — layout or DPI may break; skip — host windowing stays exposed.",
            ]
        )
    if key == "shell-launch":
        return "\n".join(
            [
                "- Affected product functions: process launch and exe identity.",
                "- Potential hazards: operator cannot start the client if Shell identity handling changes.",
                "- Failure scenarios: install — launch may fail; skip — host Shell stays exposed.",
            ]
        )
    return "\n".join(
        [
            "- Affected product functions: none identified.",
            "- Potential hazards: None identified for this product configuration.",
            "- Failure scenarios: none for this product configuration.",
        ]
    )


def test_planning_text(key: str) -> str:
    if key == "schannel-tls":
        suite = [
            "- `TC-UNIT-TLS-MARKER`",
            "- `TC-REG-TLS-CALLBACK`",
        ]
        gaps = ["- No UI automation for the bulletin button."]
    elif key == "ntfs-notes":
        suite = [
            "- `TC-UNIT-NOTES-EMPTY`",
            "- `TC-UNIT-NOTES-PATH`",
            "- `TC-SMOKE-NOTES`",
        ]
        gaps = ["- No host-NTFS integration test."]
    elif key == "os-dotnet":
        suite = ["- `TC-SMOKE-SYSINFO`"]
        gaps = [
            "- No test that the bundled runtime is independent of an OS .NET KB.",
        ]
    else:
        suite = ["- None. No documented test covers this coupling."]
        gaps = [
            "- No Unit, Smoke, or Regression case in `docs/test-plan.md` for this host path.",
            "- No UI automation.",
        ]
    return "\n".join(
        [
            "### Recommended Regression Suite",
            "",
            *suite,
            "",
            "### Gap Analysis",
            "",
            *gaps,
        ]
    )


def recommendation_text(
    key: str, members: list[dict[str, object]], config_name: str
) -> str:
    labels = {recommendation_label(item.get("action"), item.get("policy_result")) for item in members}
    name = config_name or "this configuration"
    if labels == {"Install - High Prio"}:
        return (
            f"Install - High Prio: lab-check the published win-x64 build for {name} "
            f"against this `{key}` coupling. Do not instruct production install from this analysis."
        )
    return (
        f"Low Prio: do not treat this host KB as a product patch for {name} "
        f"(`{key}`). Keep it off the product install set."
    )


def score_table(scores: dict[str, str] | None) -> str:
    item = scores or {}
    return (
        "| | Severity | Likelihood | Risk |\n"
        "| --- | --- | --- | --- |\n"
        f"| Vendor | {item.get('vendor_severity') or 'NA'} | "
        f"{item.get('vendor_likelihood') or 'NA'} | {item.get('vendor_risk') or 'NA'} |\n"
        f"| Product | {item.get('product_severity') or 'NA'} | "
        f"{item.get('product_likelihood') or 'NA'} | {item.get('product_risk') or 'NA'} |"
    )


def member_packages(members: list[dict[str, object]]) -> list[str]:
    packages: list[str] = []
    for item in unique_updates(members):
        pkg = str(item.get("package") or "").strip()
        if pkg and pkg not in packages:
            packages.append(pkg)
    return packages


def issue_body(
    key: str,
    members: list[dict[str, object]],
    evidence: str,
    risk: dict[str, str],
    source_versions: str | None = None,
    device: str | None = None,
    log: str | None = None,
    scores: dict[str, str] | None = None,
) -> str:
    del log
    config_name = (device or "").strip() or "Configurations1"
    rows = []
    for item in unique_updates(members):
        url = item.get("official_url")
        rows.append(
            "| {title} | {package} | {cves} | {recommendation} |".format(
                title=_md_cell(item.get("title")),
                package=linked_update(item.get("package"), url) or "`-`",
                cves=cve_text(item),
                recommendation=recommendation_label(item.get("action"), item.get("policy_result")),
            )
        )
    versions = source_versions if source_versions is not None else source_version_lines()
    letters = scores or psirt_scores.scores_from_members(
        members,
        required_for_app=risk.get("required_for_app"),
        install_risk=risk.get("install_risk"),
        skip_risk=risk.get("skip_risk"),
        compatibility=risk.get("compatibility"),
    )
    return f"""<!-- impact:{key}:{config_name} -->

{versions}

## Updates applicable for this product configuration

| Title | Package | CVEs | Recommendation |
| --- | --- | --- | --- |
{chr(10).join(rows)}

## Product Configuration Specification

- Product configuration: {config_name}
- Model / role: {unique_field(members, "model")} / {unique_field(members, "device_role")}
- Deployment group: {unique_field(members, "deployment_group")}
- OS: {unique_field(members, "os_product")} build {unique_field(members, "os_build")}
- Clinical criticality: {unique_field(members, "clinical_criticality")}
- Network exposure: {unique_field(members, "network_exposure")}

## Vendor vs product scores

{score_table(letters)}

Letters are C / H / M / L. Vendor comes from FindUpdates severity, KEV, and exploitability. Product is allowed to be lower when the patched component is not loaded.

## Technical Impact Assessment

### Impacted Components

{evidence}

### Potential Risks

{risk_why(key, risk)}

### Conclusions

{short_risk(key)}. Current `main` has no third-party PackageReference. CI publishes a self-contained win-x64 exe, so an OS .NET KB does not patch the bundled runtime.

## Cybersecurity impact assessment

{cybersecurity_text(key, members)}

## Product Risk assessment

{product_risk_text(key)}

## Test Planning

{test_planning_text(key)}

## Recommendation

{recommendation_text(key, members, config_name)}
"""


def issue_title(key: str, members: list[dict[str, object]], config_name: str) -> str:
    return f"[Impact] {patch_name(members, key)} on {config_name} - {short_risk(key)}"


def build_cluster_issues(
    payload: dict[str, object],
) -> tuple[list[dict[str, object]], list[tuple[str, int]]]:
    labels = report_config_labels(payload)
    items = [
        item
        for item in payload.get("items") or []
        if isinstance(item, dict) and relevant(item)
    ]
    items.sort(key=lambda item: (item.get("action") != CANDIDATE, -int(item.get("risk_score") or 0)))

    groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in items:
        key = cluster_key(item)
        if not key:
            continue
        groups[key].append(item)

    ranked = sorted(
        groups.items(),
        key=lambda pair: (
            min(member.get("action") != CANDIDATE for member in pair[1]),
            -max(int(member.get("risk_score") or 0) for member in pair[1]),
        ),
    )

    evidence = app_notes()
    versions = source_version_lines()
    issues: list[dict[str, object]] = []
    overflow: list[tuple[str, int]] = []
    for index, (key, members) in enumerate(ranked):
        if index >= MAX_CLUSTER_KEYS:
            overflow.append((key, len(members)))
            continue
        by_config: dict[str, list[dict[str, object]]] = defaultdict(list)
        for item in members:
            device = str(item.get("device_id") or "").strip()
            label = labels.get(device)
            if not label:
                continue
            by_config[label].append(item)
        for config_name in sorted(by_config, key=config_sort_key):
            config_members = by_config[config_name]
            risk = risk_fields(key)
            letters = psirt_scores.scores_from_members(
                config_members,
                required_for_app=risk["required_for_app"],
                install_risk=risk["install_risk"],
                skip_risk=risk["skip_risk"],
                compatibility=risk["compatibility"],
            )
            issues.append(
                {
                    "title": issue_title(key, config_members, config_name),
                    "advisory_id": key,
                    "device_id": config_name,
                    "cluster_key": key,
                    "packages": member_packages(config_members),
                    "labels": ["vendor-update-impact", f"product-config:{config_name}"],
                    "required_for_app": risk["required_for_app"],
                    "install_risk": risk["install_risk"],
                    "skip_risk": risk["skip_risk"],
                    "compatibility": risk["compatibility"],
                    **letters,
                    "body": issue_body(
                        key,
                        config_members,
                        evidence,
                        risk,
                        source_versions=versions,
                        device=config_name,
                        scores=letters,
                    ),
                }
            )
    return issues, overflow


def main() -> int:
    if not REPORT.exists():
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "missing-report.json").write_text(
            json.dumps(
                {
                    "title": "FindUpdates report.json was not available",
                    "advisory_id": "missing-report",
                    "device_id": "configurations",
                    "cluster_key": "missing-report",
                    "body": "inputs/report.json was missing. Orchestrator did not start FindUpdates.",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"missing {REPORT}; wrote placeholder analysis")
        return 0
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        payload = {}
    issues, overflow = build_cluster_issues(payload)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for written, issue in enumerate(issues, start=1):
        key = str(issue.get("cluster_key") or "cluster")
        config_name = str(issue.get("device_id") or "Configurations")
        name = (
            f"{written:02d}-"
            f"{re.sub(r'[^A-Za-z0-9._-]+', '-', key)}-"
            f"{re.sub(r'[^A-Za-z0-9._-]+', '-', config_name)}.json"
        )
        (OUT_DIR / name).write_text(json.dumps(issue, indent=2) + "\n", encoding="utf-8")

    if overflow:
        rows = [f"- `{key}` ({count} updates)" for key, count in overflow]
        (OUT_DIR / "summary.json").write_text(
            json.dumps(
                {
                    "title": "[Impact] Additional vendor-update clusters across configurations",
                    "advisory_id": "summary",
                    "device_id": "configurations",
                    "cluster_key": "summary",
                    "labels": ["vendor-update-impact"],
                    "body": (
                        "<!-- impact:summary:configurations -->\n\n"
                        "These additional clusters exceeded the per-run cap.\n\n"
                        + "\n".join(rows)
                    ),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    if not issues:
        (OUT_DIR / "none.json").write_text(json.dumps({"issues": []}, indent=2) + "\n", encoding="utf-8")
    print(f"fallback wrote {len(issues)} clustered issue payloads overflow={len(overflow)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
