#!/usr/bin/env python3
"""Build a static GitHub Pages site from one Orchestrator run. No AI."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
PAGES_DIR = _SCRIPTS / "pages"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
import psirt_scores

RETENTION_DAYS = 90
SKIP_ISSUE_NAMES = {"none.json", "missing-report.json", "summary.json", "ai-usage.json"}
TEST_SUMMARY_RE = re.compile(
    r"(Passed|Failed)!\s+-\s+Failed:\s+(\d+),\s+Passed:\s+(\d+),\s+Skipped:\s+(\d+),\s+Total:\s+(\d+)",
    re.IGNORECASE,
)
TEST_RUN_RE = re.compile(r"Test Run (Successful|Failed)\.", re.IGNORECASE)
TEST_TOTAL_RE = re.compile(r"Total tests:\s+(\d+)", re.IGNORECASE)
TEST_PASSED_RE = re.compile(r"^\s*Passed:\s+(\d+)", re.MULTILINE | re.IGNORECASE)
TEST_FAILED_RE = re.compile(r"^\s*Failed:\s+(\d+)", re.MULTILINE | re.IGNORECASE)
TEST_SKIPPED_RE = re.compile(r"^\s*Skipped:\s+(\d+)", re.MULTILINE | re.IGNORECASE)
HEAD_RE = re.compile(r"HEAD:\s+`([0-9a-f]{7,40})`", re.IGNORECASE)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    stamp = value or _now()
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _read_json(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _first_file(root: Path, name: str) -> Path | None:
    if not root.exists():
        return None
    if (root / name).is_file():
        return root / name
    matches = sorted(root.rglob(name))
    return matches[0] if matches else None


def _first_dir(root: Path, name: str) -> Path | None:
    if not root.exists():
        return None
    if (root / name).is_dir():
        return root / name
    matches = sorted(path for path in root.rglob(name) if path.is_dir())
    return matches[0] if matches else None


def parse_test_results(text: str) -> dict[str, object]:
    blob = text or ""
    match = TEST_SUMMARY_RE.search(blob)
    if match:
        return {
            "outcome": match.group(1).lower(),
            "failed": int(match.group(2)),
            "passed": int(match.group(3)),
            "skipped": int(match.group(4)),
            "total": int(match.group(5)),
            "filter": "Smoke|Regression",
        }
    run = TEST_RUN_RE.search(blob)
    total = TEST_TOTAL_RE.search(blob)
    if run and total:
        passed = TEST_PASSED_RE.search(blob)
        failed = TEST_FAILED_RE.search(blob)
        skipped = TEST_SKIPPED_RE.search(blob)
        outcome = "passed" if run.group(1).lower() == "successful" else "failed"
        return {
            "outcome": outcome,
            "failed": int(failed.group(1)) if failed else 0,
            "passed": int(passed.group(1)) if passed else 0,
            "skipped": int(skipped.group(1)) if skipped else 0,
            "total": int(total.group(1)),
            "filter": "Smoke|Regression",
        }
    return {
        "outcome": "unknown",
        "failed": None,
        "passed": None,
        "skipped": None,
        "total": None,
        "filter": "Smoke|Regression",
    }


SCORE_FIELDS = (
    ("required_for_app", "Required for app"),
    ("install_risk", "If we install"),
    ("skip_risk", "If we skip"),
    ("compatibility", "Compatibility"),
)

SCORE_VALUE_LABELS = {
    "required": "Required",
    "not_required": "Not required",
    "breaks_app": "App may stop working",
    "may_break_app": "App may break",
    "compatible": "Compatible with the app",
    "app_will_fail": "App will fail",
    "stays_vulnerable": "Configuration stays exposed",
    "no_app_impact": "No effect on the app",
    "incompatible": "Not compatible",
}

CHART_RISK_LABELS = {
    "stays_vulnerable": "Skip: still exposed",
    "may_break_app": "Install: may break",
    "no_app_impact": "Skip: no app effect",
    "compatible": "Install: compatible",
}

RISK_HINTS = {
    "stays_vulnerable": "If we do not install this KB, the configuration stays exposed on that host path.",
    "may_break_app": "If we install this KB, the app on main may break.",
    "no_app_impact": "If we skip this KB, the app on main does not change.",
    "compatible": "If we install this KB, the app on main should still run.",
}

SCORE_FIELD_HINTS = {
    "required_for_app": "Does the product on main need this KB to keep working?",
    "install_risk": "What happens to the app if we put the KB on the configuration?",
    "skip_risk": "What happens if we leave the KB off the configuration?",
    "compatibility": "Does current main work with these vendor bits?",
    "vendor_severity": "Microsoft / FindUpdates severity as C H M L.",
    "vendor_likelihood": "KEV is C. High exploitability is H. Unknown is M.",
    "vendor_risk": "Combined vendor severity and likelihood.",
    "product_severity": "How severe this is for the published exe on this configuration.",
    "product_likelihood": "How reachable the issue is on this configuration. Often L when the component is not loaded.",
    "product_risk": "Product risk may be L even when vendor risk is C.",
}

PSIRT_FIELDS = (
    ("vendor_severity", "Vendor severity"),
    ("vendor_likelihood", "Vendor likelihood"),
    ("vendor_risk", "Vendor risk"),
    ("product_severity", "Product severity"),
    ("product_likelihood", "Product likelihood"),
    ("product_risk", "Product risk"),
)


def score_label(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "—"
    return SCORE_VALUE_LABELS.get(text, text.replace("_", " "))


def chart_risk_label(key: str) -> str:
    return CHART_RISK_LABELS.get(key, key.replace("_", " "))


def risk_chart_caption(counts: dict[str, int] | None) -> str:
    item = counts or {}
    exposed = int(item.get("stays_vulnerable") or 0)
    may_break = int(item.get("may_break_app") or 0)
    no_effect = int(item.get("no_app_impact") or 0)
    compatible = int(item.get("compatible") or 0)
    return (
        f"{exposed} stay exposed if we skip the KB. "
        f"{may_break} may break the app if we install. "
        f"{no_effect} do not affect the app. "
        f"{compatible} look compatible if installed."
    )


def score_rows(cluster: dict[str, object] | None) -> list[tuple[str, str]]:
    item = cluster or {}
    rows = [(label, score_label(item.get(key))) for key, label in SCORE_FIELDS]
    rows.extend((label, str(item.get(key) or "NA")) for key, label in PSIRT_FIELDS)
    return rows


KB_RE = re.compile(r"\bKB\d+\b", re.IGNORECASE)


def extract_kb_ids(*parts: object) -> list[str]:
    found: list[str] = []
    for part in parts:
        for match in KB_RE.findall(str(part or "")):
            kb = match.upper()
            if kb not in found:
                found.append(kb)
    return found


def impact_excerpt(body: object) -> str:
    text = re.sub(r"<!--.*?-->", "", str(body or ""), flags=re.S).strip()
    if not text:
        return ""
    match = re.search(
        r"## Technical Impact Assessment\s*(.*?)\s*(?=^## |\Z)",
        text,
        flags=re.S | re.M,
    )
    if not match:
        match = re.search(
            r"### Impacted Components\s*(.*?)\s*(?=### |\n## |\Z)",
            text,
            flags=re.S,
        )
    chunk = (match.group(1) if match else text).strip()
    if len(chunk) > 1200:
        return chunk[:1200].rstrip() + "…"
    return chunk


def attach_vendor_letters(packages: list[dict[str, object]] | None) -> None:
    for item in packages or []:
        if not isinstance(item, dict):
            continue
        vendor = psirt_scores.vendor_scores(
            severity=item.get("severity"),
            known_exploited=item.get("known_exploited"),
            exploitability=item.get("exploitability"),
        )
        item["vendor_severity"] = vendor["severity"]
        item["vendor_likelihood"] = vendor["likelihood"]
        item["vendor_risk"] = vendor["risk"]


def enrich_clusters(
    clusters: list[dict[str, object]] | None,
    packages: list[dict[str, object]] | None,
) -> list[dict[str, object]]:
    rows = [item for item in (clusters or []) if isinstance(item, dict)]
    pkgs = [item for item in (packages or []) if isinstance(item, dict)]
    names: list[str] = []
    for item in pkgs:
        names.extend(str(name).strip() for name in (item.get("stations") or []) if str(name).strip())
    labels = config_display_names(names)
    for cluster in rows:
        kbs = [str(item).strip() for item in (cluster.get("packages") or []) if str(item).strip()]
        for kb in extract_kb_ids(
            cluster.get("title"),
            cluster.get("impact"),
            cluster.get("advisory_id"),
            cluster.get("body"),
        ):
            if kb not in kbs:
                kbs.append(kb)
        cluster["packages"] = kbs
        if not str(cluster.get("impact") or "").strip():
            title = str(cluster.get("title") or "")
            marker = " - "
            if marker in title:
                cluster["impact"] = title.rsplit(marker, 1)[-1].strip()
        config_raw = str(cluster.get("device_id") or "").strip()
        cluster["config_label"] = labels.get(config_raw, config_raw)
    by_key: dict[str, list[str]] = {}
    for cluster in rows:
        key = str(cluster.get("cluster_key") or "").strip()
        if not key:
            continue
        slot = by_key.setdefault(key, [])
        for kb in cluster.get("packages") or []:
            text = str(kb).strip()
            if text and text not in slot:
                slot.append(text)
    for cluster in rows:
        key = str(cluster.get("cluster_key") or "").strip()
        if not cluster.get("packages") and key and by_key.get(key):
            cluster["packages"] = list(by_key[key])
        kbs = [str(item).strip() for item in (cluster.get("packages") or []) if str(item).strip()]
        members = [item for item in pkgs if str(item.get("kb") or "").strip() in kbs]
        if members and not cluster.get("vendor_risk"):
            letters = psirt_scores.scores_from_members(
                members,
                required_for_app=cluster.get("required_for_app"),
                install_risk=cluster.get("install_risk"),
                skip_risk=cluster.get("skip_risk"),
                compatibility=cluster.get("compatibility"),
            )
            cluster.update(letters)
        elif not cluster.get("product_risk"):
            product = psirt_scores.product_scores(
                required_for_app=cluster.get("required_for_app"),
                install_risk=cluster.get("install_risk"),
                skip_risk=cluster.get("skip_risk"),
                compatibility=cluster.get("compatibility"),
            )
            cluster["product_severity"] = product["severity"]
            cluster["product_likelihood"] = product["likelihood"]
            cluster["product_risk"] = product["risk"]
    return rows


def kb_config_matrix(
    packages: list[dict[str, object]] | None,
    clusters: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    names: list[str] = []
    for item in packages or []:
        if isinstance(item, dict):
            names.extend(str(name).strip() for name in (item.get("stations") or []) if str(name).strip())
    labels = config_display_names(names)
    filled = enrich_clusters(list(clusters or []), list(packages or []))
    return psirt_scores.kb_config_matrix(packages, labels, filled)


def _cluster_from_issue(path: Path, payload: dict) -> dict[str, object] | None:
    if path.name in SKIP_ISSUE_NAMES:
        return None
    if "issues" in payload and not payload.get("title"):
        return None
    if payload.get("tasks") and payload.get("summary") and not payload.get("title"):
        return None
    cluster_key = str(payload.get("cluster_key") or "").strip()
    if cluster_key == "ai-usage":
        return None
    if cluster_key in {"missing-report", "summary"}:
        return None
    cluster = {
        "title": str(payload.get("title") or path.stem),
        "device_id": str(payload.get("device_id") or ""),
        "cluster_key": cluster_key or path.stem,
        "advisory_id": str(payload.get("advisory_id") or cluster_key),
        "required_for_app": str(payload.get("required_for_app") or ""),
        "install_risk": str(payload.get("install_risk") or ""),
        "skip_risk": str(payload.get("skip_risk") or ""),
        "compatibility": str(payload.get("compatibility") or ""),
        "packages": [str(item).strip() for item in (payload.get("packages") or []) if str(item).strip()],
        "vendor_severity": str(payload.get("vendor_severity") or ""),
        "vendor_likelihood": str(payload.get("vendor_likelihood") or ""),
        "vendor_risk": str(payload.get("vendor_risk") or ""),
        "product_severity": str(payload.get("product_severity") or ""),
        "product_likelihood": str(payload.get("product_likelihood") or ""),
        "product_risk": str(payload.get("product_risk") or ""),
        "body": str(payload.get("body") or ""),
        "impact": impact_excerpt(payload.get("body") or ""),
    }
    if not cluster["product_risk"]:
        product = psirt_scores.product_scores(
            required_for_app=cluster["required_for_app"],
            install_risk=cluster["install_risk"],
            skip_risk=cluster["skip_risk"],
            compatibility=cluster["compatibility"],
        )
        cluster["product_severity"] = product["severity"]
        cluster["product_likelihood"] = product["likelihood"]
        cluster["product_risk"] = product["risk"]
    return cluster


def collect_clusters(workspace: Path) -> tuple[list[dict[str, object]], bool]:
    issues_dir = _first_dir(workspace, "issues-out")
    if issues_dir is None:
        return [], False
    none = issues_dir / "none.json"
    if none.is_file():
        payload = _read_json(none)
        if isinstance(payload, dict) and payload.get("issues") == []:
            return [], True
    clusters: list[dict[str, object]] = []
    for path in sorted(issues_dir.glob("*.json")):
        payload = _read_json(path)
        if not isinstance(payload, dict):
            continue
        cluster = _cluster_from_issue(path, payload)
        if cluster:
            clusters.append(cluster)
    return clusters, False


def collect_findings(workspace: Path) -> tuple[list[dict[str, object]], dict[str, str]]:
    analysis_path = _first_file(workspace, "analysis.json")
    payload = _read_json(analysis_path) if analysis_path else None
    if not isinstance(payload, dict):
        return [], {}
    findings = []
    for item in payload.get("findings") or []:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "id": str(item.get("id") or ""),
                "title": str(item.get("title") or ""),
                "countermeasure": str(item.get("countermeasure") or ""),
                "evidence": str(item.get("evidence") or ""),
                "patch_plan": str(item.get("patch_plan") or ""),
                "tests_to_run": [str(row).strip() for row in (item.get("tests_to_run") or []) if str(row).strip()],
                "impact_files": [str(row).strip() for row in (item.get("impact_files") or []) if str(row).strip()],
            }
        )
    advice = [
        str(row).strip()
        for row in (payload.get("os_kb_advice") or [])
        if str(row).strip()
    ]
    meta = {
        "product": str(payload.get("product") or "HostApplication"),
        "branch": str(payload.get("branch") or "main"),
        "sha": str(payload.get("sha") or ""),
        "tests_filter": str(payload.get("tests_filter") or "Smoke|Regression"),
        "os_kb_advice": advice,
    }
    return findings, meta


def _station_profile(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    device_id = str(payload.get("device_id") or "").strip()
    if not device_id:
        return None
    return {
        "device_id": device_id,
        "model": str(payload.get("model") or ""),
        "device_role": str(payload.get("device_role") or ""),
        "os_product": str(payload.get("os_product") or ""),
        "os_build": str(payload.get("os_build") or ""),
        "deployment_group": str(payload.get("deployment_group") or ""),
    }


def collect_station_profiles(workspace: Path, manifest_path: Path | None) -> list[dict[str, object]]:
    folders: list[Path] = []
    if manifest_path is not None:
        folders.append(manifest_path.parent / "stations")
    found = _first_dir(workspace, "stations")
    if found is not None:
        folders.append(found)
    profiles: list[dict[str, object]] = []
    seen: set[str] = set()
    for folder in folders:
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.json")):
            row = _station_profile(_read_json(path))
            device_id = str((row or {}).get("device_id") or "")
            if row and device_id not in seen:
                seen.add(device_id)
                profiles.append(row)
    return profiles


def _stations_from_zip(archive: zipfile.ZipFile) -> list[dict[str, object]]:
    profiles: list[dict[str, object]] = []
    seen: set[str] = set()
    for name in archive.namelist():
        if not name.startswith("stations/") or not name.endswith(".json"):
            continue
        try:
            payload = json.loads(archive.read(name))
        except (json.JSONDecodeError, KeyError):
            continue
        row = _station_profile(payload)
        device_id = str((row or {}).get("device_id") or "")
        if row and device_id not in seen:
            seen.add(device_id)
            profiles.append(row)
    return profiles


def collect_bundle(workspace: Path) -> dict[str, object] | None:
    manifest_path = _first_file(workspace, "BUNDLE_MANIFEST.json")
    payload = _read_json(manifest_path) if manifest_path else None
    zip_stations: list[dict[str, object]] = []
    if not isinstance(payload, dict):
        for zip_path in sorted(workspace.rglob("windows-patch-bundle-*.zip")):
            try:
                with zipfile.ZipFile(zip_path) as archive:
                    payload = json.loads(archive.read("BUNDLE_MANIFEST.json"))
                    zip_stations = _stations_from_zip(archive)
                break
            except (KeyError, json.JSONDecodeError, zipfile.BadZipFile):
                continue
    if not isinstance(payload, dict):
        return None
    packages = []
    for item in payload.get("packages") or []:
        if not isinstance(item, dict):
            continue
        packages.append(
            {
                "kb": str(item.get("kb") or ""),
                "title": str(item.get("title") or ""),
                "action": str(item.get("action") or ""),
                "include_in_deploy": bool(item.get("include_in_deploy")),
                "severity": str(item.get("severity") or ""),
                "official_url": str(item.get("official_url") or ""),
                "stations": list(item.get("stations") or []),
                "cve_ids": list(item.get("cve_ids") or []),
                "known_exploited": str(item.get("known_exploited") or ""),
                "exploitability": str(item.get("exploitability") or ""),
                "advisory_id": str(item.get("advisory_id") or ""),
                "os_products": [str(row).strip() for row in (item.get("os_products") or []) if str(row).strip()],
                "deployment_groups": [
                    str(row).strip() for row in (item.get("deployment_groups") or []) if str(row).strip()
                ],
            }
        )
    packages = sort_packages(packages)
    attach_vendor_letters(packages)
    stations = collect_station_profiles(workspace, manifest_path)
    if zip_stations:
        seen = {str(item.get("device_id") or "") for item in stations}
        for row in zip_stations:
            device_id = str(row.get("device_id") or "")
            if device_id and device_id not in seen:
                seen.add(device_id)
                stations.append(row)
    return {
        "bundle_id": str(payload.get("bundle_id") or ""),
        "generated": str(payload.get("generated") or ""),
        "findupdates_run_id": str(payload.get("findupdates_run_id") or ""),
        "findupdates_html_url": str(payload.get("findupdates_html_url") or ""),
        "counts": payload.get("counts") if isinstance(payload.get("counts"), dict) else {},
        "packages": packages,
        "stations": stations,
    }


_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "important": 1,
    "medium": 2,
    "moderate": 2,
    "low": 3,
}


def _kb_number(value: str) -> int:
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    return int(digits) if digits else 0


def sort_packages(packages: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        packages,
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity") or "").lower(), 9),
            0 if item.get("include_in_deploy") else 1,
            _kb_number(str(item.get("kb") or "")),
        ),
    )


def packages_for_station(
    packages: list[dict[str, object]] | None, query: str
) -> list[dict[str, object]]:
    needle = (query or "").strip().lower()
    rows = [item for item in (packages or []) if isinstance(item, dict)]
    if not needle:
        return rows
    matched: list[dict[str, object]] = []
    for item in rows:
        stations = item.get("stations") or []
        if any(needle in str(station).lower() for station in stations):
            matched.append(item)
    return matched


COUNTERMEASURE_MEANING = {
    "present": "Defense is in the product code on main.",
    "absent": "No defense found. This finding is still open.",
    "partial": "Some defense exists, but it is not complete.",
}


def countermeasure_meaning(status: object) -> str:
    key = str(status or "").strip().lower()
    return COUNTERMEASURE_MEANING.get(key, "Status is not present, absent, or partial.")


def count_findings(findings: list[dict[str, object]] | None) -> dict[str, int]:
    counts = {"present": 0, "partial": 0, "absent": 0, "other": 0, "total": 0}
    for item in findings or []:
        status = str(item.get("countermeasure") or "").lower()
        if status in {"present", "partial", "absent"}:
            counts[status] += 1
        else:
            counts["other"] += 1
        counts["total"] += 1
    return counts


def _severity_bucket(value: str) -> str:
    rank = str(value or "").lower()
    if rank == "critical":
        return "critical"
    if rank in {"high", "important"}:
        return "high"
    return "other"


def count_packages(packages: list[dict[str, object]] | None) -> dict[str, int]:
    result = {
        "deploy": 0,
        "hold": 0,
        "deploy_critical": 0,
        "deploy_high": 0,
        "deploy_other": 0,
        "hold_critical": 0,
        "hold_high": 0,
        "hold_other": 0,
    }
    for item in packages or []:
        bucket = _severity_bucket(str(item.get("severity") or ""))
        side = "deploy" if item.get("include_in_deploy") else "hold"
        result[side] += 1
        result[f"{side}_{bucket}"] += 1
    return result


def count_risks(clusters: list[dict[str, object]] | None) -> dict[str, int]:
    counts = {
        "stays_vulnerable": 0,
        "may_break_app": 0,
        "no_app_impact": 0,
        "compatible": 0,
        "other": 0,
    }
    for item in clusters or []:
        skip = str(item.get("skip_risk") or "").strip()
        install = str(item.get("install_risk") or "").strip()
        key = skip or install
        if key in counts:
            counts[key] += 1
        elif key:
            counts["other"] += 1
    return counts


def station_count(bundle: dict[str, object] | None) -> int:
    if not bundle:
        return 0
    counts = bundle.get("counts") if isinstance(bundle.get("counts"), dict) else {}
    if counts.get("stations") not in (None, ""):
        try:
            return int(counts["stations"])
        except (TypeError, ValueError):
            pass
    seen: set[str] = set()
    for item in bundle.get("packages") or []:
        if not isinstance(item, dict):
            continue
        for station in item.get("stations") or []:
            seen.add(str(station))
    return len(seen)


def bundle_summary(bundle: dict[str, object] | None, *, run_id: str = "") -> str:
    if not bundle:
        return "No Windows host update pack on this run."
    counted = count_packages(list(bundle.get("packages") or []))
    when = str(bundle.get("generated") or "")[:10]
    run = f"This run ({run_id})" if run_id else "This run"
    date = f" from {when}" if when else ""
    return (
        f"{run} host Windows update pack{date}. "
        f"{counted['deploy']} for lab check. "
        f"{counted['hold']} held — do not install. "
        f"Covers {station_count(bundle)} configurations."
    )


def config_display_names(names: list[str] | None) -> dict[str, str]:
    unique = sorted({str(name).strip() for name in (names or []) if str(name).strip()})
    return {name: f"Configurations{index}" for index, name in enumerate(unique, start=1)}


def cluster_matches_package(
    cluster: dict[str, object] | None,
    package: dict[str, object] | None,
    labels: dict[str, str] | None = None,
) -> bool:
    item = cluster or {}
    pkg = package or {}
    kb = str(pkg.get("kb") or "").strip().upper()
    listed = {str(row).strip().upper() for row in (item.get("packages") or []) if str(row).strip()}
    if kb and kb in listed:
        return True
    found = extract_kb_ids(item.get("title"), item.get("impact"), item.get("advisory_id"), item.get("body"))
    if kb and kb in {row.upper() for row in found}:
        return True
    names = labels or {}
    device = str(item.get("device_id") or "").strip()
    named = str(item.get("config_label") or "").strip()
    for raw in pkg.get("stations") or []:
        station = str(raw or "").strip()
        if not station:
            continue
        label = names.get(station, station)
        if device in {station, label} or named in {station, label}:
            return True
    return False


def clusters_for_kb(
    clusters: list[dict[str, object]] | None,
    package: dict[str, object] | None,
    labels: dict[str, str] | None = None,
) -> list[dict[str, object]]:
    pkg = package or {}
    names = labels or config_display_names(
        [str(row).strip() for row in (pkg.get("stations") or []) if str(row).strip()]
    )
    return [
        item
        for item in (clusters or [])
        if isinstance(item, dict) and cluster_matches_package(item, pkg, names)
    ]


def config_update_counts(packages: list[dict[str, object]] | None) -> list[dict[str, object]]:
    recommended: dict[str, set[str]] = {}
    ignored: dict[str, set[str]] = {}
    for index, item in enumerate(packages or []):
        if not isinstance(item, dict):
            continue
        kb = str(item.get("kb") or f"row-{index}")
        names = [str(name).strip() for name in (item.get("stations") or []) if str(name).strip()]
        bucket = recommended if item.get("include_in_deploy") else ignored
        for name in names:
            bucket.setdefault(name, set()).add(kb)
    names = sorted(set(recommended) | set(ignored))
    return [
        {
            "name": name,
            "recommended": len(recommended.get(name, set())),
            "ignored": len(ignored.get(name, set())),
        }
        for name in names
    ]


def config_chart_caption(
    rows: list[dict[str, object]] | None,
    *,
    run_id: str = "",
    history_n: int = 0,
) -> str:
    items = list(rows or [])
    recommended = sum(int(item.get("recommended") or 0) for item in items)
    ignored = sum(int(item.get("ignored") or 0) for item in items)
    run = f"This run ({run_id})" if run_id else "This run"
    line = (
        f"{run}: {ignored} applicable for our platform · "
        f"{recommended} recommended to install "
        f"across {len(items)} configurations."
    )
    if history_n < 2:
        return line + " History will grow with later runs."
    return line + f" {history_n} runs in the last 90 days."


_MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


def _trend_stamp(value: object) -> tuple[str, str]:
    raw = str(value or "")
    day = raw[:10] if len(raw) >= 10 else ""
    clock = raw[11:16] if len(raw) >= 16 else ""
    return day, clock


def trend_x_labels(points: list[dict[str, object]] | None) -> list[str]:
    rows = list(points or [])
    days = {_trend_stamp(item.get("created_at"))[0] for item in rows}
    days.discard("")
    same_day = len(days) <= 1
    labels: list[str] = []
    for item in rows:
        day, clock = _trend_stamp(item.get("created_at"))
        if same_day and clock:
            labels.append(clock)
            continue
        if len(day) == 10:
            labels.append(f"{int(day[8:10])} {_MONTHS[int(day[5:7]) - 1]}")
            continue
        labels.append(str(item.get("run_id") or "—")[-6:])
    return labels


def trend_is_flat(points: list[dict[str, object]] | None, key: str) -> bool:
    values = [int(item.get(key) or 0) for item in (points or [])]
    return len(values) > 1 and len(set(values)) == 1


def trend_caption(points: list[dict[str, object]] | None, *, selected_id: str = "") -> str:
    rows = list(points or [])
    if not rows:
        return "History will grow with later runs."
    selected = next(
        (item for item in rows if str(item.get("run_id")) == str(selected_id)),
        rows[-1],
    )
    line = (
        f"This run: {int(selected.get('absent') or 0)} still open · "
        f"{int(selected.get('deploy') or 0)} KB for lab check."
    )
    if len(rows) < 2:
        return f"{line} History will grow with later runs."
    days = {_trend_stamp(item.get("created_at"))[0] for item in rows}
    days.discard("")
    extra = f" {len(rows)} runs in the last 90 days."
    if len(days) <= 1:
        extra += " Axis shows run time because these runs share one day."
    if trend_is_flat(rows, "absent") and trend_is_flat(rows, "deploy"):
        extra += " Counts did not change."
    return line + extra


def trend_points(snapshots: list[dict[str, object]] | None) -> list[dict[str, object]]:
    points: list[dict[str, object]] = []
    for item in snapshots or []:
        findings = count_findings(list(item.get("findings") or []))
        bundle = item.get("bundle") if isinstance(item.get("bundle"), dict) else {}
        packages = count_packages(list((bundle or {}).get("packages") or []))
        points.append(
            {
                "run_id": item.get("run_id"),
                "created_at": item.get("created_at"),
                "absent": findings["absent"],
                "deploy": packages["deploy"],
            }
        )
    points.sort(key=lambda row: str(row.get("created_at") or ""))
    return points


def collect_release(workspace: Path) -> dict[str, object] | None:
    release_dir = _first_dir(workspace, "release")
    patterns = ("HostApplication-*-win-x64.zip", "DesktopApplication-*-win-x64.zip")
    zips: list[Path] = []
    if release_dir is None:
        for pattern in patterns:
            zips.extend(workspace.rglob(pattern))
    else:
        for pattern in patterns:
            zips.extend(release_dir.glob(pattern))
    zips = sorted(zips)
    if not zips:
        return None
    return {"zip_name": zips[-1].name}


def collect_sha(workspace: Path, analysis_meta: dict[str, str]) -> str:
    if analysis_meta.get("sha"):
        return analysis_meta["sha"]
    inventory = _first_file(workspace, "host-application-inventory.md") or _first_file(
        workspace, "desktop-application-inventory.md"
    )
    if inventory:
        match = HEAD_RE.search(inventory.read_text(encoding="utf-8"))
        if match:
            return match.group(1)
    return ""


def collect_ai_usage(workspace: Path) -> dict[str, object] | None:
    path = _first_file(workspace, "ai-usage.json")
    payload = _read_json(path) if path else None
    if not isinstance(payload, dict):
        return None
    summary = payload.get("summary")
    if isinstance(summary, dict) and summary.get("provider"):
        return {
            "provider": str(summary.get("provider") or ""),
            "model": str(summary.get("model") or ""),
        }
    tasks = [item for item in payload.get("tasks") or [] if isinstance(item, dict)]
    if not tasks:
        return None
    providers = []
    models = []
    for item in tasks:
        used = str(item.get("used_provider") or "")
        if used and used not in providers:
            providers.append(used)
        model = str(item.get("model") or "")
        if model and model not in models:
            models.append(model)
    return {
        "provider": providers[0] if len(providers) == 1 else " + ".join(providers) or "unknown",
        "model": models[0] if len(models) == 1 else ", ".join(models),
    }


def format_ai_usage(usage: dict[str, object] | None) -> str:
    if not usage or not usage.get("provider"):
        return "AI usage was not recorded for this run."
    provider = str(usage.get("provider") or "")
    model = str(usage.get("model") or "").strip()
    if provider == "offline":
        return "Analysis used offline scripts."
    model_bit = f", model {model}" if model else ""
    return f"Analysis used {provider}{model_bit}."


def collect_tests(workspace: Path, filter_name: str) -> dict[str, object]:
    path = _first_file(workspace, "TEST_RESULTS.md")
    text = path.read_text(encoding="utf-8") if path else ""
    result = parse_test_results(text)
    if filter_name:
        result["filter"] = filter_name
    return result


def snapshot_from_workspace(workspace: Path, *, env: dict[str, str] | None = None) -> dict[str, object]:
    environ = env if env is not None else os.environ
    clusters, none_marker = collect_clusters(workspace)
    findings, meta = collect_findings(workspace)
    bundle = collect_bundle(workspace)
    tests = collect_tests(workspace, meta.get("tests_filter") or "")
    release = collect_release(workspace)
    ai = collect_ai_usage(workspace)
    run_id = (environ.get("GITHUB_RUN_ID") or "").strip() or "local"
    server = (environ.get("GITHUB_SERVER_URL") or "https://github.com").rstrip("/")
    repo = (environ.get("GITHUB_REPOSITORY") or "defrances/Orchestrator").strip()
    workflow = (environ.get("GITHUB_WORKFLOW") or "Vendor impact and PDLC").strip()
    fu_repo = (environ.get("FINDUPDATES_REPO") or "defrances/FindUpdates").strip()
    app_repo = (environ.get("APP_REPO") or "defrances/HostApplication").strip()
    fu_run = (environ.get("FU_RUN_ID") or "").strip()
    fu_url = (environ.get("FU_HTML_URL") or "").strip()
    if bundle and not fu_run:
        fu_run = str(bundle.get("findupdates_run_id") or "")
    if bundle and not fu_url:
        fu_url = str(bundle.get("findupdates_html_url") or "")
    if fu_run and not fu_url:
        fu_url = f"{server}/{fu_repo}/actions/runs/{fu_run}"
    sha = collect_sha(workspace, meta)
    created = _iso()
    pkg_rows = list((bundle or {}).get("packages") or []) if bundle else []
    clusters = enrich_clusters(clusters, pkg_rows)
    if bundle:
        attach_vendor_letters(pkg_rows)
        bundle["packages"] = pkg_rows
    return {
        "schema_version": 1,
        "run_id": str(run_id),
        "created_at": created,
        "workflow": workflow,
        "run_url": f"{server}/{repo}/actions/runs/{run_id}" if run_id != "local" else "",
        "findupdates_run_id": fu_run,
        "findupdates_url": fu_url,
        "product": meta.get("product") or "HostApplication",
        "branch": meta.get("branch") or "main",
        "sha": sha,
        "sha_url": f"{server}/{app_repo}/commit/{sha}" if sha else "",
        "conclusion": (environ.get("ORCH_CONCLUSION") or "").strip(),
        "clusters": clusters,
        "cluster_count": len(clusters),
        "no_clusters": none_marker or not clusters,
        "findings": findings,
        "os_kb_advice": list(meta.get("os_kb_advice") or []),
        "bundle": bundle,
        "psirt_matrix": kb_config_matrix((bundle or {}).get("packages") if bundle else [], clusters),
        "tests": tests,
        "release": release,
        "ai": ai,
    }


def load_history(history_dir: Path) -> list[dict[str, object]]:
    if not history_dir.exists():
        return []
    snapshots: list[dict[str, object]] = []
    data_dir = history_dir / "data" / "history"
    if not data_dir.is_dir():
        data_dir = history_dir / "history" if (history_dir / "history").is_dir() else data_dir
    if data_dir.is_dir():
        for path in sorted(data_dir.glob("*.json")):
            payload = _read_json(path)
            if isinstance(payload, dict) and payload.get("run_id"):
                snapshots.append(payload)
    index = _read_json(history_dir / "data" / "index.json")
    if isinstance(index, dict) and not snapshots:
        latest = _read_json(history_dir / "data" / "latest.json")
        if isinstance(latest, dict) and latest.get("run_id"):
            snapshots.append(latest)
    return snapshots


def enrich_snapshot(snapshot: dict[str, object]) -> dict[str, object]:
    bundle = snapshot.get("bundle")
    packages: list[dict[str, object]] = []
    if isinstance(bundle, dict):
        packages = [item for item in (bundle.get("packages") or []) if isinstance(item, dict)]
        attach_vendor_letters(packages)
        bundle["packages"] = packages
        snapshot["bundle"] = bundle
    clusters = enrich_clusters(
        [item for item in (snapshot.get("clusters") or []) if isinstance(item, dict)],
        packages,
    )
    snapshot["clusters"] = clusters
    snapshot["psirt_matrix"] = kb_config_matrix(packages, clusters)
    return snapshot


def merge_history(
    existing: list[dict[str, object]],
    current: dict[str, object],
    *,
    now: datetime | None = None,
    retention_days: int = RETENTION_DAYS,
) -> list[dict[str, object]]:
    moment = now or _now()
    cutoff = moment - timedelta(days=retention_days)
    by_id: dict[str, dict[str, object]] = {}
    for item in existing + [current]:
        run_id = str(item.get("run_id") or "").strip()
        if not run_id:
            continue
        created = _parse_iso(str(item.get("created_at") or ""))
        if created is not None and created < cutoff and run_id != current.get("run_id"):
            continue
        by_id[run_id] = item
    merged = list(by_id.values())
    current_id = str(current.get("run_id") or "")
    merged.sort(
        key=lambda item: (
            str(item.get("created_at") or ""),
            1 if str(item.get("run_id")) == current_id else 0,
        ),
        reverse=True,
    )
    return merged


def write_site(out: Path, snapshots: list[dict[str, object]]) -> dict[str, object]:
    if not snapshots:
        raise SystemExit("no snapshots to publish")
    latest = snapshots[0]
    out.mkdir(parents=True, exist_ok=True)
    data = out / "data"
    history = data / "history"
    if data.exists():
        shutil.rmtree(data)
    history.mkdir(parents=True)
    snapshots = [enrich_snapshot(item) for item in snapshots]
    latest = snapshots[0]
    for item in snapshots:
        run_id = str(item["run_id"])
        (history / f"{run_id}.json").write_text(json.dumps(item, indent=2) + "\n", encoding="utf-8")
    (data / "latest.json").write_text(json.dumps(latest, indent=2) + "\n", encoding="utf-8")
    index = {
        "generated": _iso(),
        "latest": latest["run_id"],
        "retention_days": RETENTION_DAYS,
        "runs": [
            {
                "run_id": item["run_id"],
                "created_at": item.get("created_at") or "",
                "label": _run_label(item),
            }
            for item in snapshots
        ],
    }
    (data / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    (out / "assets").mkdir(exist_ok=True)
    shutil.copyfile(PAGES_DIR / "style.css", out / "assets" / "style.css")
    shutil.copyfile(PAGES_DIR / "app.js", out / "assets" / "app.js")
    (out / "assets" / "data.js").write_text(
        "window.SITE_INDEX = "
        + json.dumps(index)
        + ";\nwindow.SITE_SNAPSHOTS = "
        + json.dumps({item["run_id"]: item for item in snapshots})
        + ";\n",
        encoding="utf-8",
    )
    shutil.copyfile(PAGES_DIR / "index.html", out / "index.html")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    return index


def _run_label(item: dict[str, object]) -> str:
    created = str(item.get("created_at") or "")[:10]
    run_id = str(item.get("run_id") or "")
    return f"{created} · {run_id}"


def _gh_json(args: list[str]) -> object:
    result = subprocess.run(["gh", *args], check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(result.stderr or result.stdout or "gh failed")
    return json.loads(result.stdout or "null")


def backfill_snapshots(repo: str, dest: Path) -> list[dict[str, object]]:
    dest.mkdir(parents=True, exist_ok=True)
    runs = _gh_json(
        [
            "run",
            "list",
            "--repo",
            repo,
            "--workflow",
            "orchestrate.yml",
            "--limit",
            "40",
            "--json",
            "databaseId,createdAt,url,conclusion,displayTitle",
        ]
    )
    if not isinstance(runs, list):
        return []
    cutoff = _now() - timedelta(days=RETENTION_DAYS)
    snapshots: list[dict[str, object]] = []
    for row in runs:
        if not isinstance(row, dict):
            continue
        created = _parse_iso(str(row.get("createdAt") or ""))
        if created is not None and created < cutoff:
            continue
        run_id = str(row.get("databaseId") or "")
        if not run_id:
            continue
        work = dest / run_id
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        pull = subprocess.run(
            ["gh", "run", "download", run_id, "--repo", repo, "--dir", str(work)],
            check=False,
            text=True,
            capture_output=True,
        )
        if pull.returncode != 0:
            continue
        env = {
            "GITHUB_RUN_ID": run_id,
            "GITHUB_REPOSITORY": repo,
            "GITHUB_WORKFLOW": str(row.get("displayTitle") or "Vendor impact and PDLC"),
            "ORCH_CONCLUSION": str(row.get("conclusion") or ""),
        }
        snapshot = snapshot_from_workspace(work, env=env)
        snapshot["created_at"] = _iso(created) if created else snapshot["created_at"]
        snapshot["run_url"] = str(row.get("url") or snapshot.get("run_url") or "")
        snapshots.append(snapshot)
    return snapshots


def build(
    workspace: Path,
    history_dir: Path,
    out: Path,
    *,
    env: dict[str, str] | None = None,
    backfill: bool = False,
) -> dict[str, object]:
    existing = load_history(history_dir)
    if backfill:
        repo = (os.environ.get("GITHUB_REPOSITORY") or "defrances/Orchestrator").strip()
        existing.extend(backfill_snapshots(repo, out.parent / ".pages-backfill"))
    current = snapshot_from_workspace(workspace, env=env)
    snapshots = merge_history(existing, current)
    return write_site(out, snapshots)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Orchestrator GitHub Pages from run files. No AI.")
    parser.add_argument("--workspace", default=".", help="Run files or downloaded artifacts root")
    parser.add_argument("--history", default="", help="Previous gh-pages checkout (data/history)")
    parser.add_argument("--out", default="site", help="Output directory")
    parser.add_argument("--backfill", action="store_true", help="Also pull surviving Actions artifacts (14 days)")
    args = parser.parse_args()
    workspace = Path(args.workspace).resolve()
    history = Path(args.history).resolve() if args.history else workspace
    out = Path(args.out).resolve()
    index = build(workspace, history, out, backfill=args.backfill)
    print(f"wrote {out / 'index.html'} latest={index['latest']} runs={len(index['runs'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
