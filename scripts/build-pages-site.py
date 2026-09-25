#!/usr/bin/env python3
"""Build a static GitHub Pages site from one Orchestrator run. No AI."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

RETENTION_DAYS = 90
SKIP_ISSUE_NAMES = {"none.json", "missing-report.json", "summary.json"}
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
    ("install_risk", "Install risk"),
    ("skip_risk", "Skip risk"),
    ("compatibility", "Compatibility"),
)


def score_label(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "—"
    return text.replace("_", " ")


def score_rows(cluster: dict[str, object] | None) -> list[tuple[str, str]]:
    item = cluster or {}
    return [(label, score_label(item.get(key))) for key, label in SCORE_FIELDS]


def _cluster_from_issue(path: Path, payload: dict) -> dict[str, object] | None:
    if path.name in SKIP_ISSUE_NAMES:
        return None
    if "issues" in payload and not payload.get("title"):
        return None
    cluster_key = str(payload.get("cluster_key") or "").strip()
    if cluster_key in {"missing-report", "summary"}:
        return None
    return {
        "title": str(payload.get("title") or path.stem),
        "device_id": str(payload.get("device_id") or ""),
        "cluster_key": cluster_key or path.stem,
        "advisory_id": str(payload.get("advisory_id") or cluster_key),
        "required_for_app": str(payload.get("required_for_app") or ""),
        "install_risk": str(payload.get("install_risk") or ""),
        "skip_risk": str(payload.get("skip_risk") or ""),
        "compatibility": str(payload.get("compatibility") or ""),
    }


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
            }
        )
    meta = {
        "product": str(payload.get("product") or "DesktopApplication"),
        "branch": str(payload.get("branch") or "main"),
        "sha": str(payload.get("sha") or ""),
        "tests_filter": str(payload.get("tests_filter") or "Smoke|Regression"),
    }
    return findings, meta


def collect_bundle(workspace: Path) -> dict[str, object] | None:
    manifest_path = _first_file(workspace, "BUNDLE_MANIFEST.json")
    payload = _read_json(manifest_path) if manifest_path else None
    if not isinstance(payload, dict):
        for zip_path in sorted(workspace.rglob("windows-patch-bundle-*.zip")):
            try:
                with zipfile.ZipFile(zip_path) as archive:
                    payload = json.loads(archive.read("BUNDLE_MANIFEST.json"))
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
            }
        )
    packages = sort_packages(packages)
    return {
        "bundle_id": str(payload.get("bundle_id") or ""),
        "generated": str(payload.get("generated") or ""),
        "findupdates_run_id": str(payload.get("findupdates_run_id") or ""),
        "findupdates_html_url": str(payload.get("findupdates_html_url") or ""),
        "counts": payload.get("counts") if isinstance(payload.get("counts"), dict) else {},
        "packages": packages,
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
    "present": "Defense is in the current product code.",
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
        f"Covers {station_count(bundle)} stations."
    )


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
    if release_dir is None:
        zips = sorted(workspace.rglob("DesktopApplication-*-win-x64.zip"))
    else:
        zips = sorted(release_dir.glob("DesktopApplication-*-win-x64.zip"))
    if not zips:
        return None
    return {"zip_name": zips[-1].name}


def collect_sha(workspace: Path, analysis_meta: dict[str, str]) -> str:
    if analysis_meta.get("sha"):
        return analysis_meta["sha"]
    inventory = _first_file(workspace, "desktop-application-inventory.md")
    if inventory:
        match = HEAD_RE.search(inventory.read_text(encoding="utf-8"))
        if match:
            return match.group(1)
    return ""


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
    run_id = (environ.get("GITHUB_RUN_ID") or "").strip() or "local"
    server = (environ.get("GITHUB_SERVER_URL") or "https://github.com").rstrip("/")
    repo = (environ.get("GITHUB_REPOSITORY") or "defrances/Orchestrator").strip()
    workflow = (environ.get("GITHUB_WORKFLOW") or "Vendor impact and PDLC").strip()
    fu_repo = (environ.get("FINDUPDATES_REPO") or "defrances/FindUpdates").strip()
    app_repo = (environ.get("APP_REPO") or "defrances/DesktopApplication").strip()
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
    return {
        "schema_version": 1,
        "run_id": str(run_id),
        "created_at": created,
        "workflow": workflow,
        "run_url": f"{server}/{repo}/actions/runs/{run_id}" if run_id != "local" else "",
        "findupdates_run_id": fu_run,
        "findupdates_url": fu_url,
        "product": meta.get("product") or "DesktopApplication",
        "branch": meta.get("branch") or "main",
        "sha": sha,
        "sha_url": f"{server}/{app_repo}/commit/{sha}" if sha else "",
        "conclusion": (environ.get("ORCH_CONCLUSION") or "").strip(),
        "clusters": clusters,
        "cluster_count": len(clusters),
        "no_clusters": none_marker or not clusters,
        "findings": findings,
        "bundle": bundle,
        "tests": tests,
        "release": release,
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
    (out / "assets" / "style.css").write_text(STYLE_CSS, encoding="utf-8")
    (out / "assets" / "app.js").write_text(APP_JS, encoding="utf-8")
    (out / "assets" / "data.js").write_text(
        "window.SITE_INDEX = "
        + json.dumps(index)
        + ";\nwindow.SITE_SNAPSHOTS = "
        + json.dumps({item["run_id"]: item for item in snapshots})
        + ";\n",
        encoding="utf-8",
    )
    (out / "index.html").write_text(INDEX_HTML, encoding="utf-8")
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


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Orchestrator — latest run</title>
  <link rel="stylesheet" href="assets/style.css">
</head>
<body>
  <header>
    <p class="kicker">Orchestrator · DesktopApplication</p>
    <h1>Vendor impact and PDLC</h1>
    <p class="banner">Advisory only. Not an authorization to install, approve, or deploy. HOLD and BLOCK stay. Stations are synthetic lab fixtures.</p>
    <label class="history">
      History (90 days)
      <select id="run-select"></select>
    </label>
  </header>
  <main id="app">Loading latest run…</main>
  <footer>Generated by <code>scripts/build-pages-site.py</code>. No AI in this page. Artifacts on Actions expire in 14 days; this site keeps 90-day snapshots.</footer>
  <script src="assets/data.js"></script>
  <script src="assets/app.js"></script>
</body>
</html>
"""

STYLE_CSS = """:root {
  --ink: #111;
  --muted: #4d4d4d;
  --line: #d9dee7;
  --bg: #f7f7f7;
  --card: #fff;
  --red: #cc0000;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Arial, Helvetica, sans-serif;
  color: var(--ink);
  background: var(--bg);
}
header, main, footer { max-width: 1100px; margin: 0 auto; padding: 1.2rem 1.25rem; }
header { padding-top: 1.6rem; }
.kicker { margin: 0 0 0.35rem; color: var(--muted); letter-spacing: 0.04em; text-transform: uppercase; font-size: 0.75rem; }
h1 { margin: 0 0 0.75rem; font-size: 1.7rem; }
h2 { margin: 0 0 0.7rem; font-size: 1.05rem; }
.banner {
  background: #fff;
  border-left: 4px solid var(--red);
  padding: 0.7rem 0.85rem;
  margin: 0 0 1rem;
}
.history { display: block; margin-top: 0.9rem; font-size: 0.9rem; color: var(--muted); }
select { display: block; margin-top: 0.35rem; min-width: 22rem; max-width: 100%; padding: 0.4rem; }
.meta, .cards, .table-wrap { margin-bottom: 1.2rem; }
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap: 0.6rem; }
.meta div, .card, .table-wrap, .empty {
  background: var(--card);
  border: 1px solid var(--line);
  padding: 0.75rem 0.85rem;
}
.meta dt { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; }
.meta dd { margin: 0.2rem 0 0; word-break: break-all; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); gap: 0.7rem; }
.card h3 { margin: 0 0 0.45rem; font-size: 0.95rem; overflow-wrap: anywhere; }
.card .sub { margin: 0 0 0.55rem; font-size: 0.8rem; color: var(--muted); overflow-wrap: anywhere; }
.score-list { margin: 0; display: grid; gap: 0.35rem 0.7rem; }
.score-list div { display: grid; grid-template-columns: minmax(7rem, 40%) 1fr; gap: 0.35rem; align-items: baseline; }
.score-list dt { margin: 0; color: var(--muted); font-size: 0.75rem; }
.score-list dd { margin: 0; font-size: 0.85rem; overflow-wrap: anywhere; }
.tag { display: inline-block; padding: 0.1rem 0.4rem; border: 1px solid var(--line); font-size: 0.75rem; text-transform: uppercase; }
.tag.absent, .tag.failed { border-color: var(--red); color: var(--red); }
.tag.present, .tag.passed { border-color: #111; }
.meaning { margin: 0.45rem 0 0; font-size: 0.85rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { text-align: left; padding: 0.4rem 0.35rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: normal; }
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--ink); }
th.sort-asc::after { content: " \\25b2"; font-size: 0.7em; }
th.sort-desc::after { content: " \\25bc"; font-size: 0.7em; }
.station-filter { display: flex; flex-direction: column; gap: 0.25rem; margin: 0.7rem 0 0.45rem; max-width: 28rem; }
.station-filter span { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; }
.station-filter input { padding: 0.4rem; font: inherit; }
a { color: inherit; }
.empty { color: var(--muted); }
.charts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.7rem; margin: 0 0 1.2rem; }
.chart-card, .chart-wide {
  background: var(--card);
  border: 1px solid var(--line);
  padding: 0.75rem 0.85rem;
}
.chart-wide { margin-bottom: 1.2rem; }
.chart-card h3, .chart-wide h3 { margin: 0 0 0.45rem; font-size: 0.95rem; }
.chart-cap { color: var(--muted); font-size: 0.8rem; margin: 0.45rem 0 0; line-height: 1.4; overflow-wrap: break-word; }
.chart-legend { color: var(--muted); font-size: 0.75rem; margin: 0.7rem 0 0.2rem; line-height: 1.4; }
svg.chart { width: 100%; height: auto; display: block; }
svg.chart .chart-lab { font-size: 11px; fill: #4d4d4d; font-family: Arial, Helvetica, sans-serif; }
svg.chart .chart-n { font-size: 11px; fill: #111; font-family: Arial, Helvetica, sans-serif; }
@media (max-width: 900px) { .charts { grid-template-columns: 1fr; } }
footer { color: var(--muted); font-size: 0.8rem; padding-bottom: 2rem; }
"""

APP_JS = r"""(function () {
  var app = document.getElementById("app");
  var select = document.getElementById("run-select");
  var index = window.SITE_INDEX || { runs: [], latest: "" };
  var snapshots = window.SITE_SNAPSHOTS || {};
  var currentRun = null;
  var pkgSort = { key: "severity", dir: 1 };
  var pkgStation = "";
  var SEV = { critical: 0, high: 1, important: 1, medium: 2, moderate: 2, low: 3 };

  function text(value, fallback) {
    if (value === null || value === undefined || value === "") return fallback || "—";
    return String(value);
  }

  function esc(value) {
    return text(value).replace(/[&<>"]/g, function (ch) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[ch];
    });
  }

  function link(href, label) {
    if (!href) return esc(label);
    return '<a href="' + esc(href) + '">' + esc(label) + "</a>";
  }

  function kbNumber(value) {
    var digits = String(value || "").replace(/\D/g, "");
    return digits ? parseInt(digits, 10) : 0;
  }

  function pkgValue(pkg, key) {
    if (key === "kb") return kbNumber(pkg.kb);
    if (key === "severity") {
      var rank = SEV[String(pkg.severity || "").toLowerCase()];
      return rank === undefined ? 9 : rank;
    }
    if (key === "deploy") return pkg.include_in_deploy ? 0 : 1;
    if (key === "stations") return (pkg.stations || []).join(", ").toLowerCase();
    return String(pkg[key] || "").toLowerCase();
  }

  function matchesStation(pkg, query) {
    var needle = String(query || "").trim().toLowerCase();
    if (!needle) return true;
    return (pkg.stations || []).some(function (id) {
      return String(id).toLowerCase().indexOf(needle) !== -1;
    });
  }

  function packagesForStation(packages, query) {
    return (packages || []).filter(function (pkg) { return matchesStation(pkg, query); });
  }

  function applyStationFilter() {
    var input = document.getElementById("station-filter");
    if (input) pkgStation = input.value;
    var needle = String(pkgStation || "").trim().toLowerCase();
    var rows = app.querySelectorAll("tr[data-stations]");
    var shown = 0;
    rows.forEach(function (tr) {
      var hay = (tr.getAttribute("data-stations") || "").toLowerCase();
      var ok = !needle || hay.indexOf(needle) !== -1;
      tr.hidden = !ok;
      if (ok) shown += 1;
    });
    var empty = document.getElementById("station-filter-empty");
    if (empty) empty.hidden = shown !== 0 || rows.length === 0;
    var cap = document.getElementById("station-filter-cap");
    if (cap) {
      cap.textContent = needle
        ? shown + " of " + rows.length + " KBs match this station"
        : "";
    }
  }

  function sortedPackages(packages) {
    return (packages || []).slice().sort(function (a, b) {
      var av = pkgValue(a, pkgSort.key);
      var bv = pkgValue(b, pkgSort.key);
      if (av < bv) return -pkgSort.dir;
      if (av > bv) return pkgSort.dir;
      return kbNumber(a.kb) - kbNumber(b.kb);
    });
  }

  function sortClass(key) {
    if (pkgSort.key !== key) return "sortable";
    return "sortable " + (pkgSort.dir === 1 ? "sort-asc" : "sort-desc");
  }

  function countFindings(findings) {
    var counts = { present: 0, partial: 0, absent: 0, other: 0, total: 0 };
    (findings || []).forEach(function (item) {
      var status = String(item.countermeasure || "").toLowerCase();
      if (counts[status] !== undefined && status !== "total" && status !== "other") counts[status] += 1;
      else counts.other += 1;
      counts.total += 1;
    });
    return counts;
  }

  function severityBucket(value) {
    var rank = String(value || "").toLowerCase();
    if (rank === "critical") return "critical";
    if (rank === "high" || rank === "important") return "high";
    return "other";
  }

  function countPackages(packages) {
    var result = {
      deploy: 0, hold: 0,
      deploy_critical: 0, deploy_high: 0, deploy_other: 0,
      hold_critical: 0, hold_high: 0, hold_other: 0
    };
    (packages || []).forEach(function (item) {
      var side = item.include_in_deploy ? "deploy" : "hold";
      result[side] += 1;
      result[side + "_" + severityBucket(item.severity)] += 1;
    });
    return result;
  }

  function countRisks(clusters) {
    var counts = { stays_vulnerable: 0, may_break_app: 0, no_app_impact: 0, compatible: 0, other: 0 };
    (clusters || []).forEach(function (item) {
      var key = String(item.skip_risk || item.install_risk || "").trim();
      if (counts[key] !== undefined) counts[key] += 1;
      else if (key) counts.other += 1;
    });
    return counts;
  }

  function allSnapshots() {
    var list = [];
    Object.keys(snapshots).forEach(function (id) { list.push(snapshots[id]); });
    list.sort(function (a, b) { return String(a.created_at || "").localeCompare(String(b.created_at || "")); });
    return list;
  }

  function trendPoints(list) {
    return list.map(function (item) {
      var findings = countFindings(item.findings || []);
      var packages = countPackages(((item.bundle || {}).packages) || []);
      return {
        run_id: item.run_id,
        created_at: item.created_at,
        absent: findings.absent,
        deploy: packages.deploy
      };
    });
  }

  function hbars(rows) {
    var max = 1;
    rows.forEach(function (row) { if (row.value > max) max = row.value; });
    var h = rows.length * 28 + 8;
    var svg = '<svg viewBox="0 0 300 ' + h + '" class="chart">';
    rows.forEach(function (row, i) {
      var y = 6 + i * 28;
      var bw = row.value ? Math.max(row.value / max * 150, 4) : 0;
      svg += '<text x="0" y="' + (y + 13) + '" class="chart-lab">' + esc(row.label) + "</text>";
      if (bw) svg += '<rect x="110" y="' + y + '" width="' + bw + '" height="16" fill="' + row.color + '"/>';
      svg += '<text x="' + (118 + bw) + '" y="' + (y + 13) + '" class="chart-n">' + row.value + "</text>";
    });
    return svg + "</svg>";
  }

  function stackedBars(groups) {
    var max = 1;
    groups.forEach(function (group) {
      var total = 0;
      group.parts.forEach(function (part) { total += part.value; });
      group.total = total;
      if (total > max) max = total;
    });
    var svg = '<svg viewBox="0 0 300 150" class="chart">';
    groups.forEach(function (group, i) {
      var x = 50 + i * 100;
      var y = 118;
      group.parts.forEach(function (part) {
        var bh = part.value / max * 90;
        y -= bh;
        if (bh > 0) svg += '<rect x="' + x + '" y="' + y + '" width="44" height="' + bh + '" fill="' + part.color + '"/>';
      });
      svg += '<text x="' + (x + 22) + '" y="136" text-anchor="middle" class="chart-lab">' + esc(group.label) + "</text>";
      svg += '<text x="' + (x + 22) + '" y="' + (y - 6) + '" text-anchor="middle" class="chart-n">' + group.total + "</text>";
    });
    return svg + "</svg>";
  }

  function trendXLabels(points) {
    var days = {};
    points.forEach(function (point) {
      var day = String(point.created_at || "").slice(0, 10);
      if (day) days[day] = 1;
    });
    var sameDay = Object.keys(days).length <= 1;
    var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    return points.map(function (point) {
      var raw = String(point.created_at || "");
      if (sameDay && raw.length >= 16) return raw.slice(11, 16);
      if (raw.length >= 10) {
        return String(Number(raw.slice(8, 10))) + " " + months[Number(raw.slice(5, 7)) - 1];
      }
      return String(point.run_id || "").slice(-6);
    });
  }

  function trendIsFlat(points, key) {
    var seen = {};
    var count = 0;
    points.forEach(function (point) {
      seen[String(Number(point[key] || 0))] = 1;
      count += 1;
    });
    return count > 1 && Object.keys(seen).length === 1;
  }

  function trendCaption(points, selectedId) {
    if (!points.length) return "History will grow with later runs.";
    var selected = points[points.length - 1];
    points.forEach(function (point) {
      if (String(point.run_id) === String(selectedId)) selected = point;
    });
    var line = "This run: " + Number(selected.absent || 0) + " still open · " +
      Number(selected.deploy || 0) + " KB for lab check.";
    if (points.length < 2) return line + " History will grow with later runs.";
    var days = {};
    points.forEach(function (point) {
      var day = String(point.created_at || "").slice(0, 10);
      if (day) days[day] = 1;
    });
    var extra = " " + points.length + " runs in the last 90 days.";
    if (Object.keys(days).length <= 1) {
      extra += " Axis shows run time because these runs share one day.";
    }
    if (trendIsFlat(points, "absent") && trendIsFlat(points, "deploy")) {
      extra += " Counts did not change.";
    }
    return line + extra;
  }

  function trendRow(points, selectedId, key, color) {
    var w = 1000;
    var h = 120;
    var padL = 44;
    var padR = 18;
    var padT = 20;
    var padB = 28;
    var innerW = w - padL - padR;
    var innerH = h - padT - padB;
    var max = 1;
    var selectedIndex = -1;
    points.forEach(function (point, i) {
      if (Number(point[key]) > max) max = Number(point[key]);
      if (String(point.run_id) === String(selectedId)) selectedIndex = i;
    });
    if (selectedIndex < 0) selectedIndex = points.length - 1;
    var labels = trendXLabels(points);
    function xAt(i) {
      if (points.length === 1) return padL + innerW / 2;
      return padL + i * innerW / (points.length - 1);
    }
    function yAt(value) { return padT + innerH - (Number(value) / max) * innerH; }
    function showLabel(i) {
      if (points.length <= 8) return true;
      if (i === 0 || i === points.length - 1 || i === selectedIndex) return true;
      return i % Math.ceil(points.length / 7) === 0;
    }
    var svg = '<svg viewBox="0 0 ' + w + " " + h + '" class="chart">';
    svg += '<text x="0" y="' + (padT + 4) + '" class="chart-lab">' + max + "</text>";
    svg += '<text x="0" y="' + (padT + innerH + 4) + '" class="chart-lab">0</text>';
    if (points.length) {
      var sx = xAt(selectedIndex);
      svg += '<line x1="' + sx + '" x2="' + sx + '" y1="' + padT + '" y2="' + (padT + innerH) +
        '" stroke="#4d4d4d" stroke-dasharray="3 3"/>';
    }
    var d = points.map(function (point, i) {
      return (i ? "L" : "M") + xAt(i) + " " + yAt(point[key]);
    }).join(" ");
    svg += '<path d="' + d + '" fill="none" stroke="' + color + '" stroke-width="2"/>';
    points.forEach(function (point, i) {
      var selected = i === selectedIndex;
      svg += '<circle cx="' + xAt(i) + '" cy="' + yAt(point[key]) + '" r="' +
        (selected ? 5 : 3) + '" fill="' + color + '"/>';
      if (selected) {
        svg += '<text x="' + xAt(i) + '" y="' + (yAt(point[key]) - 8) +
          '" text-anchor="middle" class="chart-n">' + Number(point[key] || 0) + "</text>";
      }
      if (showLabel(i)) {
        svg += '<text x="' + xAt(i) + '" y="' + (h - 8) + '" text-anchor="middle" class="chart-lab">' +
          esc(labels[i] || "") + "</text>";
      }
    });
    return svg + "</svg>";
  }

  function bundleDate(bundle) {
    var raw = String((bundle && bundle.generated) || "");
    if (raw.length >= 10) return raw.slice(0, 10);
    var match = String((bundle && bundle.bundle_id) || "").match(/(\d{4})(\d{2})(\d{2})T/);
    return match ? match[1] + "-" + match[2] + "-" + match[3] : "";
  }

  var COUNTERMEASURE_MEANING = {
    present: "Defense is in the current product code.",
    absent: "No defense found. This finding is still open.",
    partial: "Some defense exists, but it is not complete."
  };

  function countermeasureMeaning(status) {
    var key = String(status || "").trim().toLowerCase();
    return COUNTERMEASURE_MEANING[key] || "Status is not present, absent, or partial.";
  }

  function scoreLabel(value) {
    var text = String(value || "").trim();
    return text ? text.replace(/_/g, " ") : "—";
  }

  function scoreRows(cluster) {
    return [
      ["Required for app", scoreLabel(cluster && cluster.required_for_app)],
      ["Install risk", scoreLabel(cluster && cluster.install_risk)],
      ["Skip risk", scoreLabel(cluster && cluster.skip_risk)],
      ["Compatibility", scoreLabel(cluster && cluster.compatibility)]
    ];
  }

  function scoreList(cluster) {
    var html = '<dl class="score-list">';
    scoreRows(cluster).forEach(function (row) {
      html += "<div><dt>" + esc(row[0]) + "</dt><dd>" + esc(row[1]) + "</dd></div>";
    });
    return html + "</dl>";
  }

  function stationCount(bundle) {
    if (bundle && bundle.counts && bundle.counts.stations !== undefined && bundle.counts.stations !== "") {
      return bundle.counts.stations;
    }
    var seen = {};
    ((bundle && bundle.packages) || []).forEach(function (item) {
      (item.stations || []).forEach(function (id) { seen[id] = 1; });
    });
    return Object.keys(seen).length;
  }

  function bundleSummary(run) {
    var bundle = run && run.bundle;
    if (!bundle) return "No Windows host update pack on this run.";
    var counted = countPackages(bundle.packages || []);
    var when = bundleDate(bundle) || String((run && run.created_at) || "").slice(0, 10);
    var runBit = run && run.run_id ? "This run (" + run.run_id + ")" : "This run";
    return runBit + " host Windows update pack" + (when ? " from " + when : "") +
      ". " + counted.deploy + " for lab check. " + counted.hold +
      " held — do not install. Covers " + stationCount(bundle) + " stations.";
  }

  function glance(run) {
    var findings = countFindings(run.findings || []);
    var packages = countPackages(((run.bundle || {}).packages) || []);
    var risks = countRisks(run.clusters || []);
    var points = trendPoints(allSnapshots());
    var parts = ['<section class="charts">'];
    parts.push('<article class="chart-card"><h3>Countermeasures</h3>');
    parts.push(hbars([
      { label: "present", value: findings.present, color: "#111111" },
      { label: "partial", value: findings.partial, color: "#4d4d4d" },
      { label: "absent", value: findings.absent, color: "#CC0000" }
    ]));
    parts.push('<p class="chart-cap">' + findings.absent + " absent of " + findings.total + " findings</p></article>");
    parts.push('<article class="chart-card"><h3>Host KB</h3>');
    parts.push(stackedBars([
      {
        label: "deploy",
        parts: [
          { value: packages.deploy_other, color: "#d9dee7" },
          { value: packages.deploy_high, color: "#4d4d4d" },
          { value: packages.deploy_critical, color: "#CC0000" }
        ]
      },
      {
        label: "hold",
        parts: [
          { value: packages.hold_other, color: "#d9dee7" },
          { value: packages.hold_high, color: "#4d4d4d" },
          { value: packages.hold_critical, color: "#CC0000" }
        ]
      }
    ]));
    parts.push('<p class="chart-cap">' + packages.deploy + " for lab check · " + packages.hold +
      " held · " + packages.deploy_critical + " critical in the lab set</p>");
    parts.push('<p class="chart-legend">Red critical · gray high · light other</p></article>');
    parts.push('<article class="chart-card"><h3>Impact clusters</h3>');
    parts.push(hbars([
      { label: "stays_vulnerable", value: risks.stays_vulnerable, color: "#CC0000" },
      { label: "may_break_app", value: risks.may_break_app, color: "#4d4d4d" },
      { label: "no_app_impact", value: risks.no_app_impact, color: "#111111" },
      { label: "compatible", value: risks.compatible, color: "#111111" }
    ]));
    parts.push('<p class="chart-cap">' + risks.stays_vulnerable + " stay vulnerable · " +
      risks.may_break_app + " may break app</p></article>");
    parts.push("</section>");
    parts.push('<section class="chart-wide"><h3>90 days</h3>');
    parts.push('<p class="chart-cap">' + esc(trendCaption(points, run.run_id)) + "</p>");
    parts.push('<p class="chart-legend">Still-open findings</p>');
    parts.push(trendRow(points, run.run_id, "absent", "#CC0000"));
    parts.push('<p class="chart-legend">KB for lab check</p>');
    parts.push(trendRow(points, run.run_id, "deploy", "#111111"));
    parts.push("</section>");
    return parts.join("");
  }

  function bindPackageSort() {
    var heads = app.querySelectorAll("th.sortable");
    heads.forEach(function (th) {
      th.addEventListener("click", function () {
        var key = th.getAttribute("data-sort");
        if (pkgSort.key === key) pkgSort.dir = -pkgSort.dir;
        else {
          pkgSort.key = key;
          pkgSort.dir = 1;
        }
        if (currentRun) render(currentRun);
      });
    });
  }

  function bindStationFilter() {
    var input = document.getElementById("station-filter");
    if (!input) return;
    input.value = pkgStation;
    input.addEventListener("input", applyStationFilter);
    applyStationFilter();
  }

  function render(run) {
    currentRun = run;
    if (!run) {
      app.innerHTML = '<p class="empty">No snapshot for this run.</p>';
      return;
    }
    var bundle = run.bundle || null;
    var findings = run.findings || [];
    var clusters = run.clusters || [];
    var parts = [];
    parts.push('<section class="meta">');
    [
      ["Created", esc(run.created_at)],
      ["Orchestrator run", run.run_url ? link(run.run_url, run.run_id) : esc(run.run_id)],
      ["FindUpdates run", (function () {
        var href = run.findupdates_url || (run.findupdates_run_id ? "https://github.com/defrances/FindUpdates/actions/runs/" + run.findupdates_run_id : "");
        return href ? link(href, run.findupdates_run_id) : esc(text(run.findupdates_run_id));
      })()],
      ["DesktopApplication SHA", (function () {
        var href = run.sha_url || (run.sha ? "https://github.com/defrances/DesktopApplication/commit/" + run.sha : "");
        return href ? link(href, run.sha) : esc(run.sha);
      })()],
    ].forEach(function (row) {
      parts.push("<div><dt>" + esc(row[0]) + "</dt><dd>" + row[1] + "</dd></div>");
    });
    parts.push("</section>");
    parts.push(glance(run));

    parts.push("<h2>Impact</h2>");
    if (run.no_clusters || !clusters.length) {
      parts.push('<p class="empty">No vendor-update clusters for this run.</p>');
    } else {
      parts.push('<div class="cards">');
      clusters.forEach(function (cluster) {
        parts.push(
          '<article class="card"><h3>' +
            esc(cluster.title) +
            '</h3><p class="sub">' +
            esc(cluster.cluster_key) +
            " · " +
            esc(cluster.device_id) +
            "</p>" +
            scoreList(cluster) +
            "</article>"
        );
      });
      parts.push("</div>");
    }

    parts.push("<h2>Countermeasures</h2>");
    if (!findings.length) {
      parts.push('<p class="empty">No PDLC analysis.json on this run.</p>');
    } else {
      parts.push('<p class="chart-cap">PRESENT: defense is in the current product code. ABSENT: no defense found. PARTIAL: incomplete defense.</p>');
      parts.push('<div class="cards">');
      findings.forEach(function (item) {
        parts.push(
          '<article class="card"><h3>' +
            esc(item.id) +
            " — " +
            esc(item.title) +
            '</h3><span class="tag ' +
            esc(item.countermeasure) +
            '">' +
            esc(item.countermeasure) +
            '</span><p class="meaning">' +
            esc(countermeasureMeaning(item.countermeasure)) +
            "</p></article>"
        );
      });
      parts.push("</div>");
    }

    parts.push("<h2>Patch package</h2>");
    if (!bundle) {
      parts.push('<p class="empty">No Windows patch bundle on this run.</p>');
    } else {
      parts.push("<p>" + esc(bundleSummary(run)) + "</p>");
      if (bundle.bundle_id) {
        parts.push('<p class="chart-cap">Pack id ' + esc(bundle.bundle_id) + "</p>");
      }
      parts.push('<label class="station-filter"><span>Stations</span>');
      parts.push('<input id="station-filter" type="search" placeholder="Type a station name" autocomplete="off"></label>');
      parts.push('<p id="station-filter-cap" class="chart-cap"></p>');
      parts.push('<div class="table-wrap"><table><thead><tr>');
      parts.push('<th class="' + sortClass("kb") + '" data-sort="kb">KB</th>');
      parts.push('<th class="' + sortClass("severity") + '" data-sort="severity">Severity</th>');
      parts.push('<th class="' + sortClass("deploy") + '" data-sort="deploy">Deploy</th>');
      parts.push('<th class="' + sortClass("stations") + '" data-sort="stations">Stations</th>');
      parts.push("<th>Official</th></tr></thead><tbody>");
      sortedPackages(bundle.packages).forEach(function (pkg) {
        var stations = (pkg.stations || []).join(", ");
        parts.push(
          '<tr data-stations="' +
            esc(stations) +
            '"><td>' +
            esc(pkg.kb) +
            "</td><td>" +
            esc(pkg.severity) +
            "</td><td>" +
            (pkg.include_in_deploy ? "yes" : "no") +
            "</td><td>" +
            esc(stations) +
            "</td><td>" +
            (pkg.official_url ? link(pkg.official_url, "MSRC") : "—") +
            "</td></tr>"
        );
      });
      parts.push('<tr id="station-filter-empty" hidden><td colspan="5">No KBs for this station.</td></tr>');
      parts.push("</tbody></table></div>");
    }

    app.innerHTML = parts.join("");
    bindPackageSort();
    bindStationFilter();
  }

  function show(runId) {
    var snap = snapshots[runId] || snapshots[String(runId)];
    if (snap) {
      render(snap);
      return;
    }
    fetch("data/history/" + encodeURIComponent(runId) + ".json")
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(render)
      .catch(function () { render(null); });
  }

  (index.runs || []).forEach(function (row) {
    var opt = document.createElement("option");
    opt.value = row.run_id;
    opt.textContent = row.label || row.run_id;
    if (row.run_id === index.latest) opt.selected = true;
    select.appendChild(opt);
  });
  select.addEventListener("change", function () { show(select.value); });
  show(index.latest || (index.runs[0] && index.runs[0].run_id));
})();
"""


if __name__ == "__main__":
    raise SystemExit(main())
