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
    match = TEST_SUMMARY_RE.search(text or "")
    if not match:
        return {
            "outcome": "unknown",
            "failed": None,
            "passed": None,
            "skipped": None,
            "total": None,
            "filter": "Smoke|Regression",
        }
    return {
        "outcome": match.group(1).lower(),
        "failed": int(match.group(2)),
        "passed": int(match.group(3)),
        "skipped": int(match.group(4)),
        "total": int(match.group(5)),
        "filter": "Smoke|Regression",
    }


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
    return {
        "bundle_id": str(payload.get("bundle_id") or ""),
        "generated": str(payload.get("generated") or ""),
        "findupdates_run_id": str(payload.get("findupdates_run_id") or ""),
        "findupdates_html_url": str(payload.get("findupdates_html_url") or ""),
        "counts": payload.get("counts") if isinstance(payload.get("counts"), dict) else {},
        "packages": packages,
    }


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
.card h3 { margin: 0 0 0.45rem; font-size: 0.95rem; }
.score { font-size: 0.85rem; color: var(--muted); }
.tag { display: inline-block; padding: 0.1rem 0.4rem; border: 1px solid var(--line); font-size: 0.75rem; text-transform: uppercase; }
.tag.absent, .tag.failed { border-color: var(--red); color: var(--red); }
.tag.present, .tag.passed { border-color: #111; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { text-align: left; padding: 0.4rem 0.35rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: normal; }
a { color: inherit; }
.empty { color: var(--muted); }
footer { color: var(--muted); font-size: 0.8rem; padding-bottom: 2rem; }
"""

APP_JS = r"""(function () {
  var app = document.getElementById("app");
  var select = document.getElementById("run-select");
  var index = window.SITE_INDEX || { runs: [], latest: "" };
  var snapshots = window.SITE_SNAPSHOTS || {};

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

  function render(run) {
    if (!run) {
      app.innerHTML = '<p class="empty">No snapshot for this run.</p>';
      return;
    }
    var tests = run.tests || {};
    var bundle = run.bundle || null;
    var release = run.release || null;
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
      ["Conclusion", esc(run.conclusion)],
      ["Workflow", esc(run.workflow)],
    ].forEach(function (row) {
      parts.push("<div><dt>" + esc(row[0]) + "</dt><dd>" + row[1] + "</dd></div>");
    });
    parts.push("</section>");

    parts.push("<h2>Impact</h2>");
    if (run.no_clusters || !clusters.length) {
      parts.push('<p class="empty">No vendor-update clusters for this run.</p>');
    } else {
      parts.push('<div class="cards">');
      clusters.forEach(function (cluster) {
        parts.push(
          '<article class="card"><h3>' +
            esc(cluster.title) +
            "</h3><p>" +
            esc(cluster.cluster_key) +
            " · " +
            esc(cluster.device_id) +
            '</p><p class="score">required_for_app ' +
            esc(cluster.required_for_app) +
            " · install_risk " +
            esc(cluster.install_risk) +
            " · skip_risk " +
            esc(cluster.skip_risk) +
            " · compatibility " +
            esc(cluster.compatibility) +
            "</p></article>"
        );
      });
      parts.push("</div>");
    }

    parts.push("<h2>Countermeasures</h2>");
    if (!findings.length) {
      parts.push('<p class="empty">No PDLC analysis.json on this run.</p>');
    } else {
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
            "</span></article>"
        );
      });
      parts.push("</div>");
    }

    parts.push("<h2>Patch package</h2>");
    if (!bundle) {
      parts.push('<p class="empty">No Windows patch bundle on this run.</p>');
    } else {
      var counts = bundle.counts || {};
      parts.push(
        '<p>' +
          esc(bundle.bundle_id) +
          " · deploy " +
          esc(counts.deploy) +
          " · do_not_install " +
          esc(counts.do_not_install) +
          " · stations " +
          esc(counts.stations) +
          "</p>"
      );
      parts.push('<div class="table-wrap"><table><thead><tr><th>KB</th><th>Severity</th><th>Deploy</th><th>Stations</th><th>Official</th></tr></thead><tbody>');
      (bundle.packages || []).forEach(function (pkg) {
        parts.push(
          "<tr><td>" +
            esc(pkg.kb) +
            "</td><td>" +
            esc(pkg.severity) +
            "</td><td>" +
            (pkg.include_in_deploy ? "yes" : "no") +
            "</td><td>" +
            esc((pkg.stations || []).join(", ")) +
            "</td><td>" +
            (pkg.official_url ? link(pkg.official_url, "MSRC") : "—") +
            "</td></tr>"
        );
      });
      parts.push("</tbody></table></div>");
    }

    parts.push("<h2>Test gate</h2>");
    parts.push(
      '<p><span class="tag ' +
        esc(tests.outcome) +
        '">' +
        esc(tests.outcome) +
        "</span> passed " +
        esc(tests.passed) +
        " · failed " +
        esc(tests.failed) +
        " · total " +
        esc(tests.total) +
        " · filter " +
        esc(tests.filter) +
        "</p>"
    );

    parts.push("<h2>Release package</h2>");
    if (!release || !release.zip_name) {
      parts.push('<p class="empty">No win-x64 zip name recorded. The exe is not published on this page.</p>');
    } else {
      parts.push("<p>" + esc(release.zip_name) + " — exe is not offered here. Download the Actions artifact if needed.</p>");
    }
    app.innerHTML = parts.join("");
  }

  function show(runId) {
    if (snapshots[runId]) {
      render(snapshots[runId]);
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
