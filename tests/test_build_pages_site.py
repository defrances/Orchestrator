#!/usr/bin/env python3
"""Pages builder is deterministic and keeps a 90-day history."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-pages-site.py"
SPEC = importlib.util.spec_from_file_location("build_pages_site", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot load {SCRIPT}")
pages = importlib.util.module_from_spec(SPEC)
sys.modules["build_pages_site"] = pages
SPEC.loader.exec_module(pages)


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
        return
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class BuildPagesSiteTests(unittest.TestCase):
    def test_snapshot_and_history_switch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw) / "run"
            _write(
                work / "issues-out" / "01-schannel-tls-SYNTHETIC-W11-24H2-01.json",
                {
                    "title": "[Impact] schannel-tls on SYNTHETIC-W11-24H2-01",
                    "cluster_key": "schannel-tls",
                    "device_id": "SYNTHETIC-W11-24H2-01",
                    "required_for_app": "not_required",
                    "install_risk": "compatible",
                    "skip_risk": "stays_vulnerable",
                    "compatibility": "compatible",
                },
            )
            _write(
                work / "pdlc-out" / "analysis.json",
                {
                    "product": "DesktopApplication",
                    "branch": "main",
                    "sha": "abc1234",
                    "findings": [{"id": "VR-TLS-001", "title": "TLS", "countermeasure": "present"}],
                    "tests_filter": "Smoke|Regression",
                },
            )
            _write(
                work / "artifacts" / "windows-bundle" / "demo" / "BUNDLE_MANIFEST.json",
                {
                    "bundle_id": "windows-patch-bundle-live-1",
                    "generated": "2026-09-23T17:46:29Z",
                    "findupdates_run_id": "111",
                    "counts": {"deploy": 1, "do_not_install": 0, "stations": 1},
                    "packages": [
                        {
                            "kb": "KB5002916",
                            "title": "Graphics",
                            "include_in_deploy": True,
                            "severity": "HIGH",
                            "official_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-81955",
                            "stations": ["SYNTHETIC-W11-24H2-01"],
                            "cve_ids": ["CVE-2026-81955"],
                        }
                    ],
                },
            )
            _write(
                work / "artifacts" / "TEST_RESULTS.md",
                "Passed!  - Failed:     0, Passed:     4, Skipped:     0, Total:     4, Duration: 1 s\n",
            )
            _write(work / "artifacts" / "release" / "DesktopApplication-20260923T174629Z-9-win-x64.zip", "zip")

            first = pages.snapshot_from_workspace(
                work,
                env={
                    "GITHUB_RUN_ID": "9",
                    "GITHUB_REPOSITORY": "defrances/Orchestrator",
                    "ORCH_CONCLUSION": "success",
                    "FU_RUN_ID": "111",
                },
            )
            self.assertEqual(first["cluster_count"], 1)
            self.assertEqual(first["sha"], "abc1234")
            self.assertEqual(
                first["findupdates_url"],
                "https://github.com/defrances/FindUpdates/actions/runs/111",
            )
            self.assertEqual(
                first["sha_url"],
                "https://github.com/defrances/DesktopApplication/commit/abc1234",
            )
            self.assertEqual(first["tests"]["passed"], 4)
            self.assertEqual(first["release"]["zip_name"], "DesktopApplication-20260923T174629Z-9-win-x64.zip")
            self.assertEqual([pkg["kb"] for pkg in first["bundle"]["packages"]], ["KB5002916"])
            self.assertNotIn(".exe", json.dumps(first))
            first["created_at"] = "2026-09-23T17:46:29Z"

            out1 = Path(raw) / "site1"
            pages.write_site(out1, [first])

            _write(
                work / "issues-out" / "none.json",
                {"issues": []},
            )
            (work / "issues-out" / "01-schannel-tls-SYNTHETIC-W11-24H2-01.json").unlink()
            second = pages.snapshot_from_workspace(
                work,
                env={
                    "GITHUB_RUN_ID": "10",
                    "GITHUB_REPOSITORY": "defrances/Orchestrator",
                    "ORCH_CONCLUSION": "success",
                    "FU_RUN_ID": "112",
                },
            )
            second["created_at"] = "2026-09-24T18:00:00Z"
            existing = pages.load_history(out1)
            merged = pages.merge_history(existing, second)
            out2 = Path(raw) / "site2"
            index = pages.write_site(out2, merged)
            self.assertEqual(index["latest"], "10")
            self.assertEqual([row["run_id"] for row in index["runs"]], ["10", "9"])
            html = (out2 / "index.html").read_text(encoding="utf-8")
            self.assertIn("assets/data.js", html)
            data_js = (out2 / "assets" / "data.js").read_text(encoding="utf-8")
            self.assertIn('"10"', data_js)
            self.assertIn('"9"', data_js)
            latest = json.loads((out2 / "data" / "latest.json").read_text(encoding="utf-8"))
            self.assertTrue(latest["no_clusters"])

    def test_prunes_snapshots_older_than_90_days(self) -> None:
        now = datetime(2026, 9, 24, tzinfo=timezone.utc)
        old = {
            "run_id": "old",
            "created_at": (now - timedelta(days=91)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        keep = {
            "run_id": "keep",
            "created_at": (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        current = {"run_id": "new", "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
        merged = pages.merge_history([old, keep], current, now=now)
        self.assertEqual([item["run_id"] for item in merged], ["new", "keep"])

    def test_packages_sort_critical_then_kb(self) -> None:
        rows = pages.sort_packages(
            [
                {"kb": "KB5099999", "severity": "HIGH", "include_in_deploy": True},
                {"kb": "KB5000001", "severity": "CRITICAL", "include_in_deploy": True},
                {"kb": "KB5000002", "severity": "CRITICAL", "include_in_deploy": False},
                {"kb": "KB5000100", "severity": "LOW", "include_in_deploy": True},
            ]
        )
        self.assertEqual(
            [item["kb"] for item in rows],
            ["KB5000001", "KB5000002", "KB5099999", "KB5000100"],
        )

    def test_skips_none_and_summary_issue_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            _write(work / "issues-out" / "none.json", {"issues": []})
            _write(
                work / "issues-out" / "summary.json",
                {"title": "overflow", "cluster_key": "summary", "device_id": "overflow"},
            )
            clusters, none_marker = pages.collect_clusters(work)
            self.assertEqual(clusters, [])
            self.assertTrue(none_marker)


if __name__ == "__main__":
    unittest.main()
