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
            app_js = (out2 / "assets" / "app.js").read_text(encoding="utf-8")
            self.assertIn("function glance", app_js)
            self.assertIn("90 days", app_js)
            self.assertIn("function trendRow", app_js)
            self.assertIn("function trendCaption", app_js)
            self.assertIn("Still-open findings", app_js)
            self.assertIn("Counts did not change", app_js)
            self.assertNotIn("test failed", app_js)
            self.assertNotIn("key: \"failed\"", app_js)
            self.assertIn("function scoreList", app_js)
            self.assertIn("Required for app", app_js)
            self.assertNotIn("required_for_app ", app_js)
            self.assertIn("function countermeasureMeaning", app_js)
            self.assertIn("Defense is in the current product code.", app_js)
            self.assertIn("No defense found. This finding is still open.", app_js)
            self.assertNotIn("Test gate", app_js)
            self.assertNotIn("Release package", app_js)
            self.assertNotIn("exe is not offered here", app_js)
            self.assertNotIn('["Conclusion"', app_js)
            self.assertNotIn('["Workflow"', app_js)
            self.assertIn("function applyStationFilter", app_js)
            self.assertIn("id=\"station-filter\"", app_js)
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

    def test_parse_test_run_successful_block(self) -> None:
        text = (
            "Test run for /tmp/DesktopApplication.Tests.dll\n"
            "Test Run Successful.\n"
            "Total tests: 3\n"
            "     Passed: 3\n"
            " Total time: 10.7176 Seconds\n"
        )
        result = pages.parse_test_results(text)
        self.assertEqual(result["outcome"], "passed")
        self.assertEqual(result["passed"], 3)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["total"], 3)

    def test_count_findings_and_packages_and_trend(self) -> None:
        findings = [
            {"id": "A", "countermeasure": "present"},
            {"id": "B", "countermeasure": "absent"},
            {"id": "C", "countermeasure": "present"},
        ]
        self.assertEqual(pages.count_findings(findings)["absent"], 1)
        self.assertEqual(pages.count_findings(findings)["present"], 2)
        packages = [
            {"severity": "CRITICAL", "include_in_deploy": True},
            {"severity": "HIGH", "include_in_deploy": True},
            {"severity": "HIGH", "include_in_deploy": False},
        ]
        counted = pages.count_packages(packages)
        self.assertEqual(counted["deploy"], 2)
        self.assertEqual(counted["hold"], 1)
        self.assertEqual(counted["deploy_critical"], 1)
        risks = pages.count_risks(
            [
                {"skip_risk": "stays_vulnerable"},
                {"skip_risk": "", "install_risk": "may_break_app"},
                {"skip_risk": "no_app_impact"},
            ]
        )
        self.assertEqual(risks["stays_vulnerable"], 1)
        self.assertEqual(risks["may_break_app"], 1)
        points = pages.trend_points(
            [
                {
                    "run_id": "2",
                    "created_at": "2026-09-24T00:00:00Z",
                    "findings": findings,
                    "bundle": {"packages": packages},
                },
                {
                    "run_id": "1",
                    "created_at": "2026-09-23T00:00:00Z",
                    "findings": [{"countermeasure": "absent"}],
                    "bundle": {"packages": []},
                },
            ]
        )
        self.assertEqual([row["run_id"] for row in points], ["1", "2"])
        self.assertEqual(points[0]["absent"], 1)
        self.assertNotIn("failed", points[0])
        self.assertEqual(points[1]["deploy"], 2)

    def test_trend_labels_use_time_when_runs_share_one_day(self) -> None:
        same_day = [
            {"run_id": "1", "created_at": "2026-09-25T18:01:00Z", "absent": 1, "deploy": 20},
            {"run_id": "2", "created_at": "2026-09-25T18:40:00Z", "absent": 1, "deploy": 20},
        ]
        self.assertEqual(pages.trend_x_labels(same_day), ["18:01", "18:40"])
        self.assertTrue(pages.trend_is_flat(same_day, "deploy"))
        caption = pages.trend_caption(same_day, selected_id="2")
        self.assertIn("This run: 1 still open · 20 KB for lab check.", caption)
        self.assertIn("Axis shows run time", caption)
        self.assertIn("Counts did not change.", caption)
        mixed = [
            {"run_id": "1", "created_at": "2026-09-23T10:00:00Z", "absent": 2, "deploy": 4},
            {"run_id": "2", "created_at": "2026-09-25T18:40:00Z", "absent": 1, "deploy": 20},
        ]
        self.assertEqual(pages.trend_x_labels(mixed), ["23 Sep", "25 Sep"])
        self.assertNotIn("Counts did not change.", pages.trend_caption(mixed, selected_id="2"))

    def test_countermeasure_meaning(self) -> None:
        self.assertEqual(
            pages.countermeasure_meaning("PRESENT"),
            "Defense is in the current product code.",
        )
        self.assertEqual(
            pages.countermeasure_meaning("absent"),
            "No defense found. This finding is still open.",
        )
        self.assertEqual(
            pages.countermeasure_meaning("partial"),
            "Some defense exists, but it is not complete.",
        )

    def test_packages_for_station_filters_partial_name(self) -> None:
        packages = [
            {"kb": "KB1", "stations": ["SYNTHETIC-PACS-01", "SYNTHETIC-W11-24H2-01"]},
            {"kb": "KB2", "stations": ["SYNTHETIC-US-01"]},
            {"kb": "KB3", "stations": ["SYNTHETIC-LAB-24H2-01"]},
        ]
        self.assertEqual(
            [item["kb"] for item in pages.packages_for_station(packages, "pacs")],
            ["KB1"],
        )
        self.assertEqual(
            [item["kb"] for item in pages.packages_for_station(packages, "24H2")],
            ["KB1", "KB3"],
        )
        self.assertEqual(
            [item["kb"] for item in pages.packages_for_station(packages, "")],
            ["KB1", "KB2", "KB3"],
        )
        self.assertEqual(pages.packages_for_station(packages, "missing"), [])

    def test_score_rows_are_a_list(self) -> None:
        rows = pages.score_rows(
            {
                "required_for_app": "not_required",
                "install_risk": "compatible",
                "skip_risk": "stays_vulnerable",
                "compatibility": "compatible",
            }
        )
        self.assertEqual(
            rows,
            [
                ("Required for app", "not required"),
                ("Install risk", "compatible"),
                ("Skip risk", "stays vulnerable"),
                ("Compatibility", "compatible"),
            ],
        )
        empty = pages.score_rows({})
        self.assertEqual(empty[0], ("Required for app", "—"))

    def test_bundle_summary_follows_the_selected_run(self) -> None:
        first = {
            "generated": "2026-09-23T10:00:00Z",
            "counts": {"stations": 7},
            "packages": [
                {"severity": "HIGH", "include_in_deploy": True, "stations": ["A"]},
                {"severity": "LOW", "include_in_deploy": False, "stations": ["B"]},
            ],
        }
        second = {
            "generated": "2026-09-25T18:37:11Z",
            "counts": {"stations": 3},
            "packages": [
                {"severity": "CRITICAL", "include_in_deploy": True, "stations": ["A"]},
                {"severity": "HIGH", "include_in_deploy": True, "stations": ["B"]},
                {"severity": "HIGH", "include_in_deploy": True, "stations": ["C"]},
            ],
        }
        one = pages.bundle_summary(first, run_id="111")
        two = pages.bundle_summary(second, run_id="222")
        self.assertIn("This run (111)", one)
        self.assertIn("1 for lab check", one)
        self.assertIn("1 held", one)
        self.assertIn("This run (222)", two)
        self.assertIn("3 for lab check", two)
        self.assertIn("0 held", two)
        self.assertNotEqual(one, two)

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
