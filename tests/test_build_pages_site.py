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
            _write(
                work / "artifacts" / "ai-usage.json",
                {
                    "summary": {
                        "provider": "agent",
                        "model": "composer-2.5",
                        "total_tokens": 18240,
                        "cost_usd": 0.12,
                    }
                },
            )

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
            self.assertEqual(first["ai"], {"provider": "agent", "model": "composer-2.5"})
            self.assertEqual(pages.format_ai_usage(first["ai"]), "Analysis used agent, model composer-2.5.")
            self.assertNotIn("tokens", pages.format_ai_usage(first["ai"]).lower())
            self.assertNotIn("cost", pages.format_ai_usage(first["ai"]).lower())
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
            self.assertIn("Desktop Application", html)
            self.assertNotIn("Orchestrator · DesktopApplication", html)
            app_js = (out2 / "assets" / "app.js").read_text(encoding="utf-8")
            self.assertIn("Desktop Application SHA", app_js)
            self.assertIn("function glance", app_js)
            self.assertIn("90 days", app_js)
            self.assertIn("function configBars", app_js)
            self.assertIn("KB × configurations", app_js)
            self.assertIn("NA = not applicable", app_js)
            self.assertIn("Vendor risk", app_js)
            self.assertIn("function configUpdateCounts", app_js)
            self.assertIn("applicable for our platform", app_js)
            self.assertIn("recommended to install", app_js)
            self.assertIn('fill="#CC0000"', app_js)
            self.assertIn('fill="#111111"', app_js)
            self.assertIn("Configurations", app_js)
            self.assertNotIn("<h3>Countermeasures</h3>", app_js)
            self.assertNotIn("<h2>Countermeasures</h2>", app_js)
            self.assertNotIn("<h3>Host KB</h3>", app_js)
            self.assertNotIn("<h3>Skip or install</h3>", app_js)
            self.assertNotIn("Still-open findings", app_js)
            self.assertNotIn("test failed", app_js)
            self.assertNotIn("key: \"failed\"", app_js)
            self.assertIn("function scoreList", app_js)
            self.assertIn("Required for app", app_js)
            self.assertIn("function infoTip", app_js)
            self.assertIn("function formatAiUsage", app_js)
            self.assertNotIn("model tokens", app_js)
            self.assertNotIn("cost is not available", app_js)
            self.assertNotIn("cost_usd", app_js)
            self.assertIn("site-footer", html)
            self.assertIn("info-slot", app_js)
            self.assertIn("function realClusters", app_js)
            self.assertIn("info-mark", app_js)
            self.assertIn("configuration stays exposed on that host path", app_js)
            self.assertNotIn("required_for_app ", app_js)
            self.assertNotIn("function countermeasureMeaning", app_js)
            self.assertNotIn("Defense is in the product code on main.", app_js)
            self.assertNotIn("No defense found. This finding is still open.", app_js)
            self.assertNotIn("Test gate", app_js)
            self.assertNotIn("Release package", app_js)
            self.assertNotIn("exe is not offered here", app_js)
            self.assertNotIn('["Conclusion"', app_js)
            self.assertNotIn('["Workflow"', app_js)
            self.assertIn("function applyStationFilter", app_js)
            self.assertIn("id=\"station-filter\"", app_js)
            self.assertIn("Type a configuration name", app_js)
            self.assertIn("function configNameMap", app_js)
            self.assertIn('"Configurations"', app_js)
            self.assertNotIn(".replace(/^SYNTHETIC-/", app_js)
            html_banner = html
            self.assertIn("Configurations are synthetic lab fixtures", html_banner)
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
        configs = pages.config_update_counts(
            [
                {"kb": "KB1", "include_in_deploy": True, "stations": ["CFG-A", "CFG-B"]},
                {"kb": "KB2", "include_in_deploy": False, "stations": ["CFG-A"]},
                {"kb": "KB1", "include_in_deploy": True, "stations": ["CFG-A"]},
            ]
        )
        by_name = {item["name"]: item for item in configs}
        self.assertEqual(by_name["CFG-A"]["recommended"], 1)
        self.assertEqual(by_name["CFG-A"]["ignored"], 1)
        self.assertEqual(by_name["CFG-B"]["recommended"], 1)
        self.assertEqual(by_name["CFG-B"]["ignored"], 0)
        caption = pages.config_chart_caption(configs, run_id="9", history_n=3)
        self.assertIn("This run (9)", caption)
        self.assertIn("1 applicable for our platform", caption)
        self.assertIn("2 recommended to install", caption)
        self.assertIn("2 configurations", caption)
        self.assertIn("3 runs in the last 90 days", caption)
        labels = pages.config_display_names(
            ["SYNTHETIC-W11-24H2-01", "SYNTHETIC-CT-IMG-01", "SYNTHETIC-LAB-24H2-01"]
        )
        self.assertEqual(labels["SYNTHETIC-CT-IMG-01"], "Configurations1")
        self.assertEqual(labels["SYNTHETIC-LAB-24H2-01"], "Configurations2")
        self.assertEqual(labels["SYNTHETIC-W11-24H2-01"], "Configurations3")

    def test_config_chart_caption_grows_with_history(self) -> None:
        rows = [{"name": "CFG-A", "recommended": 2, "ignored": 1}]
        short = pages.config_chart_caption(rows, run_id="1", history_n=1)
        self.assertIn("History will grow with later runs.", short)
        long = pages.config_chart_caption(rows, run_id="2", history_n=4)
        self.assertIn("4 runs in the last 90 days", long)
        self.assertNotIn("still open", long)

    def test_kb_config_matrix_marks_na(self) -> None:
        matrix = pages.kb_config_matrix(
            [
                {
                    "kb": "KB1",
                    "severity": "HIGH",
                    "stations": ["SYNTHETIC-CT-IMG-01", "SYNTHETIC-LAB-24H2-01"],
                },
                {
                    "kb": "KB2",
                    "severity": "LOW",
                    "stations": ["SYNTHETIC-LAB-24H2-01"],
                },
            ]
        )
        self.assertEqual(matrix["columns"], ["Configurations1", "Configurations2"])
        by_kb = {row["kb"]: row["cells"] for row in matrix["rows"]}
        self.assertNotEqual(by_kb["KB1"][0], "NA")
        self.assertEqual(by_kb["KB2"][0], "NA")
        self.assertNotEqual(by_kb["KB2"][1], "NA")

    def test_ai_usage_line(self) -> None:
        self.assertEqual(
            pages.format_ai_usage(None),
            "AI usage was not recorded for this run.",
        )
        self.assertEqual(
            pages.format_ai_usage({"provider": "offline", "model": ""}),
            "Analysis used offline scripts.",
        )

    def test_countermeasure_meaning(self) -> None:
        self.assertEqual(
            pages.countermeasure_meaning("PRESENT"),
            "Defense is in the product code on main.",
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
                "vendor_severity": "C",
                "vendor_likelihood": "H",
                "vendor_risk": "H",
                "product_severity": "L",
                "product_likelihood": "L",
                "product_risk": "L",
            }
        )
        self.assertEqual(
            rows[:4],
            [
                ("Required for app", "Not required"),
                ("If we install", "Compatible with the app"),
                ("If we skip", "Configuration stays exposed"),
                ("Compatibility", "Compatible with the app"),
            ],
        )
        self.assertEqual(rows[6], ("Vendor risk", "H"))
        self.assertEqual(rows[9], ("Product risk", "L"))
        self.assertEqual(pages.chart_risk_label("stays_vulnerable"), "Skip: still exposed")
        self.assertIn("configuration stays exposed", pages.RISK_HINTS["stays_vulnerable"])
        self.assertIn(
            "6 stay exposed if we skip the KB",
            pages.risk_chart_caption({"stays_vulnerable": 6, "may_break_app": 0, "no_app_impact": 2, "compatible": 0}),
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
            _write(
                work / "issues-out" / "ai-usage.json",
                {"schema_version": 1, "tasks": [], "summary": {"provider": "agent"}},
            )
            clusters, none_marker = pages.collect_clusters(work)
            self.assertEqual(clusters, [])
            self.assertTrue(none_marker)


if __name__ == "__main__":
    unittest.main()
