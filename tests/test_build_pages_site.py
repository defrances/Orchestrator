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
                    "title": "[Impact] KB5002916 on Configurations1 - Schannel TLS host path",
                    "cluster_key": "schannel-tls",
                    "device_id": "Configurations1",
                    "packages": [],
                    "required_for_app": "not_required",
                    "install_risk": "compatible",
                    "skip_risk": "stays_vulnerable",
                    "compatibility": "compatible",
                    "body": (
                        "## Technical Impact Assessment\n\n"
                        "### Impacted Components\n\n"
                        "Host Schannel TLS. Cited `src/DesktopApplication/App.xaml`.\n"
                    ),
                },
            )
            _write(
                work / "pdlc-out" / "analysis.json",
                {
                    "product": "DesktopApplication",
                    "branch": "main",
                    "sha": "abc1234",
                    "findings": [
                        {
                            "id": "VR-TLS-001",
                            "title": "TLS",
                            "countermeasure": "present",
                            "evidence": "InsecureVendorBulletinClient accepts any certificate.",
                            "patch_plan": "Validate sslPolicyErrors.",
                            "tests_to_run": ["TC-REG-TLS-CALLBACK"],
                            "impact_files": ["src/DesktopApplication.Core/InsecureVendorBulletinClient.cs"],
                        }
                    ],
                    "os_kb_advice": [
                        "Host Schannel KBs stay a station recommendation and are not in the application zip."
                    ],
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
                            "known_exploited": "false",
                            "exploitability": "low",
                            "os_products": ["Windows 11 Version 24H2 for x64-based Systems"],
                            "deployment_groups": ["pacs-validate"],
                        }
                    ],
                },
            )
            _write(
                work / "artifacts" / "windows-bundle" / "demo" / "stations" / "SYNTHETIC-W11-24H2-01.json",
                {
                    "device_id": "SYNTHETIC-W11-24H2-01",
                    "model": "PACS-Validate-24H2",
                    "device_role": "pacs-review-workstation",
                    "os_product": "Windows 11 Version 24H2 for x64-based Systems",
                    "os_build": "10.0.26100.4200",
                    "deployment_group": "pacs-validate",
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
            self.assertEqual(first["clusters"][0]["packages"], ["KB5002916"])
            self.assertIn("Host Schannel TLS", first["clusters"][0]["impact"])
            self.assertIn("Host Schannel TLS", first["clusters"][0]["body"])
            self.assertEqual(first["bundle"]["packages"][0]["os_products"], [
                "Windows 11 Version 24H2 for x64-based Systems"
            ])
            self.assertEqual(first["clusters"][0]["config_label"], "Configurations1")
            self.assertEqual(first["bundle"]["packages"][0]["vendor_severity"], "H")
            self.assertEqual(first["bundle"]["packages"][0]["vendor_likelihood"], "L")
            self.assertEqual(first["findings"][0]["evidence"][:24], "InsecureVendorBulletinCl")
            self.assertTrue(first["os_kb_advice"][0].startswith("Host Schannel"))
            self.assertEqual(first["bundle"]["stations"][0]["os_build"], "10.0.26100.4200")
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
            self.assertIn("Alcon", html)
            self.assertIn("Windows Patch Management", html)
            self.assertNotIn("Orchestrator · DesktopApplication", html)
            app_js = (out2 / "assets" / "app.js").read_text(encoding="utf-8")
            self.assertIn("Alcon", app_js)
            self.assertIn("Manager View", app_js)
            self.assertIn("Engineer View", app_js)
            self.assertIn("Host Application SHA", app_js)
            self.assertIn("function glance", app_js)
            self.assertIn("90 days", app_js)
            self.assertIn("function configBars", app_js)
            self.assertIn("KB × configurations", app_js)
            self.assertIn("NA = not applicable", app_js)
            self.assertIn("Vendor risk", app_js)
            self.assertIn("function configUpdateCounts", app_js)
            self.assertIn("applicable for our platform", app_js)
            self.assertIn("recommended to install", app_js)
            self.assertIn('fill="#ef3e4e"', app_js)
            self.assertIn('fill="#0b57b8"', app_js)
            self.assertIn("Configurations", app_js)
            self.assertNotIn("KB5082052", app_js)
            self.assertNotIn("KB5099414", app_js)
            self.assertNotIn("Windchill", app_js)
            self.assertNotIn("Quality Review", app_js)
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
            self.assertIn('["Conclusion"', app_js)
            self.assertIn('["Workflow"', app_js)
            self.assertIn("kb-search", app_js)
            self.assertIn("Search KB or title", app_js)
            self.assertIn("function configNameMap", app_js)
            self.assertIn('"Configurations"', app_js)
            self.assertNotIn(".replace(/^SYNTHETIC-/", app_js)
            self.assertIn("function clusterMatchesPkg", app_js)
            self.assertIn("function filledScore", app_js)
            self.assertNotIn("KB5082052", app_js)
            self.assertIn("function clusterImpactText", app_js)
            self.assertIn("This KB across loaded runs", app_js)
            self.assertIn("function displayProduct", app_js)
            self.assertIn("PDLC findings", app_js)
            self.assertIn("Host OS products", app_js)
            self.assertIn("Release and Evidence", app_js)
            self.assertIn("function clusterKeyLabel", app_js)
            self.assertIn('class="stepper"', app_js)
            self.assertIn('class="timeline"', app_js)
            self.assertIn('class="callout"', app_js)
            self.assertIn("View all", app_js)
            self.assertIn("All Patches", app_js)
            self.assertNotIn("Run now", app_js)
            self.assertNotIn("CTConsole", app_js)
            self.assertNotIn("KB5082052", app_js)
            css = (out2 / "assets" / "style.css").read_text(encoding="utf-8")
            self.assertIn(".stepper", css)
            self.assertIn(".timeline", css)
            self.assertIn(".callout", css)
            self.assertIn(".configRow", css)
            self.assertIn("repeat(5, 1fr)", css)
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

    def test_extract_kb_and_impact_excerpt(self) -> None:
        self.assertEqual(pages.extract_kb_ids("[Impact] KB5099414 on Configurations1 - Shell"), ["KB5099414"])
        self.assertEqual(
            pages.extract_kb_ids("dwm-wpf", "See KB5093998 and kb5099535"),
            ["KB5093998", "KB5099535"],
        )
        body = (
            "## Updates applicable for this product configuration\n\n"
            "table\n\n"
            "## Technical Impact Assessment\n\n"
            "### Impacted Components\n\n"
            "Host Shell launch path.\n\n"
            "### Potential Risks\n\n"
            "If we skip: Configuration stays exposed.\n\n"
            "## Cybersecurity impact assessment\n\n"
            "CVE text\n"
        )
        excerpt = pages.impact_excerpt(body)
        self.assertIn("Host Shell launch path", excerpt)
        self.assertIn("If we skip", excerpt)
        self.assertNotIn("Cybersecurity", excerpt)

    def test_enrich_snapshot_fills_empty_packages_and_sibling_keys(self) -> None:
        snapshot = pages.enrich_snapshot(
            {
                "run_id": "old",
                "clusters": [
                    {
                        "title": "[Impact] KB5099414 on Configurations1 - Shell may change exe launch",
                        "device_id": "Configurations1",
                        "cluster_key": "shell-launch",
                        "packages": None,
                        "required_for_app": "not_required",
                        "install_risk": "may_break_app",
                        "skip_risk": "stays_vulnerable",
                        "compatibility": "compatible",
                    },
                    {
                        "title": "[Impact] shell-launch on Configurations2 - Shell may change exe launch",
                        "device_id": "Configurations2",
                        "cluster_key": "shell-launch",
                        "packages": [],
                        "required_for_app": "not_required",
                        "install_risk": "may_break_app",
                        "skip_risk": "stays_vulnerable",
                        "compatibility": "compatible",
                    },
                ],
                "bundle": {
                    "packages": [
                        {
                            "kb": "KB5099414",
                            "severity": "CRITICAL",
                            "known_exploited": "false",
                            "exploitability": "low",
                            "stations": ["SYNTHETIC-CT-IMG-01", "SYNTHETIC-LAB-24H2-01"],
                        }
                    ]
                },
            }
        )
        clusters = {item["device_id"]: item for item in snapshot["clusters"]}
        self.assertEqual(clusters["Configurations1"]["packages"], ["KB5099414"])
        self.assertEqual(clusters["Configurations2"]["packages"], ["KB5099414"])
        self.assertIn("Shell may change exe launch", clusters["Configurations1"]["impact"])
        self.assertEqual(snapshot["bundle"]["packages"][0]["vendor_severity"], "C")
        matrix = snapshot["psirt_matrix"]
        self.assertEqual(matrix["columns"], ["Configurations1", "Configurations2"])
        self.assertNotIn("NA", matrix["rows"][0]["cells"][0])
        self.assertIn("/", matrix["rows"][0]["cells"][0])

    def test_kb_config_matrix_maps_numbered_device_ids(self) -> None:
        matrix = pages.kb_config_matrix(
            [
                {
                    "kb": "KB5099414",
                    "severity": "HIGH",
                    "stations": ["SYNTHETIC-LAB-24H2-01"],
                },
                {
                    "kb": "KB2",
                    "severity": "LOW",
                    "stations": ["SYNTHETIC-CT-IMG-01"],
                },
            ],
            [
                {
                    "device_id": "Configurations2",
                    "packages": ["KB5099414"],
                    "required_for_app": "not_required",
                    "install_risk": "compatible",
                    "skip_risk": "no_app_impact",
                    "compatibility": "compatible",
                }
            ],
        )
        self.assertEqual(matrix["columns"], ["Configurations1", "Configurations2"])
        by_kb = {row["kb"]: row["cells"] for row in matrix["rows"]}
        self.assertEqual(by_kb["KB5099414"][0], "NA")
        self.assertIn("L", by_kb["KB5099414"][1])
        self.assertEqual(by_kb["KB2"][1], "NA")

    def test_cluster_joins_numbered_device_id_to_synthetic_station(self) -> None:
        labels = pages.config_display_names(["SYNTHETIC-US-01", "SYNTHETIC-LAB-24H2-01"])
        cluster = {
            "title": "[Impact] shell-launch on Configurations1",
            "device_id": "Configurations1",
            "packages": [],
            "cluster_key": "shell-launch",
        }
        pkg = {
            "kb": "KB5002916",
            "stations": ["SYNTHETIC-LAB-24H2-01"],
        }
        self.assertEqual(labels["SYNTHETIC-LAB-24H2-01"], "Configurations1")
        self.assertTrue(pages.cluster_matches_package(cluster, pkg, labels))
        matched = pages.clusters_for_kb([cluster], pkg, labels)
        self.assertEqual(len(matched), 1)
        other = {
            "kb": "KB5002916",
            "stations": ["SYNTHETIC-US-01"],
        }
        self.assertFalse(pages.cluster_matches_package(cluster, other, labels))

    def test_package_without_cluster_gets_vendor_letter(self) -> None:
        rows = [
            {
                "kb": "KB5002916",
                "severity": "HIGH",
                "known_exploited": "false",
                "exploitability": "low",
            }
        ]
        pages.attach_vendor_letters(rows)
        self.assertEqual(rows[0]["vendor_severity"], "H")
        self.assertEqual(rows[0]["vendor_likelihood"], "L")
        self.assertNotEqual(rows[0]["vendor_risk"], "NA")


if __name__ == "__main__":
    unittest.main()
