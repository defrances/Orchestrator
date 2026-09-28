#!/usr/bin/env python3
"""Tests for GitHub Issue-format Orchestrator emails."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "send-results-email.py"
SPEC = importlib.util.spec_from_file_location("send_results_email", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot load {SCRIPT}")
mail = importlib.util.module_from_spec(SPEC)
sys.modules["send_results_email"] = mail
SPEC.loader.exec_module(mail)


CLUSTER_BODY = """<!-- impact:schannel-tls:uvcs-configuration-1 -->

Impact analysis conducted on source code version:

- https://github.com/defrances/DesktopApplication - commit `abc1234`

## Updates applicable for this product configuration

| Title | Package | CVEs | Recommendation |
| --- | --- | --- | --- |
| Schannel RCE | [KB5122871](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72940) | CVE-2026-72940 | Install - High Prio |

## Product Configuration Specification

- Product configuration: UVCS configuration 1

## Technical Impact Assessment

- `src/DesktopApplication.Core/InsecureVendorBulletinClient.cs` — HTTPS via host Schannel

## Cybersecurity impact assessment

This patch fixes CVE-2026-72940 in KB5122871. SBOM scan and source code scan revealed that the vendor bulletin HTTPS client uses host Schannel.

## Recommendation

Install - High Prio: lab-check the published win-x64 build for UVCS configuration 1.
"""


class MarkdownHtmlTests(unittest.TestCase):
    def test_issue_template_renders_table_and_emphasis(self) -> None:
        html = mail.markdown_to_html(CLUSTER_BODY)
        self.assertIn("<table>", html)
        self.assertIn("<th>", html)
        self.assertIn('<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72940">', html)
        self.assertIn("Schannel RCE", html)
        self.assertIn("KB5122871", html)
        self.assertIn("Install - High Prio", html)
        self.assertIn("<ul>", html)
        self.assertIn("<h2>Updates applicable for this product configuration</h2>", html)
        self.assertNotIn("impact:schannel-tls", html)
        self.assertNotIn("Advisory", html)
        self.assertNotIn("Policy", html)

    def test_https_table_links_are_anchors(self) -> None:
        html = mail.markdown_to_html(CLUSTER_BODY)
        self.assertIn(
            '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72940">KB5122871</a>',
            html,
        )
        self.assertNotIn(
            '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72940">Schannel RCE</a>',
            html,
        )

    def test_non_https_markdown_links_are_not_anchors(self) -> None:
        html = mail.markdown_to_html("[click](javascript:alert(1))")
        self.assertNotIn("<a ", html)
        self.assertIn("javascript:alert(1)", html)

    def test_fenced_code_and_hr(self) -> None:
        html = mail.markdown_to_html("```\ngit log\n```\n\n---\n\nDone.")
        self.assertIn("<pre><code>git log</code></pre>", html)
        self.assertIn("<hr>", html)
        self.assertIn("<p>Done.</p>", html)

    def test_bare_https_urls_become_anchors(self) -> None:
        html = mail.markdown_to_html(
            "- FindUpdates: https://github.com/defrances/FindUpdates/actions/runs/1"
        )
        self.assertIn(
            '<a href="https://github.com/defrances/FindUpdates/actions/runs/1">'
            "https://github.com/defrances/FindUpdates/actions/runs/1</a>",
            html,
        )


class PayloadEmailTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["FU_RUN_ID"] = "35341770186"
        os.environ["FU_HTML_URL"] = (
            "https://github.com/defrances/FindUpdates/actions/runs/35341770186"
        )
        os.environ["ORCH_HTML_URL"] = (
            "https://github.com/defrances/Orchestrator/actions/runs/1"
        )
        os.environ["DA_CHECKOUT"] = str(ROOT)
        self._bundle_tmp = tempfile.TemporaryDirectory()
        os.environ["BUNDLE_DIR"] = self._bundle_tmp.name
        os.environ.pop("BUNDLE_README", None)

    def tearDown(self) -> None:
        self._bundle_tmp.cleanup()
        os.environ.pop("BUNDLE_DIR", None)
        os.environ.pop("BUNDLE_README", None)

    def _write_json(self, directory: Path, name: str, payload: object) -> None:
        (directory / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def test_one_email_per_cluster(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self._write_json(
                directory,
                "01-schannel-tls-SYNTHETIC-W11-24H2-01.json",
                {
                    "title": "[Impact] KB5122871 on UVCS configuration 1 - Schannel TLS path has no defense in depth",
                    "body": CLUSTER_BODY,
                    "cluster_key": "schannel-tls",
                    "device_id": "uvcs-configuration-1",
                },
            )
            self._write_json(
                directory,
                "02-os-dotnet-uvcs-configuration-1.json",
                {
                    "title": "[Impact] os-dotnet on UVCS configuration 1 - OS .NET KB does not patch the bundled runtime",
                    "body": "## Updates applicable for this product configuration\n\nOS .NET KB does not patch the bundled runtime.",
                    "cluster_key": "os-dotnet",
                    "device_id": "uvcs-configuration-1",
                },
            )
            messages = mail.build_messages(issues_dir=directory, app_dir=ROOT)
            self.assertEqual(len(messages), 2)
            self.assertEqual(
                messages[0].subject,
                "[Impact] KB5122871 on UVCS configuration 1 - Schannel TLS path has no defense in depth",
            )
            self.assertIn("## Updates applicable for this product configuration", messages[0].plain)
            self.assertIn("## Product Configuration Specification", messages[0].plain)
            self.assertIn("## Cybersecurity impact assessment", messages[0].plain)
            self.assertIn("<table>", messages[0].html)
            self.assertIn("FindUpdates", messages[0].plain)
            self.assertIn("35341770186", messages[0].plain)
            self.assertNotIn("GitHub Issues were not created", messages[0].plain)
            self.assertNotIn("not an authorization", messages[0].plain)
            self.assertNotIn("Desktop Application `main`", messages[0].plain)
            self.assertEqual(
                messages[1].subject,
                "[Impact] os-dotnet on UVCS configuration 1 - OS .NET KB does not patch the bundled runtime",
            )
            self.assertIn("bundled runtime", messages[1].plain)

    def test_none_json_sends_one_status_email(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self._write_json(directory, "none.json", {"issues": []})
            messages = mail.build_messages(issues_dir=directory, app_dir=ROOT)
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].subject, mail.NO_CLUSTER_SUBJECT)
            self.assertIn("No vendor-update clusters", messages[0].plain)
            self.assertIn("35341770186", messages[0].plain)

    def test_empty_directory_sends_one_status_email(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            messages = mail.build_messages(issues_dir=Path(raw), app_dir=ROOT)
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].subject, mail.NO_CLUSTER_SUBJECT)

    def test_token_field_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self._write_json(
                directory,
                "secret.json",
                {"title": "leak", "body": "nope", "token": "should-not-send"},
            )
            self._write_json(
                directory,
                "ok.json",
                {"title": "[Impact] ntfs-notes on UVCS configuration 1 - notes I/O", "body": "## Product Configuration Specification\n\nSafe."},
            )
            messages = mail.build_messages(issues_dir=directory, app_dir=ROOT)
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].subject, "[Impact] ntfs-notes on UVCS configuration 1 - notes I/O")
            self.assertNotIn("should-not-send", messages[0].plain)

    def test_issues_array_payload(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self._write_json(
                directory,
                "batch.json",
                {
                    "issues": [
                        {"title": "First cluster", "body": "## Updates applicable for this product configuration\n\nA"},
                        {"title": "Second cluster", "body": "## Updates applicable for this product configuration\n\nB"},
                    ]
                },
            )
            messages = mail.build_messages(issues_dir=directory, app_dir=ROOT)
            self.assertEqual([item.subject for item in messages], ["First cluster", "Second cluster"])

    def test_multipart_html_matches_plain_sections(self) -> None:
        from email.message import EmailMessage

        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self._write_json(
                directory,
                "01.json",
                {"title": "[Impact] shell-launch on UVCS configuration 1 - launch identity", "body": CLUSTER_BODY},
            )
            messages = mail.build_messages(issues_dir=directory, app_dir=ROOT)
            self.assertEqual(len(messages), 1)
            self.assertIn("<table>", messages[0].html)
            self.assertIn("</html>", messages[0].html)
            built = EmailMessage()
            built.set_content(messages[0].plain)
            built.add_alternative(messages[0].html, subtype="html")
            self.assertTrue(built.is_multipart())
            types = [part.get_content_type() for part in built.iter_parts()]
            self.assertEqual(types, ["text/plain", "text/html"])

    def test_dry_run_prints_one_subject_per_cluster(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self._write_json(
                directory,
                "01.json",
                {"title": "Cluster A", "body": "## Updates applicable for this product configuration\n\nA"},
            )
            self._write_json(
                directory,
                "02.json",
                {"title": "Cluster B", "body": "## Updates applicable for this product configuration\n\nB"},
            )
            os.environ["ISSUES_OUT_DIR"] = str(directory)
            os.environ["SMTP_DRY_RUN"] = "1"
            from io import StringIO
            from unittest.mock import patch

            buffer = StringIO()
            with patch("sys.stdout", buffer):
                status = mail.main()
            os.environ.pop("SMTP_DRY_RUN", None)
            os.environ.pop("ISSUES_OUT_DIR", None)
            output = buffer.getvalue()
            self.assertEqual(status, 0)
            self.assertIn("SUBJECT: Cluster A", output)
            self.assertIn("SUBJECT: Cluster B", output)
            self.assertIn("<table>", mail.markdown_to_html(CLUSTER_BODY))
            self.assertIn("sent=2 failed=0", output)

    def test_bundle_readme_is_an_extra_email_with_clickable_links(self) -> None:
        readme = """# Windows patch bundle

- Bundle id: `windows-patch-bundle-live-20260923T180458Z`
- FindUpdates run: [35341770186](https://github.com/defrances/FindUpdates/actions/runs/35341770186)

## Deploy set

- [KB5122871](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72940) — Schannel RCE — SYNTHETIC-W11-24H2-01
"""
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self._write_json(
                directory,
                "01.json",
                {"title": "Cluster A", "body": "## Updates applicable for this product configuration\n\nA"},
            )
            bundle_dir = Path(self._bundle_tmp.name) / "windows-patch-bundle-live-20260923T180458Z"
            bundle_dir.mkdir()
            (bundle_dir / "README.md").write_text(readme, encoding="utf-8")
            messages = mail.build_messages(issues_dir=directory, app_dir=ROOT)
            self.assertEqual(len(messages), 2)
            self.assertEqual(messages[0].subject, "Cluster A")
            self.assertEqual(
                messages[1].subject,
                "Windows patch bundle `windows-patch-bundle-live-20260923T180458Z`",
            )
            self.assertIn("## Deploy set", messages[1].plain)
            self.assertIn(
                '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72940">KB5122871</a>',
                messages[1].html,
            )
            self.assertIn(
                '<a href="https://github.com/defrances/FindUpdates/actions/runs/35341770186">35341770186</a>',
                messages[1].html,
            )
            self.assertIn(
                '<a href="https://github.com/defrances/Orchestrator/actions/runs/1">',
                messages[1].html,
            )


FALLBACK = ROOT / "scripts" / "fallback-analyze.py"
FALLBACK_SPEC = importlib.util.spec_from_file_location("fallback_analyze", FALLBACK)
if FALLBACK_SPEC is None or FALLBACK_SPEC.loader is None:
    raise SystemExit(f"cannot load {FALLBACK}")
fallback = importlib.util.module_from_spec(FALLBACK_SPEC)
sys.modules["fallback_analyze"] = fallback
FALLBACK_SPEC.loader.exec_module(fallback)


class FallbackLinkTests(unittest.TestCase):
    def test_linked_update_uses_https_official_url(self) -> None:
        url = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72940"
        self.assertEqual(
            fallback.linked_update("KB5122871", url),
            f"[KB5122871]({url})",
        )

    def test_linked_update_skips_missing_or_non_https(self) -> None:
        self.assertEqual(fallback.linked_update("KB1", None), "`KB1`")
        self.assertEqual(fallback.linked_update("KB1", "http://example.invalid/x"), "`KB1`")

    def test_recommendation_label_maps_findupdates_action(self) -> None:
        self.assertEqual(
            fallback.recommendation_label("candidate_for_validation"),
            "Install - High Prio",
        )
        self.assertEqual(fallback.recommendation_label("do_not_install"), "Low Prio")
        self.assertEqual(
            fallback.recommendation_label("candidate_for_validation", "HOLD"),
            "Low Prio",
        )

    def test_patch_name_uses_single_kb(self) -> None:
        members = [
            {"package": "KB5122871", "cve_ids": ["CVE-1"], "title": "A"},
            {"package": "KB5122871", "cve_ids": ["CVE-1"], "title": "A"},
        ]
        self.assertEqual(fallback.patch_name(members, "schannel-tls"), "KB5122871")
        members.append({"package": "KB5000001", "cve_ids": ["CVE-2"], "title": "B"})
        self.assertEqual(fallback.patch_name(members, "schannel-tls"), "schannel-tls")

    def test_issue_body_table_contains_official_links(self) -> None:
        url = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72940"
        body = fallback.issue_body(
            "schannel-tls",
            [
                {
                    "advisory_id": "advisory_1",
                    "title": "Schannel RCE",
                    "package": "KB5122871",
                    "cve_ids": ["CVE-2026-72940"],
                    "action": "candidate_for_validation",
                    "policy_result": "REQUIRE_APPROVAL",
                    "risk_score": 75,
                    "official_url": url,
                    "model": "PACS",
                    "device_role": "review",
                    "deployment_group": "pacs-validate",
                    "os_product": "Windows 11",
                    "os_build": "26100",
                    "clinical_criticality": "medium",
                    "network_exposure": "restricted_lan",
                    "explanation": "TLS path.",
                }
            ],
            "- `src/DesktopApplication.Core/InsecureVendorBulletinClient.cs`",
            fallback.risk_fields("schannel-tls"),
            source_versions="- https://github.com/defrances/DesktopApplication - commit `abc`",
        )
        self.assertIn(f"[KB5122871]({url})", body)
        self.assertNotIn(f"[Schannel RCE]({url})", body)
        self.assertNotIn(f"[advisory_1]({url})", body)
        self.assertNotIn("| Advisory |", body)
        self.assertNotIn("| Policy |", body)
        self.assertNotIn("| Score |", body)
        self.assertNotIn("## Workstation", body)
        self.assertNotIn("## Recent code", body)
        self.assertNotIn("not an authorization", body)
        self.assertIn("Schannel RCE", body)
        self.assertIn("Install - High Prio", body)
        self.assertIn("## Updates applicable for this product configuration", body)
        self.assertIn("## Product Configuration Specification", body)
        self.assertIn("## Technical Impact Assessment", body)
        self.assertIn("## Cybersecurity impact assessment", body)
        self.assertIn("## Product Risk assessment", body)
        self.assertIn("## TEST PLANNING & COVERAGE ANALYSIS", body)
        self.assertIn("## Recommendation", body)
        self.assertIn("UVCS configuration 1", body)
        self.assertIn("https://github.com/defrances/DesktopApplication - commit `abc`", body)
        self.assertIn("TC-REG-TLS-CALLBACK", body)
        self.assertIn("**Required for the app to keep working: Not required.**", body)
        self.assertIn("**If we skip: Station stays exposed.**", body)
        self.assertIn("self-contained", body)
        self.assertIn("InsecureVendorBulletinClient", body)
        self.assertNotIn("`not_required`", body)
        self.assertNotIn("- Required for the app to keep working: `not_required`", body)


if __name__ == "__main__":
    unittest.main()
