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


CLUSTER_BODY = """<!-- impact:schannel-tls:SYNTHETIC-W11-24H2-01 -->

## Updates in this cluster

| Advisory | Title | Package | CVEs | Action | Policy | Score |
| --- | --- | --- | --- | --- | --- | --- |
| `advisory_1` | Schannel RCE | `KB5122871` | CVE-2026-72940 | `candidate_for_validation` | `REQUIRE_APPROVAL` | 75 |

This issue is **not** an authorization to install, approve, or deploy.

## Workstation

- Device: `SYNTHETIC-W11-24H2-01`

## Evidence from DesktopApplication main

- `src/DesktopApplication.Core/InsecureVendorBulletinClient.cs` — `AcceptAnyServerCertificate`

## Recommended reviewer action

Validate the Schannel KBs in a lab ring.
"""


class MarkdownHtmlTests(unittest.TestCase):
    def test_issue_template_renders_table_and_emphasis(self) -> None:
        html = mail.markdown_to_html(CLUSTER_BODY)
        self.assertIn("<table>", html)
        self.assertIn("<th>", html)
        self.assertIn("CVE-2026-72940", html)
        self.assertIn("<strong>not</strong>", html)
        self.assertIn("<code>KB5122871</code>", html)
        self.assertIn("<ul>", html)
        self.assertIn("<h2>Updates in this cluster</h2>", html)
        self.assertNotIn("impact:schannel-tls", html)

    def test_fenced_code_and_hr(self) -> None:
        html = mail.markdown_to_html("```\ngit log\n```\n\n---\n\nDone.")
        self.assertIn("<pre><code>git log</code></pre>", html)
        self.assertIn("<hr>", html)
        self.assertIn("<p>Done.</p>", html)


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

    def _write_json(self, directory: Path, name: str, payload: object) -> None:
        (directory / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def test_one_email_per_cluster(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self._write_json(
                directory,
                "01-schannel-tls-SYNTHETIC-W11-24H2-01.json",
                {
                    "title": "[Impact] schannel-tls on SYNTHETIC-W11-24H2-01 — Schannel TLS",
                    "body": CLUSTER_BODY,
                    "cluster_key": "schannel-tls",
                    "device_id": "SYNTHETIC-W11-24H2-01",
                },
            )
            self._write_json(
                directory,
                "02-os-dotnet-SYNTHETIC-W11-24H2-01.json",
                {
                    "title": "[Impact] os-dotnet on SYNTHETIC-W11-24H2-01 — bundled runtime",
                    "body": "## Updates in this cluster\n\nOS .NET KB does not patch the bundled runtime.",
                    "cluster_key": "os-dotnet",
                    "device_id": "SYNTHETIC-W11-24H2-01",
                },
            )
            messages = mail.build_messages(issues_dir=directory, app_dir=ROOT)
            self.assertEqual(len(messages), 2)
            self.assertEqual(
                messages[0].subject,
                "[Impact] schannel-tls on SYNTHETIC-W11-24H2-01 — Schannel TLS",
            )
            self.assertIn("## Updates in this cluster", messages[0].plain)
            self.assertIn("## Workstation", messages[0].plain)
            self.assertIn("<table>", messages[0].html)
            self.assertIn("FindUpdates", messages[0].plain)
            self.assertIn("35341770186", messages[0].plain)
            self.assertIn("GitHub Issues were not created", messages[0].plain)
            self.assertEqual(
                messages[1].subject,
                "[Impact] os-dotnet on SYNTHETIC-W11-24H2-01 — bundled runtime",
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
                {"title": "[Impact] ntfs-notes on STATION — notes I/O", "body": "## Workstation\n\nSafe."},
            )
            messages = mail.build_messages(issues_dir=directory, app_dir=ROOT)
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].subject, "[Impact] ntfs-notes on STATION — notes I/O")
            self.assertNotIn("should-not-send", messages[0].plain)

    def test_issues_array_payload(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self._write_json(
                directory,
                "batch.json",
                {
                    "issues": [
                        {"title": "First cluster", "body": "## Updates in this cluster\n\nA"},
                        {"title": "Second cluster", "body": "## Updates in this cluster\n\nB"},
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
                {"title": "[Impact] shell-launch on STATION — launch identity", "body": CLUSTER_BODY},
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
                {"title": "Cluster A", "body": "## Updates in this cluster\n\nA"},
            )
            self._write_json(
                directory,
                "02.json",
                {"title": "Cluster B", "body": "## Updates in this cluster\n\nB"},
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


if __name__ == "__main__":
    unittest.main()
