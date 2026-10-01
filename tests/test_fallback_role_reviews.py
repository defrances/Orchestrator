#!/usr/bin/env python3
"""Offline role reviews write one JSON file per skill from existing analysis."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fallback-role-reviews.py"
SPEC = importlib.util.spec_from_file_location("fallback_role_reviews", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot load {SCRIPT}")
fallback = importlib.util.module_from_spec(SPEC)
sys.modules["fallback_role_reviews"] = fallback
SPEC.loader.exec_module(fallback)


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class FallbackRoleReviewsTests(unittest.TestCase):
    def test_writes_all_role_reviews_from_clusters(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _write(
                root / "issues-out" / "01-schannel-tls-Config1.json",
                {
                    "title": "[Impact] KB5002916 on Config1 - Schannel TLS host path",
                    "cluster_key": "schannel-tls",
                    "device_id": "Config1",
                    "packages": ["KB5002916"],
                    "required_for_app": "not_required",
                    "install_risk": "compatible",
                    "skip_risk": "stays_vulnerable",
                    "compatibility": "compatible",
                    "vendor_severity": "C",
                    "vendor_likelihood": "H",
                    "vendor_risk": "C",
                    "product_risk": "L",
                    "body": (
                        "Clinical criticality: high\n"
                        "Cited `src/HostApplication.Core/InsecureVendorBulletinClient.cs`.\n"
                        "Recommended `TC-REG-TLS-CALLBACK`.\n"
                    ),
                },
            )
            _write(
                root / "pdlc-out" / "analysis.json",
                {
                    "product": "HostApplication",
                    "branch": "main",
                    "findings": [
                        {
                            "id": "VR-TLS-001",
                            "title": "TLS",
                            "countermeasure": "present",
                            "tests_to_run": ["TC-REG-TLS-CALLBACK"],
                            "impact_files": [
                                "src/HostApplication.Core/InsecureVendorBulletinClient.cs"
                            ],
                        }
                    ],
                },
            )
            (root / "inputs").mkdir()
            (root / "inputs" / "vulnerability-report.md").write_text(
                "| ID | Title |\n| --- | --- |\n| VR-TLS-001 | TLS |\n",
                encoding="utf-8",
            )
            (root / "inputs" / "test-plan.md").write_text(
                "| ID |\n| --- |\n| TC-REG-TLS-CALLBACK |\n",
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                self.assertEqual(fallback.main([]), 0)
                architect = json.loads(
                    (root / "skills-out" / "architect" / "review.json").read_text(encoding="utf-8")
                )
                tests = json.loads(
                    (root / "skills-out" / "test-engineer" / "review.json").read_text(encoding="utf-8")
                )
                cyber = json.loads(
                    (root / "skills-out" / "cybersec" / "review.json").read_text(encoding="utf-8")
                )
                safety = json.loads(
                    (root / "skills-out" / "product-safety" / "review.json").read_text(encoding="utf-8")
                )
                sqa = json.loads((root / "skills-out" / "sqa" / "review.json").read_text(encoding="utf-8"))
            finally:
                os.chdir(previous)

            self.assertEqual(architect["skill"], "Architect_Skill")
            self.assertTrue(architect["advisory"])
            self.assertTrue(architect["do_not_deploy"])
            self.assertTrue(any("schannel-tls" in str(row.get("id")) for row in architect["findings"]))
            self.assertIn("TC-REG-TLS-CALLBACK", tests["findings"][0]["tests_to_run"])
            self.assertEqual(cyber["findings"][0]["vendor_risk"], "C")
            self.assertEqual(cyber["findings"][0]["product_risk"], "L")
            self.assertFalse(cyber["findings"][0]["kev"])
            self.assertEqual(safety["findings"][0]["clinical_criticality"], "high")
            self.assertIn("HOLD/BLOCK", safety["findings"][0]["recommendation"])
            statuses = {row["id"]: row["status"] for row in sqa["findings"]}
            self.assertEqual(statuses["SQA-CONFIG-LABELS"], "pass")
            self.assertEqual(statuses["SQA-HOLD-BLOCK"], "pass")
            self.assertEqual(statuses["SQA-SCOPE"], "pass")
            self.assertNotIn("Windchill", json.dumps(architect))
            self.assertNotIn("Run now", json.dumps(safety))

    def test_empty_inputs_still_write_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            previous = Path.cwd()
            try:
                os.chdir(root)
                self.assertEqual(fallback.main([]), 0)
                for folder in (
                    "architect",
                    "test-engineer",
                    "cybersec",
                    "product-safety",
                    "sqa",
                ):
                    payload = json.loads(
                        (root / "skills-out" / folder / "review.json").read_text(encoding="utf-8")
                    )
                    self.assertTrue(payload["advisory"])
                    self.assertTrue(payload["do_not_deploy"])
                    if folder == "sqa":
                        self.assertTrue(payload["findings"])
                        self.assertTrue(all(row.get("status") == "pass" for row in payload["findings"]))
                    else:
                        self.assertEqual(payload["findings"], [])
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
