#!/usr/bin/env python3
"""PSIRT letter scores stay vendor vs product and use NA when a KB does not apply."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "psirt_scores.py"
SPEC = importlib.util.spec_from_file_location("psirt_scores", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot load {SCRIPT}")
psirt = importlib.util.module_from_spec(SPEC)
sys.modules["psirt_scores"] = psirt
SPEC.loader.exec_module(psirt)


class PsirtScoresTests(unittest.TestCase):
    def test_kev_is_critical_likelihood(self) -> None:
        self.assertEqual(psirt.vendor_likelihood("true", "low"), "C")
        self.assertEqual(psirt.vendor_likelihood("false", "high"), "H")
        self.assertEqual(psirt.vendor_likelihood("", "unknown"), "M")
        self.assertEqual(psirt.vendor_likelihood("", "none"), "L")

    def test_product_risk_drops_when_skip_has_no_app_impact(self) -> None:
        vendor = psirt.vendor_scores(severity="critical", known_exploited="false", exploitability="high")
        self.assertEqual(vendor["severity"], "C")
        self.assertEqual(vendor["likelihood"], "H")
        product = psirt.product_scores(
            required_for_app="not_required",
            install_risk="compatible",
            skip_risk="no_app_impact",
            compatibility="compatible",
        )
        self.assertEqual(product["risk"], "L")
        self.assertGreater(psirt.LETTER_RANK[vendor["risk"]], psirt.LETTER_RANK[product["risk"]])

    def test_matrix_uses_na_when_configuration_does_not_apply(self) -> None:
        labels = {
            "SYNTHETIC-CT-IMG-01": "Configurations1",
            "SYNTHETIC-LAB-24H2-01": "Configurations2",
        }
        matrix = psirt.kb_config_matrix(
            [
                {
                    "kb": "KB1",
                    "severity": "high",
                    "known_exploited": "false",
                    "exploitability": "low",
                    "stations": ["SYNTHETIC-LAB-24H2-01"],
                }
            ],
            labels,
            [
                {
                    "device_id": "Configurations2",
                    "packages": ["KB1"],
                    "required_for_app": "not_required",
                    "install_risk": "compatible",
                    "skip_risk": "no_app_impact",
                    "compatibility": "compatible",
                }
            ],
        )
        self.assertEqual(matrix["columns"], ["Configurations1", "Configurations2"])
        self.assertEqual(matrix["rows"][0]["kb"], "KB1")
        self.assertEqual(matrix["rows"][0]["cells"][0], "NA")
        self.assertIn("/", matrix["rows"][0]["cells"][1])
        self.assertNotEqual(matrix["rows"][0]["cells"][1], "NA")

    def test_matrix_joins_numbered_device_id_to_synthetic_columns(self) -> None:
        labels = {
            "SYNTHETIC-CT-IMG-01": "Configurations1",
            "SYNTHETIC-LAB-24H2-01": "Configurations2",
        }
        matrix = psirt.kb_config_matrix(
            [
                {
                    "kb": "KB5099414",
                    "severity": "critical",
                    "stations": ["SYNTHETIC-CT-IMG-01", "SYNTHETIC-LAB-24H2-01"],
                }
            ],
            labels,
            [
                {
                    "device_id": "Configurations1",
                    "packages": ["KB5099414"],
                    "required_for_app": "not_required",
                    "install_risk": "may_break_app",
                    "skip_risk": "stays_vulnerable",
                    "compatibility": "compatible",
                }
            ],
        )
        self.assertEqual(matrix["rows"][0]["cells"][0], "H / M")
        self.assertEqual(matrix["rows"][0]["cells"][1], "H / —")


if __name__ == "__main__":
    unittest.main()
