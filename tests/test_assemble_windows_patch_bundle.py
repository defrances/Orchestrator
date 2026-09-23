#!/usr/bin/env python3
"""Windows patch bundle assembler."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "assemble-windows-patch-bundle.py"
SPEC = importlib.util.spec_from_file_location("assemble_windows_patch_bundle", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot load {SCRIPT}")
bundle = importlib.util.module_from_spec(SPEC)
sys.modules["assemble_windows_patch_bundle"] = bundle
SPEC.loader.exec_module(bundle)


REPORT = {
    "kind": "station_report",
    "schema_version": "1.0",
    "source": "fixtures",
    "item_count": 2,
    "items": [
        {
            "device_id": "SYNTHETIC-CT-IMG-01",
            "model": "CT",
            "device_role": "imaging",
            "deployment_group": "lab-a",
            "os_product": "Windows 11 IoT Enterprise",
            "os_build": "10.0.22621.2500",
            "advisory_id": "ADV260915",
            "title": "Windows Kernel Elevation of Privilege",
            "vendor": "microsoft",
            "package": "KB5060001",
            "cve_ids": ["CVE-2026-12345"],
            "action": "candidate_for_validation",
            "official_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12345",
            "severity": "high",
            "listed": True,
        },
        {
            "device_id": "SYNTHETIC-CT-IMG-01",
            "model": "CT",
            "device_role": "imaging",
            "deployment_group": "lab-a",
            "os_product": "Windows 11 IoT Enterprise",
            "advisory_id": "ADV-HOLD",
            "title": "Held update",
            "vendor": "microsoft",
            "package": "KB5099999",
            "cve_ids": [],
            "action": "do_not_install",
            "official_url": "https://msrc.microsoft.com/update-guide",
            "severity": "high",
            "listed": True,
        },
    ],
    "stations": [
        "SYNTHETIC-CT-IMG-01",
        "SYNTHETIC-LAB-24H2-01",
        "SYNTHETIC-MR-IMG-01",
    ],
}


class AssembleWindowsPatchBundleTests(unittest.TestCase):
    def test_groups_deploy_and_hold(self) -> None:
        packages = bundle._group_packages(REPORT["items"])
        self.assertEqual(len(packages), 2)
        deploy = next(item for item in packages if item["kb"] == "KB5060001")
        hold = next(item for item in packages if item["kb"] == "KB5099999")
        self.assertTrue(deploy["include_in_deploy"])
        self.assertFalse(hold["include_in_deploy"])
        self.assertEqual(deploy["stations"], ["SYNTHETIC-CT-IMG-01"])

    def test_writes_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.json"
            report.write_text(json.dumps(REPORT), encoding="utf-8")
            out = root / "out"
            bundle.REPORT = report
            bundle.OUT_DIR = out
            bundle.FU_RUN = "123"
            bundle.FU_SOURCE = "fixtures"
            bundle.FU_URL = "https://example.test/fu"
            self.assertEqual(bundle.main(), 0)
            zips = list(out.glob("windows-patch-bundle-fixtures-*.zip"))
            self.assertEqual(len(zips), 1)
            with zipfile.ZipFile(zips[0]) as archive:
                names = set(archive.namelist())
                readme = archive.read("README.md").decode("utf-8")
            self.assertIn("BUNDLE_MANIFEST.json", names)
            self.assertIn("APPLY.ps1", names)
            self.assertIn("README.md", names)
            self.assertTrue(any(name.startswith("packages/KB5060001") for name in names))
            self.assertIn("stations/SYNTHETIC-CT-IMG-01.json", names)
            self.assertIn("stations/SYNTHETIC-LAB-24H2-01.json", names)
            self.assertIn("stations/SYNTHETIC-MR-IMG-01.json", names)
            self.assertIn("`SYNTHETIC-CT-IMG-01`", readme)
            self.assertIn("`SYNTHETIC-LAB-24H2-01`", readme)
            self.assertIn(
                "[KB5060001](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12345)",
                readme,
            )
            self.assertIn("[KB5099999](https://msrc.microsoft.com/update-guide)", readme)
            self.assertIn("[123](https://example.test/fu)", readme)


if __name__ == "__main__":
    unittest.main()
