#!/usr/bin/env python3
"""Catalog-driven PDLC fallback does not special-case a finding."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fallback-pdlc.py"
SPEC = importlib.util.spec_from_file_location("fallback_pdlc", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot load {SCRIPT}")
fallback = importlib.util.module_from_spec(SPEC)
sys.modules["fallback_pdlc"] = fallback
SPEC.loader.exec_module(fallback)


class FallbackPdlcTests(unittest.TestCase):
    def test_scores_catalog_rows_without_hardcoded_ids(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            app = root / "workspace" / "DesktopApplication"
            src = app / "src" / "App.cs"
            src.parent.mkdir(parents=True)
            src.write_text("class App {}\n", encoding="utf-8")
            (root / "inputs").mkdir()
            (root / "inputs" / "vulnerability-report.md").write_text(
                """| ID | Title | Severity | Status | Affected code | Countermeasure on main |
| --- | --- | --- | --- | --- | --- |
| VR-DEMO-001 | Example finding | High | closed | `src/App.cs` | **present** |
""",
                encoding="utf-8",
            )
            (root / "inputs" / "test-plan.md").write_text(
                """| ID | Category | Guarded files | What it proves |
| --- | --- | --- | --- |
| TC-SMOKE-APP | Smoke | `App.cs` | Starts |
""",
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                self.assertEqual(fallback.main(), 0)
                data = (root / "pdlc-out" / "analysis.json").read_text(encoding="utf-8")
            finally:
                os.chdir(previous)
            self.assertIn("VR-DEMO-001", data)
            self.assertNotIn("VR-TLS-001", data)
            self.assertIn('"patch_plan": "none"', data)


if __name__ == "__main__":
    unittest.main()
