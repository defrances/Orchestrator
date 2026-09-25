#!/usr/bin/env python3
"""Provider-specific model selection for analysis."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-ai-analyze.py"
SPEC = importlib.util.spec_from_file_location("run_ai_analyze", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot load {SCRIPT}")
analyze = importlib.util.module_from_spec(SPEC)
sys.modules["run_ai_analyze"] = analyze
SPEC.loader.exec_module(analyze)


class ResolveModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {
            key: os.environ.get(key) for key in ("AGENT_MODEL", "COPILOT_MODEL")
        }
        os.environ.pop("AGENT_MODEL", None)
        os.environ.pop("COPILOT_MODEL", None)

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_offline_has_no_model(self) -> None:
        os.environ["AGENT_MODEL"] = "composer-2.5"
        self.assertEqual(analyze.resolve_model("offline"), "")
        self.assertEqual(analyze.resolve_model("offline", "gpt-5.4"), "")

    def test_agent_uses_explicit_then_env_then_default(self) -> None:
        self.assertEqual(analyze.resolve_model("agent"), "composer-2.5")
        os.environ["AGENT_MODEL"] = "composer-2"
        self.assertEqual(analyze.resolve_model("agent"), "composer-2")
        self.assertEqual(analyze.resolve_model("agent", "auto"), "auto")

    def test_copilot_uses_its_own_env_and_default(self) -> None:
        os.environ["AGENT_MODEL"] = "composer-2"
        self.assertEqual(analyze.resolve_model("copilot"), "claude-haiku-4.5")
        os.environ["COPILOT_MODEL"] = "gpt-5.4"
        self.assertEqual(analyze.resolve_model("copilot"), "gpt-5.4")
        self.assertEqual(analyze.resolve_model("copilot", "claude-sonnet-4.6"), "claude-sonnet-4.6")

    def test_placeholder_falls_through_to_default(self) -> None:
        os.environ["AGENT_MODEL"] = "repo-default"
        self.assertEqual(analyze.resolve_model("agent", "default"), "composer-2.5")


class UsageRecordTests(unittest.TestCase):
    def test_tokens_from_result_and_cost(self) -> None:
        class Usage:
            input_tokens = 10
            output_tokens = 5
            cache_read_tokens = 100
            cache_write_tokens = 20
            total_tokens = 135

        class Result:
            usage = Usage()

        counted = analyze.tokens_from_result(Result())
        self.assertEqual(counted["model_tokens"], 15)
        self.assertEqual(counted["total_tokens"], 135)

        class Cost:
            charged_cents = 123

        class Billed:
            cost = Cost()

        self.assertEqual(analyze.cost_from_billed(Billed()), 1.23)

    def test_summarize_two_agent_tasks(self) -> None:
        summary = analyze.summarize_usage(
            [
                {
                    "used_provider": "agent",
                    "model": "composer-2.5",
                    "model_tokens": 1000,
                    "total_tokens": 5000,
                    "cost_usd": 0.02,
                },
                {
                    "used_provider": "agent",
                    "model": "composer-2.5",
                    "model_tokens": 400,
                    "total_tokens": 800,
                    "cost_usd": 0.01,
                },
            ]
        )
        self.assertEqual(summary["provider"], "agent")
        self.assertEqual(summary["model"], "composer-2.5")
        self.assertEqual(summary["model_tokens"], 1400)
        self.assertEqual(summary["total_tokens"], 5800)
        self.assertAlmostEqual(float(summary["cost_usd"]), 0.03)


class CopilotArgvTests(unittest.TestCase):
    def test_passes_selected_model(self) -> None:
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            analyze.run_copilot("prompt", "gpt-5.4")
        argv = run.call_args.args[0]
        self.assertIn("--model=gpt-5.4", argv)


if __name__ == "__main__":
    unittest.main()
