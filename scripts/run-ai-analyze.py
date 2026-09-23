#!/usr/bin/env python3
"""Run one analysis step with a selectable AI provider: agent, copilot, or offline."""

from __future__ import annotations

import argparse
import importlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PDLC_SKILL = ROOT / ".github" / "skills" / "analyze-pdlc-release" / "SKILL.md"
VENDOR_SKILL = ROOT / ".github" / "skills" / "analyze-vendor-update-impact" / "SKILL.md"

PDLC_PROMPT = """Follow .github/skills/analyze-pdlc-release/SKILL.md.

Read inputs/architecture.md, inputs/mds2.md, inputs/test-plan.md, and inputs/vulnerability-report.md.
Analyze workspace/DesktopApplication on branch main (see workspace/desktop-application-inventory.md).
For each product finding, set countermeasure present/absent/partial, cite files, list tests_to_run, and write a patch_plan.
Do not treat FindUpdates station KB rows as product vulnerabilities.
os_kb_advice must not package Windows KBs.
Write pdlc-out/analysis.json only. Do not call gh issue create. Do not deploy.
"""

VENDOR_PROMPT = """Follow .github/skills/analyze-vendor-update-impact/SKILL.md.

Analyze workspace/DesktopApplication on branch main (see workspace/desktop-application-inventory.md).
Read every source file listed in that inventory before writing analysis JSON.
Score install_risk, skip_risk, required_for_app, and compatibility against libraries and logic on main.
Cluster rows that share the same workstation, cluster_key, risk fields, and reviewer action into ONE analysis file.
Cap at 8 analysis files. Prefer cluster_key values from the skill.
Input report: inputs/report.json
Write analysis JSON files only to issues-out/. Do not call gh issue create. Do not publish GitHub Issues. Do not deploy.
"""


def run_offline(task: str) -> int:
    script = ROOT / "scripts" / ("fallback-pdlc.py" if task == "pdlc" else "fallback-analyze.py")
    print(f"provider=offline script={script.name}", flush=True)
    return subprocess.call([sys.executable, str(script)], cwd=str(ROOT))


def run_copilot(prompt: str) -> int:
    print("provider=copilot", flush=True)
    env = os.environ.copy()
    env["COPILOT_AUTO_UPDATE"] = "false"
    env.pop("COPILOT_GITHUB_TOKEN", None)
    result = subprocess.run(
        ["copilot", "--yolo", "--no-ask-user", "-p", prompt],
        cwd=str(ROOT),
        env=env,
    )
    return result.returncode


def run_agent(prompt: str) -> int:
    api_key = os.environ.get("AGENT_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("AGENT_API_KEY is not set")
    print("provider=agent", flush=True)
    sdk = importlib.import_module("cur" + "sor_sdk")
    skill_path = PDLC_SKILL if "analyze-pdlc-release" in prompt else VENDOR_SKILL
    skill_text = skill_path.read_text(encoding="utf-8") if skill_path.exists() else ""
    full_prompt = "\n\n".join(part for part in (skill_text, prompt) if part)
    try:
        result = sdk.Agent.prompt(
            full_prompt,
            sdk.AgentOptions(
                api_key=api_key,
                model=os.environ.get("AGENT_MODEL") or "composer-2.5",
                local=sdk.LocalAgentOptions(cwd=str(ROOT)),
            ),
        )
    except Exception as exc:
        print(f"agent startup failed: {exc}", file=sys.stderr, flush=True)
        return 1
    print(f"agent status={result.status}", flush=True)
    return 0 if result.status != "error" else 2


def normalize_provider(raw: str) -> str:
    value = (raw or "agent").strip().lower()
    aliases = {
        "agent": "agent",
        "copilot": "copilot",
        "github-copilot": "copilot",
        "offline": "offline",
        "fallback": "offline",
        "none": "offline",
    }
    if value not in aliases:
        raise SystemExit(f"unknown AI provider {raw!r}; use agent, copilot, or offline")
    return aliases[value]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", choices=("pdlc", "vendor-impact"), required=True)
    parser.add_argument(
        "--provider",
        default=os.environ.get("ORCHESTRATOR_AI_PROVIDER", "agent"),
        help="agent | copilot | offline",
    )
    args = parser.parse_args()
    provider = normalize_provider(args.provider)
    prompt = PDLC_PROMPT if args.task == "pdlc" else VENDOR_PROMPT
    out_dir = ROOT / ("pdlc-out" if args.task == "pdlc" else "issues-out")
    out_dir.mkdir(parents=True, exist_ok=True)

    def output_ready() -> bool:
        if args.task == "pdlc":
            return (out_dir / "analysis.json").is_file()
        return any(out_dir.glob("*.json"))

    if provider == "offline":
        return run_offline(args.task)
    if provider == "copilot":
        code = run_copilot(prompt)
        if code != 0 or not output_ready():
            print("copilot failed or wrote no JSON; using offline analysis", flush=True)
            return run_offline(args.task)
        return 0
    try:
        code = run_agent(prompt)
    except Exception as exc:
        print(f"agent failed: {exc}; using offline analysis", file=sys.stderr, flush=True)
        return run_offline(args.task)
    if code != 0 or not output_ready():
        print("agent run failed or wrote no JSON; using offline analysis", flush=True)
        return run_offline(args.task)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
