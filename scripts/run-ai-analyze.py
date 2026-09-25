#!/usr/bin/env python3
"""Run one analysis step with a selectable AI provider: agent, copilot, or offline."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import time
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


USAGE_PATH = ROOT / "artifacts" / "ai-usage.json"


def _pick_int(blob: object, *names: str) -> int | None:
    if blob is None:
        return None
    data = blob if isinstance(blob, dict) else getattr(blob, "__dict__", None)
    if not isinstance(data, dict):
        data = {name: getattr(blob, name) for name in names if hasattr(blob, name)}
    for name in names:
        if name not in data and hasattr(blob, name):
            value = getattr(blob, name)
        else:
            value = data.get(name) if isinstance(data, dict) else None
        if value in (None, ""):
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def tokens_from_result(result: object) -> dict[str, int | None]:
    usage = getattr(result, "usage", None)
    if usage is None and isinstance(result, dict):
        usage = result.get("usage")
    empty = {
        "input_tokens": None,
        "output_tokens": None,
        "cache_read_tokens": None,
        "cache_write_tokens": None,
        "model_tokens": None,
        "total_tokens": None,
    }
    if usage is None:
        return empty
    inp = _pick_int(usage, "input_tokens", "inputTokens", "prompt_tokens")
    out = _pick_int(usage, "output_tokens", "outputTokens", "completion_tokens")
    cache_r = _pick_int(usage, "cache_read_tokens", "cacheReadTokens")
    cache_w = _pick_int(usage, "cache_write_tokens", "cacheWriteTokens")
    total = _pick_int(usage, "total_tokens", "totalTokens", "total")
    model = (inp or 0) + (out or 0) if inp is not None or out is not None else None
    if total is None and model is not None:
        total = model + (cache_r or 0) + (cache_w or 0)
    return {
        "input_tokens": inp,
        "output_tokens": out,
        "cache_read_tokens": cache_r,
        "cache_write_tokens": cache_w,
        "model_tokens": model,
        "total_tokens": total,
    }


def cost_from_billed(billed: object) -> float | None:
    cost = getattr(billed, "cost", None)
    if cost is None and isinstance(billed, dict):
        cost = billed.get("cost")
    if cost is None:
        return None
    cents = getattr(cost, "charged_cents", None)
    if cents is None and isinstance(cost, dict):
        cents = cost.get("charged_cents")
    if cents in (None, ""):
        return None
    try:
        return float(cents) / 100.0
    except (TypeError, ValueError):
        return None


def billed_cost(agent: object) -> float | None:
    getter = getattr(agent, "get_usage", None)
    if not callable(getter):
        return None
    last = None
    for attempt in range(4):
        try:
            last = getter()
        except Exception as exc:
            print(f"usage lookup failed: {exc}", file=sys.stderr, flush=True)
            return None
        value = cost_from_billed(last)
        if value is not None:
            return value
        if attempt < 3:
            time.sleep(2)
    return None


def usage_entry(
    *,
    task: str,
    requested: str,
    used: str,
    model: str,
    tokens: dict[str, int | None] | None = None,
    cost_usd: float | None = None,
    fallback: bool = False,
) -> dict[str, object]:
    counts = tokens or {}
    return {
        "task": task,
        "requested_provider": requested,
        "used_provider": used,
        "model": model if used != "offline" else "",
        "input_tokens": counts.get("input_tokens"),
        "output_tokens": counts.get("output_tokens"),
        "cache_read_tokens": counts.get("cache_read_tokens"),
        "cache_write_tokens": counts.get("cache_write_tokens"),
        "model_tokens": 0 if used == "offline" else counts.get("model_tokens"),
        "total_tokens": 0 if used == "offline" else counts.get("total_tokens"),
        "cost_usd": 0.0 if used == "offline" else cost_usd,
        "fallback": fallback,
    }


def summarize_usage(tasks: list[dict[str, object]]) -> dict[str, object]:
    providers: list[str] = []
    models: list[str] = []
    model_sum = 0
    model_known = False
    raw_sum = 0
    raw_known = False
    cost_sum = 0.0
    cost_known = False
    live = False
    for item in tasks:
        used = str(item.get("used_provider") or "")
        if used and used not in providers:
            providers.append(used)
        model = str(item.get("model") or "")
        if model and model not in models:
            models.append(model)
        model_tokens = item.get("model_tokens")
        if model_tokens not in (None, ""):
            model_sum += int(model_tokens)
            model_known = True
        total = item.get("total_tokens")
        if total not in (None, ""):
            raw_sum += int(total)
            raw_known = True
        cost = item.get("cost_usd")
        if cost not in (None, ""):
            cost_sum += float(cost)
            cost_known = True
        if used and used != "offline":
            live = True
    return {
        "provider": providers[0] if len(providers) == 1 else " + ".join(providers) or "unknown",
        "model": models[0] if len(models) == 1 else ", ".join(models),
        "model_tokens": model_sum if model_known else None,
        "total_tokens": raw_sum if raw_known else None,
        "cost_usd": cost_sum if cost_known or not live else None,
        "tasks": tasks,
    }


def persist_usage(entry: dict[str, object]) -> None:
    USAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {"schema_version": 1, "tasks": []}
    if USAGE_PATH.is_file():
        try:
            loaded = json.loads(USAGE_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("tasks"), list):
                payload = loaded
        except json.JSONDecodeError:
            pass
    tasks = [item for item in payload.get("tasks") or [] if isinstance(item, dict)]
    tasks.append(entry)
    payload["tasks"] = tasks
    payload["summary"] = summarize_usage(tasks)
    text = json.dumps(payload, indent=2) + "\n"
    USAGE_PATH.write_text(text, encoding="utf-8")
    pdlc_out = ROOT / "pdlc-out"
    if pdlc_out.is_dir():
        (pdlc_out / "ai-usage.json").write_text(text, encoding="utf-8")
    print(
        "usage provider={provider} model={model} model_tokens={model_tokens} raw_total={tokens} cost_usd={cost}".format(
            provider=payload["summary"].get("provider"),
            model=payload["summary"].get("model") or "n/a",
            model_tokens=payload["summary"].get("model_tokens"),
            tokens=payload["summary"].get("total_tokens"),
            cost=payload["summary"].get("cost_usd"),
        ),
        flush=True,
    )


def run_offline(task: str) -> int:
    script = ROOT / "scripts" / ("fallback-pdlc.py" if task == "pdlc" else "fallback-analyze.py")
    print(f"provider=offline script={script.name}", flush=True)
    return subprocess.call([sys.executable, str(script)], cwd=str(ROOT))


DEFAULT_MODELS = {
    "agent": "composer-2.5",
    "copilot": "claude-haiku-4.5",
}

_PLACEHOLDER_MODELS = frozenset({"", "repo-default", "default", "-"})


def resolve_model(provider: str, explicit: str = "") -> str:
    """Pick a model for the selected provider. Offline has none."""
    if provider == "offline":
        return ""
    env_key = "AGENT_MODEL" if provider == "agent" else "COPILOT_MODEL"
    for raw in (explicit, os.environ.get(env_key, "")):
        value = (raw or "").strip()
        if value.lower() not in _PLACEHOLDER_MODELS:
            return value
    return DEFAULT_MODELS[provider]


def run_copilot(prompt: str, model: str) -> int:
    print(f"provider=copilot model={model}", flush=True)
    env = os.environ.copy()
    env["COPILOT_AUTO_UPDATE"] = "false"
    env.pop("COPILOT_GITHUB_TOKEN", None)
    argv = ["copilot", "--yolo", "--no-ask-user", "-p", prompt]
    if model:
        argv.append(f"--model={model}")
    result = subprocess.run(argv, cwd=str(ROOT), env=env)
    return result.returncode


def _agent_options(sdk: object, api_key: str, model: str) -> dict[str, object]:
    return {
        "api_key": api_key,
        "model": model,
        "local": sdk.LocalAgentOptions(cwd=str(ROOT)),
    }


def run_agent(prompt: str, model: str) -> tuple[int, dict[str, int | None], float | None]:
    api_key = os.environ.get("AGENT_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("AGENT_API_KEY is not set")
    if not model:
        raise RuntimeError("AGENT_MODEL is not set")
    print(f"provider=agent model={model}", flush=True)
    module = os.environ.get("AGENT_SDK_MODULE", "").strip()
    if not module:
        raise RuntimeError("AGENT_SDK_MODULE is not set")
    sdk = importlib.import_module(module)
    skill_path = PDLC_SKILL if "analyze-pdlc-release" in prompt else VENDOR_SKILL
    skill_text = skill_path.read_text(encoding="utf-8") if skill_path.exists() else ""
    full_prompt = "\n\n".join(part for part in (skill_text, prompt) if part)
    options = _agent_options(sdk, api_key, model)
    try:
        result = sdk.Agent.prompt(full_prompt, sdk.AgentOptions(**options))
    except Exception as exc:
        print(f"agent startup failed: {exc}", file=sys.stderr, flush=True)
        return 1, tokens_from_result(None), None
    print(f"agent status={result.status}", flush=True)
    tokens = tokens_from_result(result)
    print(
        "agent tokens input={input} output={output} cache_read={cache_r} "
        "cache_write={cache_w} model={model_tokens} raw_total={total}".format(
            input=tokens.get("input_tokens"),
            output=tokens.get("output_tokens"),
            cache_r=tokens.get("cache_read_tokens"),
            cache_w=tokens.get("cache_write_tokens"),
            model_tokens=tokens.get("model_tokens"),
            total=tokens.get("total_tokens"),
        ),
        flush=True,
    )
    return 0 if result.status != "error" else 2, tokens, None


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
    parser.add_argument(
        "--model",
        default="",
        help="model id for the selected provider (ignored when offline)",
    )
    args = parser.parse_args()
    provider = normalize_provider(args.provider)
    model = resolve_model(provider, args.model)
    prompt = PDLC_PROMPT if args.task == "pdlc" else VENDOR_PROMPT
    out_dir = ROOT / ("pdlc-out" if args.task == "pdlc" else "issues-out")
    out_dir.mkdir(parents=True, exist_ok=True)

    def output_ready() -> bool:
        if args.task == "pdlc":
            return (out_dir / "analysis.json").is_file()
        return any(out_dir.glob("*.json"))

    if provider == "offline":
        print("provider=offline model=n/a", flush=True)
        code = run_offline(args.task)
        persist_usage(
            usage_entry(task=args.task, requested=provider, used="offline", model="", fallback=False)
        )
        return code
    if provider == "copilot":
        code = run_copilot(prompt, model)
        if code != 0 or not output_ready():
            print("copilot failed or wrote no JSON; using offline analysis", flush=True)
            offline = run_offline(args.task)
            persist_usage(
                usage_entry(
                    task=args.task,
                    requested=provider,
                    used="offline",
                    model=model,
                    fallback=True,
                )
            )
            return offline
        persist_usage(
            usage_entry(task=args.task, requested=provider, used="copilot", model=model)
        )
        return 0
    try:
        code, tokens, cost = run_agent(prompt, model)
    except Exception as exc:
        print(f"agent failed: {exc}; using offline analysis", file=sys.stderr, flush=True)
        offline = run_offline(args.task)
        persist_usage(
            usage_entry(
                task=args.task,
                requested=provider,
                used="offline",
                model=model,
                fallback=True,
            )
        )
        return offline
    if code != 0 or not output_ready():
        print("agent run failed or wrote no JSON; using offline analysis", flush=True)
        offline = run_offline(args.task)
        persist_usage(
            usage_entry(
                task=args.task,
                requested=provider,
                used="offline",
                model=model,
                fallback=True,
            )
        )
        return offline
    persist_usage(
        usage_entry(
            task=args.task,
            requested=provider,
            used="agent",
            model=model,
            tokens=tokens,
            cost_usd=cost,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
