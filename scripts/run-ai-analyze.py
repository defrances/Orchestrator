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
SKILLS_ROOT = ROOT / ".github" / "skills"

ROLE_TASKS = ("architect", "test-engineer", "cybersec", "product-safety", "sqa")
ROLE_META = {
    "architect": {
        "skill_name": "Architect_Skill",
        "dir": "architect-skill",
        "out_rel": "skills-out/architect/review.json",
    },
    "test-engineer": {
        "skill_name": "Test_Engineer_Skill",
        "dir": "test-engineer-skill",
        "out_rel": "skills-out/test-engineer/review.json",
    },
    "cybersec": {
        "skill_name": "CyberSec_Engineer_Skill",
        "dir": "cybersec-engineer-skill",
        "out_rel": "skills-out/cybersec/review.json",
    },
    "product-safety": {
        "skill_name": "Product_Safety_Engineer_Skill",
        "dir": "product-safety-engineer-skill",
        "out_rel": "skills-out/product-safety/review.json",
    },
    "sqa": {
        "skill_name": "SQA_Engineer_Skill",
        "dir": "sqa-engineer-skill",
        "out_rel": "skills-out/sqa/review.json",
    },
}

PDLC_PROMPT = """Follow .github/skills/analyze-pdlc-release/SKILL.md.

Read inputs/architecture.md, inputs/mds2.md, inputs/test-plan.md, and inputs/vulnerability-report.md.
Analyze Host Application (workspace/HostApplication) on branch main (see workspace/host-application-inventory.md).
For each product finding, set countermeasure present/absent/partial, cite files, list tests_to_run, and write a patch_plan.
Do not treat FindUpdates station KB rows as product vulnerabilities.
os_kb_advice must not package Windows KBs.
Write pdlc-out/analysis.json only. Do not call gh issue create. Do not deploy.
"""

VENDOR_PROMPT = """Follow .github/skills/analyze-vendor-update-impact/SKILL.md.

Analyze Host Application (workspace/HostApplication) on branch main (see workspace/host-application-inventory.md).
Read every source file listed in that inventory before writing analysis JSON.
The numbered configuration labels are Config1, Config2, … from sorted lab device_id values (same order as the GitHub Page).
Score install_risk, skip_risk, required_for_app, and compatibility against libraries and logic on main.
Also set vendor_severity, vendor_likelihood, vendor_risk, product_severity, product_likelihood, and product_risk as C/H/M/L. Vendor likelihood: KEV is C, high exploitability is H, unknown is M. Product risk may be L when vendor risk is C.
Cluster rows that share the same numbered configuration, cluster_key, risk fields, and Recommendation into ONE analysis file.
Write one file per numbered configuration that has rows for that cluster_key. Do not collapse every configuration into one email. Cap at 8 cluster_key values. Prefer cluster_key values from the skill.
Input report: inputs/report.json
Write analysis JSON files only to issues-out/. Do not call gh issue create. Do not publish GitHub Issues. Do not deploy.
"""

ROLE_REVIEWS_PROMPT = """Follow these role skills in order:
- Architect_Skill (.github/skills/architect-skill/SKILL.md)
- Test_Engineer_Skill (.github/skills/test-engineer-skill/SKILL.md)
- CyberSec_Engineer_Skill (.github/skills/cybersec-engineer-skill/SKILL.md)
- Product_Safety_Engineer_Skill (.github/skills/product-safety-engineer-skill/SKILL.md)
- SQA_Engineer_Skill (.github/skills/sqa-engineer-skill/SKILL.md)

Review existing files under issues-out/ and pdlc-out/analysis.json.
Analyze Host Application (workspace/HostApplication) on branch main (see workspace/host-application-inventory.md).
The numbered configuration labels are Config1, Config2, … from sorted lab device_id values (same order as the GitHub Page).
Write one review file per skill:
- skills-out/architect/review.json
- skills-out/test-engineer/review.json
- skills-out/cybersec/review.json
- skills-out/product-safety/review.json
- skills-out/sqa/review.json
Do not call gh issue create. Do not deploy. Do not change HOLD/BLOCK. Do not open Windchill, Quality, or Regulatory tickets.
"""


def _role_skill(folder: str) -> Path:
    return SKILLS_ROOT / folder / "SKILL.md"


def role_prompt(task: str) -> str:
    meta = ROLE_META[task]
    return f"""Follow {meta["skill_name"]} (.github/skills/{meta["dir"]}/SKILL.md).

Review existing files under issues-out/ and pdlc-out/analysis.json.
Analyze Host Application (workspace/HostApplication) on branch main (see workspace/host-application-inventory.md).
The numbered configuration labels are Config1, Config2, … from sorted lab device_id values (same order as the GitHub Page).
Write {meta["out_rel"]} only. Do not call gh issue create. Do not deploy. Do not change HOLD/BLOCK. Do not open Windchill, Quality, or Regulatory tickets.
"""


def role_ready(task: str) -> bool:
    return (ROOT / ROLE_META[task]["out_rel"]).is_file()


def task_spec(task: str) -> dict[str, object]:
    if task == "pdlc":
        return {
            "prompt": PDLC_PROMPT,
            "skills": [PDLC_SKILL],
            "out_dir": ROOT / "pdlc-out",
            "ready": lambda: (ROOT / "pdlc-out" / "analysis.json").is_file(),
        }
    if task == "vendor-impact":
        return {
            "prompt": VENDOR_PROMPT,
            "skills": [VENDOR_SKILL],
            "out_dir": ROOT / "issues-out",
            "ready": lambda: any((ROOT / "issues-out").glob("*.json")),
        }
    if task == "role-reviews":
        return {
            "prompt": ROLE_REVIEWS_PROMPT,
            "skills": [_role_skill(ROLE_META[name]["dir"]) for name in ROLE_TASKS],
            "out_dir": ROOT / "skills-out",
            "ready": lambda: all(role_ready(name) for name in ROLE_TASKS),
        }
    meta = ROLE_META[task]
    out = ROOT / meta["out_rel"]
    return {
        "prompt": role_prompt(task),
        "skills": [_role_skill(meta["dir"])],
        "out_dir": out.parent,
        "ready": lambda path=out: path.is_file(),
    }


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
    skills_out = ROOT / "skills-out"
    if skills_out.is_dir():
        (skills_out / "ai-usage.json").write_text(text, encoding="utf-8")
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
    if task == "pdlc":
        script = ROOT / "scripts" / "fallback-pdlc.py"
        argv = [sys.executable, str(script)]
    elif task == "vendor-impact":
        script = ROOT / "scripts" / "fallback-analyze.py"
        argv = [sys.executable, str(script)]
    else:
        script = ROOT / "scripts" / "fallback-role-reviews.py"
        argv = [sys.executable, str(script)]
        if task != "role-reviews":
            argv.extend(["--role", task])
    print(f"provider=offline script={script.name}", flush=True)
    return subprocess.call(argv, cwd=str(ROOT))


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


def run_agent(
    prompt: str, model: str, skill_paths: list[Path] | None = None
) -> tuple[int, dict[str, int | None], float | None]:
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
    skill_paths = skill_paths or []
    skill_text = "\n\n".join(
        path.read_text(encoding="utf-8") for path in skill_paths if path.exists()
    )
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
    parser.add_argument(
        "--task",
        choices=("pdlc", "vendor-impact", "role-reviews") + ROLE_TASKS,
        required=True,
    )
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
    spec = task_spec(args.task)
    prompt = str(spec["prompt"])
    skill_paths = list(spec["skills"])
    out_dir = spec["out_dir"]
    assert isinstance(out_dir, Path)
    out_dir.mkdir(parents=True, exist_ok=True)
    ready = spec["ready"]
    assert callable(ready)

    def output_ready() -> bool:
        return bool(ready())

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
        code, tokens, cost = run_agent(prompt, model, skill_paths)
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
