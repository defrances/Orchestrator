#!/usr/bin/env python3
"""Describe the DesktopApplication main checkout for the Copilot skill."""

from __future__ import annotations

import subprocess
from pathlib import Path

APP = Path("workspace/DesktopApplication")
OUT = Path("workspace/desktop-application-inventory.md")
SKIP_PARTS = {".git", "bin", "obj", "artifacts"}


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(APP), *args],
        check=False,
        text=True,
        capture_output=True,
    )
    text = (result.stdout or result.stderr or "").strip()
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed:\n{text}")
    return text


def source_files() -> list[Path]:
    files: list[Path] = []
    for path in APP.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(APP).parts)
        if parts & SKIP_PARTS:
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.as_posix().lower())


def main() -> int:
    if not (APP / ".git").exists():
        raise SystemExit(f"missing git checkout at {APP}")

    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    sha = git("rev-parse", "HEAD")
    if branch != "main":
        raise SystemExit(f"DesktopApplication checkout must be main, got {branch} ({sha})")

    files = source_files()
    lines = [
        "# DesktopApplication main inventory",
        "",
        f"- Remote: https://github.com/defrances/DesktopApplication",
        f"- Branch: `{branch}`",
        f"- HEAD: `{sha}`",
        f"- Tracked-like source files: {len(files)}",
        "",
        "## Recent commits on main",
        "",
        "```",
        git("log", "--oneline", "-20"),
        "```",
        "",
        "## Files the skill must read",
        "",
    ]
    for path in files:
        rel = path.relative_to(APP).as_posix()
        lines.append(f"- `workspace/DesktopApplication/{rel}`")
    lines.append("")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUT} ({len(files)} files, {branch} {sha})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
