#!/usr/bin/env python3
"""Store the GitHub PAT once on this PC. Never prints the value."""

from __future__ import annotations

import argparse
import getpass
import subprocess
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
import github_token


def _from_git() -> str:
    proc = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit("git credential fill failed")
    for line in proc.stdout.splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("git credential had no password")


def _read_token(args: argparse.Namespace) -> str:
    if args.clear:
        return ""
    if args.from_git:
        return _from_git()
    if args.stdin:
        return sys.stdin.read().strip()
    if not sys.stdin.isatty():
        raise SystemExit("pass --stdin to read the token from a pipe")
    return getpass.getpass("GitHub PAT (input hidden): ").strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Store the GitHub PAT on this PC. Never prints the value."
    )
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--from-git", action="store_true")
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--clear", action="store_true")
    args = parser.parse_args()
    if not args.replace and not args.clear and not args.from_git and not args.stdin:
        existing = github_token.load(args.root)
        if existing:
            if args.root is None:
                github_token._os_write(existing)
            print("Token already stored on this PC.")
            return 0
    token = _read_token(args)
    if not args.clear and not token:
        print("empty token", file=sys.stderr)
        return 1
    path = github_token.write(token, root=args.root)
    if args.clear:
        print("Token cleared from this PC.")
        return 0
    extra = ""
    if args.root is None and sys.platform == "win32":
        extra = " and Windows Credential Manager"
    print("Token stored for this PC (" + str(path) + extra + ").")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
