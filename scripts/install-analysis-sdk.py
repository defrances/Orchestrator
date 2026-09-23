#!/usr/bin/env python3
"""Install the optional local analysis SDK when ai_provider=agent."""

from __future__ import annotations

import os
import subprocess
import sys


def main() -> int:
    package = os.environ.get("AGENT_SDK_PACKAGE", "").strip()
    if not package:
        print("AGENT_SDK_PACKAGE is unset; skip install", flush=True)
        return 0
    return subprocess.call([sys.executable, "-m", "pip", "install", package])


if __name__ == "__main__":
    raise SystemExit(main())
