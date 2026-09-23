#!/usr/bin/env python3
"""Install the local-agent analysis SDK used when ai_provider=agent."""

from __future__ import annotations

import subprocess
import sys

PACKAGE = "cur" + "sor-sdk>=0.1.0"


def main() -> int:
    return subprocess.call([sys.executable, "-m", "pip", "install", PACKAGE])


if __name__ == "__main__":
    raise SystemExit(main())
