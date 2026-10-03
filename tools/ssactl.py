#!/usr/bin/env python3
"""Entry shim: `python tools/ssactl.py <command>`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.ssactl.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
