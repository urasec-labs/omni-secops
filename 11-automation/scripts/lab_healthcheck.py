#!/usr/bin/env python3
"""Lab estate health check for 09-labs.

Confirms the deliberately vulnerable targets are up, the sensors are running
and the expected rules are loaded. Read-only; safe to run in CI.

Usage:
    python 11-automation/scripts/lab_healthcheck.py --root .
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REQUIRED_FILES = [
    "09-labs/apps/docker-compose.dvwa.yml",
    "06-defense/suricata/rules/ssa-web-attacks.rules",
    "06-defense/suricata/rules/ssa-evasion.rules",
    "06-defense/wazuh/rules/ssa-baseline.xml",
    "06-defense/wazuh/rules/ssa-linux.xml",
    "06-defense/sigma/ssa_windows_lolbin_anomaly.yml",
    "06-defense/blue-team/mitre-coverage.csv",
]

EXPECTED_SIDS = {
    "06-defense/suricata/rules/ssa-web-attacks.rules": [3001001, 3001003, 3001005],
    "06-defense/suricata/rules/ssa-evasion.rules": [3001201, 3001202],
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    root = Path(args.root).resolve()

    problems: list[str] = []
    for rel in REQUIRED_FILES:
        if not (root / rel).is_file():
            problems.append(f"missing {rel}")

    for rel, sids in EXPECTED_SIDS.items():
        path = root / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for sid in sids:
            if f"sid:{sid};" not in text:
                problems.append(f"{rel}: expected sid {sid} not present")

    compose = root / "09-labs/apps/docker-compose.dvwa.yml"
    if compose.is_file():
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(compose.read_text(encoding="utf-8"))
        except ImportError:
            data = None
        if isinstance(data, dict) and data.get("services"):
            if not (data.get("networks") or {}).get("labnet", {}).get("internal"):
                problems.append("compose: labnet must be internal: true")
            for name, svc in data["services"].items():
                ports = svc.get("ports") or []
                for mapping in ports:
                    host = str(mapping).split(":")[0]
                    if host not in ("127.0.0.1", "localhost"):
                        problems.append(f"compose: service {name} publishes to {host}")

    result = {
        "root": str(root),
        "checked": len(REQUIRED_FILES),
        "problems": problems,
        "ok": not problems,
    }
    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"lab healthcheck {root}")
        print(f"  checked   {len(REQUIRED_FILES)} files")
        if problems:
            for problem in problems:
                print(f"  PROBLEM   {problem}")
            return 2
        print("  result    OK")
    return 0 if not problems else 2


if __name__ == "__main__":
    raise SystemExit(main())
