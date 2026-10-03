#!/usr/bin/env python3
"""Build an incident timeline from log lines.

Normalises timestamps to UTC and emits a sorted CSV conforming to the table in
06-defense/ir/timeline.md.

Usage:
    python 11-automation/scripts/build_timeline.py --input logs/ --output timeline.csv
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TS_PATTERNS = [
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})"),
    re.compile(r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
]


def extract_ts(line: str) -> tuple[str | None, str]:
    for pattern in TS_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group("ts"), line
    return None, line


def normalise(raw: str) -> str | None:
    raw = raw.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S"):
        try:
            parsed = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="file or directory")
    parser.add_argument("--output", required=True)
    parser.add_argument("--source", default="log")
    args = parser.parse_args()

    src = Path(args.input)
    files = sorted(src.rglob("*")) if src.is_dir() else [src]
    files = [f for f in files if f.is_file()]

    rows = []
    for path in files:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                raw, whole = extract_ts(line)
                if not raw:
                    continue
                stamp = normalise(raw)
                if stamp:
                    rows.append({"timestamp": stamp, "source": args.source,
                                 "raw": whole.strip()[:400]})
    rows.sort(key=lambda r: r["timestamp"])

    with Path(args.output).open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["timestamp", "source", "raw"],
                                lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"timeline: {len(rows)} events from {len(files)} file(s) -> {args.output}")
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
