#!/usr/bin/env python3
"""Render the 10-crosswalk CSV artefacts from their upstream sources.

Targets:
  control-detection   01-intel/cheat-sheets/owasp/owasp-controls.csv
                      + 06-defense rule inventories
  evasion-detection   04-evasion/index/evasion-index.csv
  attack-coverage     08-threatintel/attack + 06-defense/blue-team/mitre-coverage.csv

The generated files are sorted by their join key so git diffs stay readable and
the archive manifest hash stays stable.

Usage:
    python 11-automation/scripts/render_crosswalks.py --root . --target all
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

SURICATA_SID = re.compile(r"\bsid\s*:\s*(\d{6,7})\s*;")
WAZUH_RULE = re.compile(r'<rule\s+id="(\d{5,7})"')
SIGMA_FILE = re.compile(r"^id:\s*(ssa_[a-z0-9_]+)", re.M)


def read_csv(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return [dict(row) for row in csv.DictReader(fh)]


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, lineterminator="\n",
                                extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def suricata_inventory(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted((root / "06-defense" / "suricata" / "rules").glob("*.rules")):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = SURICATA_SID.search(line)
            if match:
                out[match.group(1)] = path.relative_to(root).as_posix()
    return out


def wazuh_inventory(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted((root / "06-defense" / "wazuh" / "rules").glob("*.xml")):
        for match in WAZUH_RULE.finditer(path.read_text(encoding="utf-8")):
            out[match.group(1)] = path.relative_to(root).as_posix()
    return out


def sigma_inventory(root: Path) -> set[str]:
    return {p.name for p in sorted((root / "06-defense" / "sigma").glob("*.yml"))}


def render_control_detection(root: Path) -> int:
    controls = read_csv(root / "01-intel" / "cheat-sheets" / "owasp" / "owasp-controls.csv")
    if not controls:
        print("WARN no owasp-controls.csv; skipping control-detection")
        return 0
    sids = suricata_inventory(root)
    wazuh = wazuh_inventory(root)
    sigmas = sigma_inventory(root)

    rows = []
    for control in sorted(controls, key=lambda c: c["control_id"]):
        anchor_kind = control.get("anchor_layer", "application")
        anchor_id = (control.get("anchor_id") or "").strip()
        sid = anchor_id if re.fullmatch(r"\d{6,7}", anchor_id) else ""
        rule = anchor_id if re.fullmatch(r"\d{5,7}", anchor_id) else ""
        sigma = anchor_id if anchor_id.endswith(".yml") else ""

        if sid:
            anchor_kind = "suricata"
        elif rule and rule in wazuh:
            anchor_kind = "wazuh"
        elif sigma and sigma in sigmas:
            anchor_kind = "sigma"

        rows.append(
            {
                "control_id": control["control_id"],
                "sheet": control.get("sheet", ""),
                "severity": control.get("severity", ""),
                "cwe_id": control.get("cwe_id", ""),
                "anchor_layer": control.get("anchor_layer", ""),
                "anchor_kind": anchor_kind,
                "suricata_sid": sid,
                "wazuh_rule": rule if rule in wazuh else "",
                "sigma_rule": sigma,
                "suricata_file": sids.get(sid, ""),
                "wazuh_file": wazuh.get(rule, ""),
                "confidence": "high" if anchor_kind in ("suricata", "wazuh") else "medium",
                "residual_gap": control.get("notes", ""),
                "reviewed": control.get("reviewed", ""),
            }
        )
    # `notes` is not part of the upstream catalogue schema; drop it from output
    for row in rows:
        row.setdefault("residual_gap", "")
    target = root / "10-crosswalk" / "control-detection" / "control-detection.csv"
    existing = {r["control_id"]: r for r in read_csv(target)}
    for row in rows:
        prev = existing.get(row["control_id"])
        if prev:
            row["residual_gap"] = prev.get("residual_gap", "") or ""
            row["reviewed"] = prev.get("reviewed", "") or row.get("reviewed", "")
        row["residual_gap"] = row.get("residual_gap", "")
        row.setdefault("reviewed", "")
    fields = ["control_id", "sheet", "severity", "cwe_id", "anchor_layer", "anchor_kind",
              "suricata_sid", "wazuh_rule", "sigma_rule", "suricata_file", "wazuh_file",
              "confidence", "residual_gap", "reviewed"]
    write_csv(target, fields, rows)
    print(f"control-detection.csv  {len(rows)} rows")
    return 0


def render_evasion_detection(root: Path) -> int:
    index = read_csv(root / "04-evasion" / "index" / "evasion-index.csv")
    if not index:
        print("WARN no evasion-index.csv; skipping evasion-detection")
        return 0
    sigmas = sigma_inventory(root)
    sids = suricata_inventory(root)

    rows = []
    for item in sorted(index, key=lambda r: r["evasion_id"]):
        sigma = item.get("sigma", "").strip()
        host = item.get("host_rule", "").strip()
        network = item.get("network_rule", "").strip()
        rows.append(
            {
                "evasion_id": item["evasion_id"],
                "technique_id": item["technique_id"],
                "sigma_rule": sigma if sigma in sigmas else "",
                "sigma_level": "high" if item.get("triage_cost") == "low" else "medium",
                "wazuh_rule": host if host.isdigit() else "",
                "suricata_sid": network if network.isdigit() else "",
                "audit_logsource": "auditd" if item.get("platform") == "linux" else "sysmon",
                "confidence": item.get("confidence", "medium"),
                "playbook": item.get("runbook", ""),
                "module": item.get("module", ""),
                "first_mapped": "2026-01-15",
            }
        )
    fields = ["evasion_id", "technique_id", "sigma_rule", "sigma_level", "wazuh_rule",
              "suricata_sid", "audit_logsource", "confidence", "playbook", "module", "first_mapped"]
    write_csv(root / "10-crosswalk" / "evasion-detection" / "evasion-to-detection.csv",
              fields, rows)
    print(f"evasion-to-detection.csv  {len(rows)} rows")
    return 0


def render_attack_coverage(root: Path) -> int:
    coverage = read_csv(root / "06-defense" / "blue-team" / "mitre-coverage.csv")
    if not coverage:
        print("WARN no mitre-coverage.csv; skipping attack-coverage")
        return 0
    rows = []
    for item in sorted(coverage, key=lambda r: r["technique_id"]):
        rows.append(
            {
                "technique_id": item["technique_id"],
                "tactic": item.get("tactic", ""),
                "name": item.get("name", ""),
                "playbooks": "",
                "payload_ids": "",
                "wordlists": "",
                "evasion_ids": "",
                "modules": "",
                "sigma_rules": item.get("detection_artifacts", ""),
                "wazuh_rules": "",
                "suricata_sids": "",
                "emulations": "",
                "coverage_state": item.get("coverage_state", ""),
                "gap_note": item.get("gap_note", ""),
                "last_reviewed": item.get("last_reviewed", ""),
            }
        )
    fields = ["technique_id", "tactic", "name", "playbooks", "payload_ids", "wordlists",
              "evasion_ids", "modules", "sigma_rules", "wazuh_rules", "suricata_sids",
              "emulations", "coverage_state", "gap_note", "last_reviewed"]
    write_csv(root / "10-crosswalk" / "attack-coverage" / "attack-coverage.csv", fields, rows)
    print(f"attack-coverage.csv  {len(rows)} rows")
    return 0


TARGETS = {
    "control-detection": render_control_detection,
    "evasion-detection": render_evasion_detection,
    "attack-coverage": render_attack_coverage,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Render SSA crosswalk artefacts")
    parser.add_argument("--root", default=".")
    parser.add_argument("--target", default="all", choices=["all", *TARGETS])
    args = parser.parse_args()
    root = Path(args.root).resolve()
    handlers = TARGETS.values() if args.target == "all" else [TARGETS[args.target]]
    for handler in handlers:
        try:
            handler(root)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR {handler.__name__}: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
