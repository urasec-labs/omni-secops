"""verify: structure, references, coverage gates."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from . import spec

PL_ID = re.compile(r"PL-[A-Z0-9]+-[0-9]{4}")
EV_ID = re.compile(r"EV-(?:LNX|WIN|MAC|CTR|CI)-[0-9]{4}")
TECH_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
SID = re.compile(r"\bsid:\s*(\d{6,7})\b")


def _read_csv(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return [dict(r) for r in csv.DictReader(fh)]


def verify_structure(root: Path, strict: bool) -> list[str]:
    problems = []
    for path, _s, _b in spec.TREE:
        d = root / path
        if not d.is_dir():
            problems.append(f"STRUCT-001 missing directory {path}")
        elif not (d / "README.md").is_file():
            problems.append(f"STRUCT-001 {path} has no README.md")
    if strict:
        # every curated file must live under an existing spec directory
        from .render import all_files
        top_level_dirs = {p for p, _s, _b in spec.TREE if "/" not in p}
        for rel in all_files():
            if "/" in rel:
                top = rel.split("/")[0]
                if top not in top_level_dirs:
                    problems.append(f"STRUCT-001 {rel} lives outside the top-level spec")
    return problems


def _payload_ids(root: Path) -> set[str]:
    out = set()
    for path in (root / "02-payloads").rglob("payloads.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for item in data.get("payloads", []):
            out.add(item.get("payload_id", ""))
    return out


def _evasion_ids(root: Path) -> set[str]:
    return {r["evasion_id"] for r in _read_csv(root / "04-evasion/index/evasion-index.csv")}


def _control_ids(root: Path) -> set[str]:
    return {r["control_id"] for r in _read_csv(root / "01-intel/cheat-sheets/owasp/owasp-controls.csv")}


def _sigma_files(root: Path) -> set[str]:
    return {p.name for p in (root / "06-defense/sigma").glob("*.yml")}


def _sids(root: Path) -> set[str]:
    out = set()
    for path in (root / "06-defense/suricata/rules").glob("*.rules"):
        out.update(SID.findall(path.read_text(encoding="utf-8")))
    return out


def _wazuh_ids(root: Path) -> set[str]:
    out = set()
    for path in (root / "06-defense/wazuh/rules").glob("*.xml"):
        out.update(re.findall(r'<rule\s+id="(\d{5,7})"', path.read_text(encoding="utf-8")))
    return out


def verify_references(root: Path) -> list[str]:
    problems = []
    pl = _payload_ids(root)
    ev = _evasion_ids(root)
    ctrl = _control_ids(root)
    sig = _sigma_files(root)
    sids = _sids(root)
    waz = _wazuh_ids(root)

    xp = root / "10-crosswalk"
    for csv_path in xp.rglob("*.csv"):
        for row in _read_csv(csv_path):
            for key, val in row.items():
                if key is None or val is None or val == "":
                    continue
                if key.endswith("payload_id") or key == "payload_id":
                    for pid in PL_ID.findall(val):
                        if pid not in pl:
                            problems.append(f"REF-001 {csv_path.name}: unknown payload_id {pid}")
                if key.endswith("evasion_id") or key in ("evasion_ids", "evasion_id"):
                    for eid in EV_ID.findall(val):
                        if eid not in ev:
                            problems.append(f"REF-001 {csv_path.name}: unknown evasion_id {eid}")
                if key == "control_id":
                    if val not in ctrl:
                        problems.append(f"REF-001 {csv_path.name}: unknown control_id {val}")
                if key.endswith("sigma_rule") or key == "sigma_rules":
                    for name in val.split("|"):
                        name = name.strip()
                        if name and name.endswith(".yml") and name not in sig:
                            problems.append(f"REF-001 {csv_path.name}: unknown sigma {name}")
                if key.endswith("sid") or key in ("suricata_sids", "expected_suricata"):
                    for sid in re.findall(r"\d{6,7}", val):
                        if sid and sid not in sids:
                            problems.append(f"REF-001 {csv_path.name}: unknown sid {sid}")
                if key.endswith("wazuh_rule") or key in ("wazuh_rules", "expected_wazuh"):
                    for rid in re.findall(r"\d{5,7}", val):
                        if rid and rid not in waz:
                            problems.append(f"REF-001 {csv_path.name}: unknown wazuh rule {rid}")
    return problems


def verify_coverage(root: Path) -> list[str]:
    problems = []
    controls = _control_ids(root)
    if not controls:
        return ["COV-001 no owasp-controls.csv found"]
    rows = _read_csv(root / "10-crosswalk/control-detection/control-detection.csv")
    anchored = {r["control_id"] for r in rows if any([r.get("suricata_sid"), r.get("wazuh_rule"), r.get("sigma_rule")])}
    for cid in sorted(controls):
        if cid not in anchored:
            problems.append(f"COV-001 control {cid} has no detection anchor")
    return problems
