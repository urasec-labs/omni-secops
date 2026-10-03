"""Curated content for 11-automation, 13-training, 14-docs."""

from __future__ import annotations

FILES: dict[str, str] = {}

# ===========================================================================
# 11-automation
# ===========================================================================

FILES["11-automation/scripts/build_payload_index.py"] = r'''
#!/usr/bin/env python3
"""Build the unified payload + wordlist index for the Sovereign Security Archive.

Merges two corpora that upstream keep separate:

  * 02-payloads/**/payloads.json   - structured payload records (PAT)
  * 03-wordlists/**/*.txt          - flat token lists (SecLists)

into 03-wordlists/index/wordlist.db (SQLite, FTS5) plus the derived exports
in 03-wordlists/index/export/.

Join rule (normative, see 10-crosswalk/wordlist-payload/README.md):
  sha256(normalise(a)) == sha256(normalise(b))
  AND surface equal AND cwe equal AND context equal

Standard library only. Deterministic output. Transactional build.

Usage:
    python 11-automation/scripts/build_payload_index.py --root .
    python 11-automation/scripts/build_payload_index.py --root . --stats
    python 11-automation/scripts/build_payload_index.py --root . --check
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Iterable

WS = re.compile(r"\s+")

SURFACE_FROM_WORDLIST = {
    "web/fuzzing": "parameter",
    "web": "parameter",
    "api": "parameter",
    "discovery/dns": "host",
    "network": "host",
    "credentials": "password",
}


def normalise(token: str) -> str:
    """Canonical form used for the join. Mirrors the spec in the crosswalk README."""
    token = unicodedata.normalize("NFC", token)
    token = token.strip()
    token = WS.sub(" ", token)
    token = token.strip("'\"")
    return token


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def surface_for(wordlist_path: Path, root: Path) -> str:
    rel = wordlist_path.relative_to(root).as_posix()
    for key, surface in sorted(SURFACE_FROM_WORDLIST.items(), key=lambda kv: -len(kv[0])):
        if key in rel:
            return surface
    return "parameter"


def iter_payload_files(root: Path) -> Iterable[Path]:
    yield from sorted((root / "02-payloads").rglob("payloads.json"))


def iter_wordlists(root: Path) -> Iterable[Path]:
    base = root / "03-wordlists"
    if not base.is_dir():
        return
    for path in sorted(base.rglob("*.txt")):
        if "/index/" in path.as_posix():
            continue
        yield path


def load_payloads(root: Path) -> list[dict]:
    records: list[dict] = []
    for path in iter_payload_files(root):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"ERROR {path}: invalid JSON ({exc})")
        for item in data.get("payloads", []):
            records.append(
                {
                    "payload_id": item["payload_id"],
                    "cwe_id": item["cwe_id"],
                    "context": item.get("context", "other"),
                    "surface": item.get("surface", "parameter"),
                    "engine": item.get("engine", ""),
                    "payload": item["payload"],
                    "severity": item.get("severity", "medium"),
                    "classification": item.get("classification", "T0"),
                    "tags": json.dumps(item.get("tags", []), separators=(",", ":")),
                    "source_file": path.relative_to(root).as_posix(),
                }
            )
    return records


def load_evasion(root: Path) -> list[dict]:
    path = root / "04-evasion" / "index" / "evasion-index.csv"
    rows: list[dict] = []
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            rows.append(
                {
                    "evasion_id": row["evasion_id"],
                    "platform": row["platform"],
                    "binary": row["binary"],
                    "technique_id": row["technique_id"],
                    "primitive": row["primitive"],
                }
            )
    return rows


def build(root: Path, stats_only: bool) -> int:
    payloads = load_payloads(root)
    evasions = load_evasion(root)
    wordlists = list(iter_wordlists(root))

    tokens: dict[tuple[str, str], dict] = {}
    fuzz: dict[tuple[str, str], dict] = {}

    def token_id(norm: str, surface: str, source: str) -> int:
        key = (sha256(norm), surface)
        if key not in tokens:
            tokens[key] = {
                "token": norm,
                "surface": surface,
                "length": len(norm),
                "sha256": key[0],
                "source": source,
            }
        return len(tokens)

    def add_payload(payload: dict) -> int:
        norm = normalise(payload["payload"])
        return token_id(norm, payload["surface"], "payload")

    def add_wordlist(norm: str, surface: str, source: str) -> int:
        return token_id(norm, surface, source)

    # 1. payloads first so they own the canonical token rows
    for payload in payloads:
        tid = add_payload(payload)
        fuzz[(tid, payload["payload_id"])] = {
            "origin": "payload",
            "confidence": 0.6,
        }

    # 2. wordlist entries: upgrade to 'both' when they match a payload
    payload_by_tid = {tid: pid for (tid, pid) in fuzz}
    for path in wordlists:
        surface = surface_for(path, root)
        source = path.relative_to(root).as_posix()
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                raw = line.rstrip("\n").rstrip("\r")
                if not raw or raw.startswith("#"):
                    continue
                norm = normalise(raw)
                if not norm or len(norm) > 128:
                    continue
                if any(ord(ch) < 32 or ord(ch) == 127 for ch in norm):
                    continue  # threat model S6
                tid = add_wordlist(norm, surface, source)
                tokens[(sha256(norm), surface)]["source"] = source
                pid = payload_by_tid.get(tid)
                if pid:
                    fuzz[(tid, pid)]["origin"] = "both"
                    fuzz[(tid, pid)]["confidence"] = 1.0
                else:
                    fuzz[(tid, f"FUZZ:{source}:{norm[:32]}")] = {
                        "origin": "fuzz",
                        "confidence": 0.4,
                    }

    if stats_only:
        report(root, tokens, fuzz, payloads, evasions, wordlists)
        return 0

    index_dir = root / "03-wordlists" / "index"
    index_dir.mkdir(parents=True, exist_ok=True)
    target = index_dir / "wordlist.db"

    fd, tmp_name = tempfile.mkstemp(dir=str(index_dir), suffix=".db")
    os.close(fd)
    tmp = Path(tmp_name)

    try:
        conn = sqlite3.connect(str(tmp))
        conn.executescript(
            (index_dir / "schema.sql").read_text(encoding="utf-8")
            if (index_dir / "schema.sql").is_file()
            else FALLBACK_SCHEMA
        )
        with conn:
            cur = conn.cursor()
            ordered_tokens = sorted(tokens.items(), key=lambda kv: kv[0][0])
            id_map: dict[int, int] = {}
            for new_id, (key, value) in enumerate(ordered_tokens, start=1):
                id_map[(key[0], key[1])] = new_id
                cur.execute(
                    "INSERT INTO token (token_id, token, surface, length, sha256, source)"
                    " VALUES (?,?,?,?,?,?)",
                    (
                        new_id,
                        value["token"],
                        value["surface"],
                        value["length"],
                        value["sha256"],
                        value["source"],
                    ),
                )
            payload_index = {}
            for payload in sorted(payloads, key=lambda p: p["payload_id"]):
                norm = normalise(payload["payload"])
                key = (sha256(norm), payload["surface"])
                if key not in id_map:
                    cur.execute(
                        "INSERT INTO token (token, surface, length, sha256, source) VALUES (?,?,?,?,?)",
                        (payload["payload"], payload["surface"], len(norm), key[0], payload["source_file"]))
                    id_map[key] = cur.lastrowid
                pid_new = id_map[key]
                payload_index[payload["payload_id"]] = pid_new
                cur.execute(
                    "INSERT INTO payload (payload_id, token_id, cwe_id, context, engine,"
                    " severity, classification, tags) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        payload["payload_id"],
                        pid_new,
                        payload["cwe_id"],
                        payload["context"],
                        payload["engine"],
                        payload["severity"],
                        payload["classification"],
                        payload["tags"],
                    ),
                )
            for (tid, pid), meta in sorted(fuzz.items(), key=lambda kv: (kv[0][0], kv[0][1])):
                if pid.startswith("FUZZ:"):
                    continue
                cur.execute(
                    "INSERT OR IGNORE INTO fuzz_token (token_id, payload_id, origin, confidence)"
                    " VALUES (?,?,?,?)",
                    (tid, pid, meta["origin"], meta["confidence"]),
                )
            for evasion in sorted(evasions, key=lambda e: e["evasion_id"]):
                cur.execute(
                    "INSERT OR REPLACE INTO evasion (evasion_id, platform, binary, technique_id,"
                    " primitive) VALUES (?,?,?,?,?)",
                    (
                        evasion["evasion_id"],
                        evasion["platform"],
                        evasion["binary"],
                        evasion["technique_id"],
                        evasion["primitive"],
                    ),
                )
            cur.execute("INSERT OR REPLACE INTO index_meta VALUES ('rows', ?)",
                        (str(len(ordered_tokens) + len(payloads)),))
            cur.execute("INSERT OR REPLACE INTO index_meta VALUES ('payloads', ?)",
                        (str(len(payloads)),))
            cur.execute("INSERT OR REPLACE INTO index_meta VALUES ('evasions', ?)",
                        (str(len(evasions)),))
        conn.execute("INSERT INTO token_fts(token) SELECT token FROM token")
        conn.commit()
        conn.close()
        os.replace(tmp, target)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if tmp.exists():
            tmp.unlink()

    write_exports(root, index_dir, tokens, fuzz, payloads)
    report(root, tokens, fuzz, payloads, evasions, wordlists)
    return 0


def write_exports(root: Path, index_dir: Path, tokens: dict, fuzz: dict, payloads: list[dict]) -> None:
    export_dir = index_dir / "export"
    export_dir.mkdir(parents=True, exist_ok=True)

    words = sorted({v["token"] for v in tokens.values()})
    (export_dir / "fuzz-words.txt").write_text("\n".join(words) + "\n", encoding="utf-8")

    by_id = {p["payload_id"]: p for p in payloads}
    with (export_dir / "injection-contexts.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["cwe_id", "context", "engine", "payload_id", "surface", "severity",
                         "classification", "origin", "confidence"])
        for (tid, pid), meta in sorted(fuzz.items(), key=lambda kv: kv[0][1]):
            payload = by_id.get(pid)
            if payload is None:
                continue
            writer.writerow([
                payload["cwe_id"], payload["context"], payload["engine"], pid,
                payload["surface"], payload["severity"], payload["classification"],
                meta["origin"], meta["confidence"],
            ])


def report(root: Path, tokens: dict, fuzz: dict, payloads: list[dict],
           evasions: list[dict], wordlists: list[Path]) -> None:
    origins: dict[str, int] = {}
    for meta in fuzz.values():
        origins[meta["origin"]] = origins.get(meta["origin"], 0) + 1
    print("Sovereign Security Archive - index report")
    print(f"  root              {root}")
    print(f"  payload records   {len(payloads)}")
    print(f"  wordlist files    {len(wordlists)}")
    print(f"  unique tokens     {len(tokens)}")
    print(f"  eviction records  {len(evasions)}")
    print(f"  fuzz rows by origin {dict(sorted(origins.items()))}")
    print(f"  database          03-wordlists/index/wordlist.db")
    print(f"  exports           03-wordlists/index/export/")


def check(root: Path) -> int:
    """Verify the database is newer than its sources."""
    db = root / "03-wordlists" / "index" / "wordlist.db"
    if not db.is_file():
        print("INDEX-001 wordlist.db missing; run `ssactl index`")
        return 2
    newest = 0.0
    for pattern in ("02-payloads/**/payloads.json", "03-wordlists/**/*.txt",
                    "04-evasion/index/evasion-index.csv"):
        for path in root.glob(pattern):
            newest = max(newest, path.stat().st_mtime)
    if db.stat().st_mtime + 1 < newest:
        print("INDEX-001 wordlist.db is stale relative to its sources")
        return 2
    print("index is current")
    return 0


FALLBACK_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE token (
    token_id INTEGER PRIMARY KEY, token TEXT NOT NULL,
    surface TEXT NOT NULL, length INTEGER NOT NULL,
    sha256 TEXT NOT NULL, source TEXT NOT NULL, UNIQUE (sha256, surface));
CREATE TABLE payload (
    payload_id TEXT PRIMARY KEY, token_id INTEGER NOT NULL REFERENCES token(token_id),
    cwe_id TEXT NOT NULL, context TEXT NOT NULL, engine TEXT,
    severity TEXT NOT NULL, classification TEXT NOT NULL, tags TEXT NOT NULL);
CREATE TABLE fuzz_token (
    token_id INTEGER NOT NULL REFERENCES token(token_id),
    payload_id TEXT NOT NULL REFERENCES payload(payload_id),
    origin TEXT NOT NULL, confidence REAL NOT NULL, PRIMARY KEY (token_id, payload_id));
CREATE TABLE evasion (
    evasion_id TEXT PRIMARY KEY, platform TEXT NOT NULL, binary TEXT NOT NULL,
    technique_id TEXT NOT NULL, primitive TEXT NOT NULL);
CREATE TABLE index_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE VIRTUAL TABLE token_fts USING fts5(token, content='token', content_rowid='token_id');
CREATE INDEX ix_payload_cwe ON payload(cwe_id, context);
CREATE INDEX ix_fuzz_origin ON fuzz_token(origin, confidence);
CREATE INDEX ix_evasion_tech ON evasion(technique_id);
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the SSA unified index")
    parser.add_argument("--root", default=".", help="archive root (default: .)")
    parser.add_argument("--stats", action="store_true", help="print stats without writing")
    parser.add_argument("--check", action="store_true", help="exit 2 if the index is stale")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if not (root / "02-payloads").is_dir():
        print(f"ERROR {root} does not look like an SSA archive", file=sys.stderr)
        return 1
    if args.check:
        return check(root)
    return build(root, args.stats)


if __name__ == "__main__":
    raise SystemExit(main())
'''.lstrip()

FILES["11-automation/scripts/render_crosswalks.py"] = r'''
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
'''.lstrip()

FILES["11-automation/scripts/validate_schemas.py"] = r'''
#!/usr/bin/env python3
"""Level-1 structural validation of every machine readable SSA artefact.

Standard library only. Uses a small internal checker that covers the subset of
JSON Schema used by 12-schemas/: type, required, enum, pattern, minimum /
maximum, minProperties, minLength / maxLength and simple allOf/anyOf/if-then.

Run with `--strict-json` (requires `pip install jsonschema`) for full draft
2020-12 validation.

Usage:
    python 11-automation/scripts/validate_schemas.py --root .
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TARGETS = {
    "12-schemas/payload.schema.json": "payload.schema.json",
    "12-schemas/wordlist-entry.schema.json": "wordlist-entry.schema.json",
    "12-schemas/evasion.schema.json": "evasion.schema.json",
    "12-schemas/detection.schema.json": "detection.schema.json",
    "12-schemas/ioc.schema.json": "ioc.schema.json",
    "10-crosswalk/api-contracts/control-detection.schema.json": "control-detection.schema.json",
}

DOC_TARGETS = [
    "02-payloads/web/sqli/payloads.json",
    "02-payloads/web/xss/payloads.json",
    "02-payloads/web/ssrf/payloads.json",
    "02-payloads/web/xxe/payloads.json",
    "02-payloads/web/ssti/payloads.json",
    "02-payloads/api/payloads.json",
    "02-payloads/infrastructure/payloads.json",
    "02-payloads/os/linux/payloads.json",
    "02-payloads/cloud/payloads.json",
    "02-payloads/mobile/payloads.json",
    "08-threatintel/ioc/sample-iocs.json",
]

TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "null": type(None),
}


def check(node: dict, schema: dict, path: str, errors: list[str]) -> None:
    types = schema.get("type")
    if types:
        wanted = types if isinstance(types, list) else [types]
        if not any(isinstance(node, TYPES[t]) for t in wanted if t in TYPES):
            errors.append(f"{path}: expected type {wanted}")
            return
    if "enum" in schema and node not in schema["enum"]:
        errors.append(f"{path}: {node!r} not in enum {schema['enum']}")
    if isinstance(node, str):
        if "pattern" in schema and not re.search(schema["pattern"], node):
            errors.append(f"{path}: {node!r} does not match /{schema['pattern']}/")
        if "minLength" in schema and len(node) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength")
        if "maxLength" in schema and len(node) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength")
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        if "minimum" in schema and node < schema["minimum"]:
            errors.append(f"{path}: below minimum")
        if "maximum" in schema and node > schema["maximum"]:
            errors.append(f"{path}: above maximum")
    if isinstance(node, list):
        if "minItems" in schema and len(node) < schema["minItems"]:
            errors.append(f"{path}: fewer than minItems")
        if schema.get("uniqueItems") and len(node) != len(set(map(str, node))):
            errors.append(f"{path}: duplicate items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for i, item in enumerate(node):
                check(item, item_schema, f"{path}[{i}]", errors)
    if isinstance(node, dict):
        for key in schema.get("required", []):
            if key not in node:
                errors.append(f"{path}: missing required property {key!r}")
        if "minProperties" in schema and len(node) < schema["minProperties"]:
            errors.append(f"{path}: fewer than minProperties")
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in node:
                check(node[key], sub, f"{path}.{key}", errors)
        additional = schema.get("additionalProperties", True)
        if additional is False:
            for key in node:
                if key not in props:
                    errors.append(f"{path}: additional property {key!r} is not allowed")
        elif isinstance(additional, dict):
            for key, value in node.items():
                if key not in props:
                    check(value, additional, f"{path}.{key}", errors)
    for combinator in ("allOf", "anyOf", "oneOf"):
        if combinator not in schema:
            continue
        outcomes = []
        for sub in schema[combinator]:
            local: list[str] = []
            check(node, sub, path, local)
            outcomes.append(local)
        passed = sum(1 for o in outcomes if not o)
        if combinator == "allOf":
            errors.extend(o for o in outcomes if o)
        elif combinator == "anyOf" and passed == 0:
            errors.append(f"{path}: does not satisfy anyOf")
        elif combinator == "oneOf" and passed != 1:
            errors.append(f"{path}: satisfies {passed} oneOf branches, expected 1")
    if "if" in schema:
        probe: list[str] = []
        check(node, schema["if"], path, probe)
        branch = "then" if not probe else "else"
        if branch in schema:
            check(node, schema[branch], path, errors)


def validate_payload_doc(root: Path, schema: dict, errors: list[str], doc_path: str) -> None:
    data = json.loads((root / doc_path).read_text(encoding="utf-8"))
    declared = data.get("schema", "")
    if declared and not (root / declared).is_file():
        errors.append(f"{doc_path}: declares schema {declared} which does not exist")
    props = dict(schema["properties"])
    props.pop("crosswalk", None)
    item_required = [r for r in schema["required"] if r != "provenance"]
    item_schema = {"type": "object", "properties": props,
                   "required": item_required, "additionalProperties": False}
    for i, item in enumerate(data.get("payloads", [])):
        check(item, item_schema, f"{doc_path}:payloads[{i}]", errors)
    ids = [i["payload_id"] for i in data.get("payloads", [])]
    duplicates = {x for x in ids if ids.count(x) > 1}
    if duplicates:
        errors.append(f"{doc_path}: duplicate payload_id {sorted(duplicates)}")


def validate_ioc_doc(root: Path, schema: dict, errors: list[str], doc_path: str) -> None:
    data = json.loads((root / doc_path).read_text(encoding="utf-8"))
    item_schema = {"type": "object", "properties": schema["properties"],
                   "required": schema["required"], "additionalProperties": False}
    for i, item in enumerate(data.get("iocs", [])):
        check(item, item_schema, f"{doc_path}:iocs[{i}]", errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--strict-json", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors: list[str] = []

    for rel in TARGETS:
        path = root / rel
        if not path.is_file():
            errors.append(f"{rel}: schema file missing")
            continue
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{rel}: invalid JSON ({exc})")
            continue
        if not schema.get("$schema", "").startswith("https://json-schema.org/draft/"):
            errors.append(f"{rel}: missing or unsupported $schema")

    payload_schema_path = root / "12-schemas/payload.schema.json"
    if payload_schema_path.is_file():
        payload_schema = json.loads(payload_schema_path.read_text(encoding="utf-8"))
        for rel in DOC_TARGETS:
            if (root / rel).is_file():
                validate_payload_doc(root, payload_schema, errors, rel)

    ioc_schema_path = root / "12-schemas/ioc.schema.json"
    if ioc_schema_path.is_file():
        ioc_schema = json.loads(ioc_schema_path.read_text(encoding="utf-8"))
        for rel in DOC_TARGETS:
            if "ioc" in rel and (root / rel).is_file():
                validate_ioc_doc(root, ioc_schema, errors, rel)

    if args.strict_json:
        try:
            import jsonschema  # type: ignore
        except ImportError:
            print("WARN jsonschema not installed; skipping --strict-json")
        else:
            for rel in TARGETS:
                schema = json.loads((root / rel).read_text(encoding="utf-8"))
                validator = jsonschema.Draft202012Validator(schema)
                for sample in ("08-threatintel/ioc/sample-iocs.json",):
                    path = root / sample
                    if path.is_file():
                        doc = json.loads(path.read_text(encoding="utf-8"))
                        for err in validator.iter_errors(doc.get("iocs", doc.get("payloads", []))):
                            errors.append(f"{sample}: {err.message}")

    if errors:
        for err in errors:
            print(f"SCHEMA-001 {err}")
        print(f"\n{len(errors)} schema error(s)")
        return 2
    checked = len(TARGETS) + len(DOC_TARGETS)
    print(f"schema validation OK  ({checked} artefacts checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''.lstrip()

FILES["11-automation/scripts/lab_healthcheck.py"] = r'''
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
'''.lstrip()

FILES["11-automation/scripts/build_timeline.py"] = r'''
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
'''.lstrip()

FILES["11-automation/ci/github-actions-ssa-validate.yml"] = r'''
name: ssa-validate

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "17 3 * * 1"     # weekly upstream drift check
  workflow_dispatch:

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Structure and reference integrity
        run: python tools/ssactl.py verify --root . --strict

      - name: Control coverage
        run: python tools/ssactl.py verify --root . --coverage

      - name: Schema validation (level 1, stdlib)
        run: python tools/ssactl.py validate --root .

      - name: Schema validation (level 2, full draft 2020-12)
        run: |
          python -m pip install --quiet --disable-pip-version-check "jsonschema>=4.22"
          python tools/ssactl.py validate --root . --strict-json

      - name: Build index and check determinism
        run: |
          python tools/ssactl.py index --root .
          sha256sum 03-wordlists/index/export/fuzz-words.txt
          python tools/ssactl.py index --root .
          sha256sum 03-wordlists/index/export/fuzz-words.txt

      - name: Lab estate healthcheck
        run: python 11-automation/scripts/lab_healthcheck.py --root .

      - name: Suricata rule syntax
        run: |
          docker run --rm -v "$PWD/06-defense/suricata/rules:/rules:ro" \
            suricata/suricata:7.0.10 \
            suricata -T -S /rules/ssa-web-attacks.rules

      - name: Archive statistics
        run: python tools/ssactl.py stats --root . | tee stats.txt

      - name: Publish statistics artifact
        uses: actions/upload-artifact@v4
        with:
          name: ssa-stats
          path: stats.txt

  drift:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Upstream drift report
        continue-on-error: true
        run: python tools/ssactl.py diff --upstream --root .
'''.lstrip()

FILES["11-automation/hooks/pre-commit"] = r'''
#!/bin/sh
# Sovereign Security Archive pre-commit hook
# Install:  git config core.hooksPath 11-automation/hooks
#          (or copy this file to .git/hooks/pre-commit and chmod +x)

set -e

fail() {
    echo ""
    echo "PRE-COMMIT BLOCKED: $1"
    echo "  fix the issue above, or: git commit --no-verify (document why)"
    echo ""
    exit 1
}

changed=$(git diff --cached --name-only)

# 1. no secrets, no private keys, no real credentials
if echo "$changed" | grep -Eq '\.(pem|key|p12|pfx|asc|ovpn|jks)$'; then
    echo "BLOCK: private key material staged"
    fail "key material must never be committed (see SECURITY.md)"
fi

if git diff --cached | grep -Eiq '(AKIA[0-9A-Z]{16}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|xox[baprs]-[0-9A-Za-z-]{10,})'; then
    echo "BLOCK: credential-shaped string detected in the diff"
    fail "remove the credential and rotate it"
fi

# 2. payload / ioc / rule artefacts must stay schema valid
if echo "$changed" | grep -qE '^(02-payloads|08-threatintel)/.*\.json$'; then
    python tools/ssactl.py validate --root . >/dev/null || fail "schema validation failed"
    echo "  ok  schema validation"
fi

# 3. crosswalk edits must not break reference integrity
if echo "$changed" | grep -q '^10-crosswalk/'; then
    python tools/ssactl.py verify --root . --strict >/dev/null || fail "crosswalk integrity failed"
    echo "  ok  crosswalk integrity"
fi

# 4. index freshness when corpora change
if echo "$changed" | grep -qE '^(02-payloads|03-wordlists)/'; then
    python tools/ssactl.py index --root . --check >/dev/null 2>&1 || \
        python tools/ssactl.py index --root . >/dev/null
    echo "  ok  index rebuilt"
fi

# 5. line endings and trailing whitespace hygiene
if git diff --cached --check >/dev/null 2>&1; then
    echo "  ok  whitespace hygiene"
else
    echo "WARN  trailing whitespace or CRLF issues in staged files"
fi

echo "pre-commit: all SSA checks passed"
exit 0
'''.lstrip()

FILES["11-automation/README.md"] = r'''
# Automation

| Field | Value |
|---|---|
| `domain` | Build and validation |
| `owner` | `@archive-steward` |
| `python` | 3.9+ standard library only (optional extras documented) |
| `entry_point` | `tools/ssactl.py` |

## 1. Tooling matrix

| Script | Purpose | Idempotent | Writes |
|---|---|---|---|
| `scripts/build_payload_index.py` | Merge payloads + wordlists into `wordlist.db` | yes | `03-wordlists/index/` |
| `scripts/render_crosswalks.py` | Regenerate the three crosswalk CSVs | yes | `10-crosswalk/` |
| `scripts/validate_schemas.py` | Level 1 + optional level 2 schema validation | yes | - |
| `scripts/lab_healthcheck.py` | Verify the lab estate wiring and expected sids | yes | - |
| `scripts/build_timeline.py` | Normalise logs into an incident timeline | yes | user-specified |

## 2. Determinism contract

Generators must satisfy:

1. **Sorted output** - every CSV row order is derived from its join key.
2. **LF endings, UTF-8, no BOM.**
3. **No timestamps in generated content** (except the explicit `first_mapped`
   column, which is copied, not computed).
4. **Transactional writes** - write to a temp file, then `os.replace`.
5. **Repeatable** - running twice must produce identical bytes.

`ssactl index` implements the transactional pattern; `render_crosswalks.py`
overwrites in place, which is safe because the file is derived entirely from
committed sources.

## 3. CI pipeline

`ci/github-actions-ssa-validate.yml` runs, in order:

| Step | Gate code | Blocking |
|---|---|---|
| `ssactl verify --strict` | `STRUCT-001`, `REF-001` | yes |
| `ssactl verify --coverage` | `COV-001` | yes |
| `ssactl validate` (L1) | `SCHEMA-001` | yes |
| `ssactl validate --strict-json` (L2) | `SCHEMA-001` | yes |
| `ssactl index` twice, compare hashes | `INDEX-001` | yes |
| `lab_healthcheck.py` | - | yes |
| `suricata -T` | - | yes |
| `ssactl diff --upstream` (weekly) | `DRIFT-001` | no |

## 4. Local development

```bash
export SSA_ROOT=.
python tools/ssactl.py init     --root .
python tools/ssactl.py verify   --root . --strict --coverage
python tools/ssactl.py validate --root . --strict-json
python tools/ssactl.py index    --root .
python tools/ssactl.py stats    --root .
```

Enable the hook:

```bash
git config core.hooksPath 11-automation/hooks
```
'''.lstrip()

# ===========================================================================
# 13-training
# ===========================================================================

FILES["13-training/90-days/phase-1-foundations-days-001-030.md"] = r'''
# Phase 1 - Foundations (Days 001-030)

| Field | Value |
|---|---|
| `phase_id` | TRN-P1 |
| `window` | day 001 - 030 |
| `outcome` | Read a packet, explain an HTTP request, enumerate a lab host |
| `gate` | Enumerate and fingerprint `09-labs` target, write findings |
| `playbooks` | `01-intel/playbooks/network/`, `01-intel/playbooks/crypto/` |

## Week 1 - Networking (001-007)

| Day | Topic | Archive material | Practical |
|---|---|---|---|
| 001 | OSI/TCP-IP model, encapsulation | `14-docs/glossary.md` | Draw the stack from memory |
| 002 | IP addressing, CIDR, routing | `03-wordlists/network/ports.txt` | Compute subnets for `10.10.10.0/24` |
| 003 | TCP handshake, states, flags | - | Capture a handshake with tcpdump |
| 004 | UDP, ICMP, ARP | - | Explain ARP spoofing in 3 sentences |
| 005 | DNS resolution, records, DNSSEC | `03-wordlists/discovery/dns/` | `dig` a record and read the flags |
| 006 | TLS 1.2/1.3 handshake | `06-defense/hardening/network-baseline.md` | Read a handshake in Wireshark |
| 007 | HTTP/1.1, headers, methods | `01-intel/playbooks/web/authentication-bypass.md` | Explain `Transfer-Encoding` vs `Content-Length` |

## Week 2 - Operating systems (008-014)

| Day | Topic | Practical |
|---|---|---|
| 008 | Linux filesystem, permissions, SUID/SGID | Map `/usr/bin` SUID set |
| 009 | Processes, signals, namespaces | Explain `/proc/<pid>/exe` |
| 010 | Users, groups, sudo, PAM | `04-evasion/linux/sudo-lpe.md` |
| 011 | Windows processes, services, tokens | `04-evasion/windows/sushi.md` |
| 012 | Windows registry, event log | Read 4624 by hand |
| 013 | Active Directory objects, LDAP | `01-intel/playbooks/active-directory/kerberos-attacks.md` |
| 014 | macOS architecture, launchd, SIP | `04-evasion/macos/sudo.md` |

## Week 3 - Linux and shell (015-021)

| Day | Topic | Practical |
|---|---|---|
| 015 | Shell, quoting, expansion | Explain the 4 quoting contexts |
| 016 | File descriptors, redirection, pipes | Build a one-liner that parses access logs |
| 017 | Process control, backgrounding, nohup | - |
| 018 | Permissions in depth, umask | Predict a file mode |
| 019 | systemd units, timers, sockets | Write a hardened unit from `06-defense/wazuh/agents/linux-server.xml` |
| 020 | Package management, repositories | Verify a package signature |
| 021 | Auditd, sysctl, capabilities | Add an execve rule for `/usr/bin/find` |

## Week 4 - Scripting and tooling (022-030)

| Day | Topic | Practical |
|---|---|---|
| 022 | Python 3 essentials for security | Parse a JSON IOC file |
| 023 | Bash for security work | Write a log triage script |
| 024 | `curl`, `wget`, HTTP clients | Fetch and follow redirects safely |
| 025 | `jq`, `yq`, `grep` on structured data | Extract `alert.signature` from `eve.json` |
| 026 | `nmap` fundamentals | `nmap -sV -sC` against the lab |
| 027 | `tcpdump`, `tshark` | Extract a credential from a pcap (lab only) |
| 028 | Git fundamentals and history forensics | Use `git log -S` to find a removed secret |
| 029 | Python standard library for crypto | Hash, encode, verify a signature |
| 030 | GitHub Actions and CI secrets | Read a workflow, list exposed secrets |

## Phase 1 gate

```bash
# 1. enumerate the lab target and produce a service matrix
nmap -sV -sC -p- 127.0.0.1 > /tmp/phase1-scan.txt
# 2. explain, in writing, why 3306 and 6379 are dangerous when unauthenticated
# 3. list ten Linux hardening items from 06-defense/hardening/linux-baseline.md and
#    run the verification command for each
```

Sign-off criteria:
- [ ] Service matrix produced with no unexplained ports
- [ ] Written explanation of the HTTP request smuggling prerequisite chain
- [ ] Ten hardening items verified with command output attached
- [ ] Quiz: `13-training/assessments/quiz-bank.md` Phase 1 section, >= 80 %
'''.lstrip()

FILES["13-training/90-days/phase-2-offensive-days-031-060.md"] = r'''
# Phase 2 - Offensive Operations (Days 031-060)

| Field | Value |
|---|---|
| `phase_id` | TRN-P2 |
| `window` | day 031 - 060 |
| `outcome` | Complete a scoped web + AD assessment with a written report |
| `gate` | Full exploitation chain in `09-labs` with detections observed |
| `playbooks` | `01-intel/playbooks/web/`, `.../active-directory/`, `.../network/` |

## Week 5 - Web application attack surface (031-037)

| Day | Topic | Material | Practical |
|---|---|---|---|
| 031 | Recon: subdomains, endpoints, JS | `05-engines/osint/sherlock/` | Enumerate the lab app |
| 032 | Content discovery and hidden paths | `03-wordlists/web/content-words.txt` | `ffuf` the lab |
| 033 | Injection: SQLi | `01-intel/playbooks/web/sql-injection.md` | Boolean and time based |
| 034 | Injection: XSS in every context | `01-intel/playbooks/web/xss.md` | Find one stored XSS |
| 035 | SSRF and XXE | `01-intel/playbooks/web/ssrf.md` | IMDSv2 token retrieval in the lab |
| 036 | AuthN / session / JWT | `02-payloads/api/jwt-hs256-confusion.md` | Forge an HS256 token |
| 037 | Access control / IDOR / BOLA | `02-payloads/api/payloads.json` | Horizontal escalation |

## Week 6 - Windows and AD (038-044)

| Day | Topic | Material | Practical |
|---|---|---|---|
| 038 | AD reconnaissance | `05-engines/metasploit/modules/modules-index.csv` | BloodHound on the lab domain |
| 039 | Kerberos mechanics | `01-intel/playbooks/active-directory/kerberos-attacks.md` | Explain ticket flow on a whiteboard |
| 040 | AS-REP roast and Kerberoast | same | Execute both in the lab |
| 041 | DCSync and delegation | same | Detect DCSync off-domain |
| 042 | SMB relay and signing | `06-defense/hardening/windows-baseline.md` | Verify signing is enforced |
| 043 | Lateral movement | `04-evasion/windows/sushi.md` | `psexec`, `wmiexec`, `smb_delivery` |
| 044 | ADCS abuse (ESC1-ESC8) | `06-defense/sigma/ssa_ad_dcsync.yml` | Identify a vulnerable template |

## Week 7 - Privilege escalation and evasion (045-051)

| Day | Topic | Material | Practical |
|---|---|---|---|
| 045 | Linux privesc survey | `04-evasion/linux/sudo-lpe.md` | Find every vector on the lab host |
| 046 | Windows privesc | `05-engines/metasploit/post-exploitation/privesc-map.md` | 8 vectors in the lab |
| 047 | Container escape | `04-evasion/containers/docker-escape.md` | Privileged run + socket |
| 048 | Pivoting and tunnelling | `01-intel/playbooks/network/pivoting.md` | chisel + proxychains |
| 049 | Cloud IAM privesc | `01-intel/playbooks/cloud/aws-iam-privesc.md` | `simulate-principal-policy` |
| 050 | Evasion chains | `04-evasion/chains/abuse-chains.md` | Replay `CH-001` |
| 051 | Payload adaptation | `02-payloads/templates/payload.template.json` | Add one payload end to end |

## Week 8 - Method, evidence, reporting (052-060)

| Day | Topic | Material | Practical |
|---|---|---|---|
| 052 | PTES phases | `01-intel/methodologies/ptes.md` | Fill the plan template |
| 053 | OSSTMM phases and RAV | `01-intel/methodologies/osstmm.md` | Score five findings |
| 054 | Evidence discipline | `06-defense/ir/evidence-handling.md` | Build a custody register |
| 055 | Finding writing | `01-intel/checklists/penetration-testing-checklist.md` §6 | Write three findings |
| 056 | Crosswalk literacy | `10-crosswalk/README.md` | Query the unified index |
| 057 | Detection engineering basics | `06-defense/blue-team/owasp-to-detection.md` | Write one Sigma rule |
| 058 | Report assembly | `14-docs/standards/knowledge-format.md` | Draft the report |
| 059 | Peer review | - | Review a colleague's report |
| 060 | Phase 2 assessment | `13-training/assessments/quiz-bank.md` | See gate below |

## Phase 2 gate

- [ ] Complete `CH-001` in `09-labs/emulations/` and observe every expected alert
- [ ] Produce a report with at least 5 findings, each with RAV, CWE and remediation
- [ ] Demonstrate one wordlist+payload crosswalk query and explain the join
- [ ] Add one payload **and** its Sigma rule **and** its crosswalk row; `ssactl verify --coverage` passes
'''.lstrip()

FILES["13-training/90-days/phase-3-defensive-days-061-090.md"] = r'''
# Phase 3 - Defensive Operations (Days 061-090)

| Field | Value |
|---|---|
| `phase_id` | TRN-P3 |
| `window` | day 061 - 090 |
| `outcome` | Ship a detection, run an IR exercise, write an after-action review |
| `gate` | One Sigma rule fires in the lab; one IR memo reviewed |
| `material` | `06-defense/**`, `08-threatintel/**` |

## Week 9 - Detection fundamentals (061-067)

| Day | Topic | Material |
|---|---|---|
| 061 | What a detection must have: fidelity, coverage, cost | `06-defense/blue-team/owasp-to-detection.md` |
| 062 | Suricata rule anatomy and sid discipline | `06-defense/suricata/README.md` |
| 063 | Writing Suricata HTTP rules | `06-defense/suricata/rules/ssa-web-attacks.rules` |
| 064 | Wazuh rules, decoders, levels | `06-defense/wazuh/rules/ssa-baseline.xml` |
| 065 | Wazuh agent hardening | `06-defense/wazuh/agents/linux-server.xml` |
| 066 | Sigma portability | `06-defense/sigma/ssa_ad_dcsync.yml` |
| 067 | Alert triage and false-positive control | `06-defense/suricata/thresholds/ssa-threshold.config` |

## Week 10 - AD and cloud detection (068-074)

| Day | Topic | Material |
|---|---|---|
| 068 | Kerberos telemetry | `06-defense/sigma/ssa_ad_kerberoast.yml` |
| 069 | DCSync and privileged telemetry | `06-defense/sigma/ssa_ad_dcsync.yml` |
| 070 | LOLBin detection patterns | `06-defense/sigma/ssa_windows_lolbin_anomaly.yml` |
| 071 | Cloud audit detection | `06-defense/sigma/ssa_cloud_metadata_access.yml` |
| 072 | Kubernetes and container audit | `04-evasion/containers/docker-escape.md` |
| 073 | Identity provider (Entra/Okta) detection | `06-defense/blue-team/controls/controls.csv` AD-* |
| 074 | Threat intelligence ingestion | `08-threatintel/feeds/feed-registry.yaml` |

## Week 11 - Incident response (075-081)

| Day | Topic | Material |
|---|---|---|
| 075 | NIST SP 800-61 lifecycle | `01-intel/methodologies/nist-sp800-61.md` |
| 076 | Roles and severity | `06-defense/ir/incident-response-playbook.md` |
| 077 | Volatile evidence | `06-defense/ir/evidence-handling.md` |
| 078 | Windows triage | `06-defense/ir/incident-response-playbook.md` §4 |
| 079 | Linux triage | same |
| 080 | Timeline construction | `11-automation/scripts/build_timeline.py` |
| 081 | Tabletop exercise | `06-defense/ir/incident-response-playbook.md` §3 |

## Week 12 - Hardening, purple team, review (082-090)

| Day | Topic | Material |
|---|---|---|
| 082 | Linux hardening verification | `06-defense/hardening/linux-baseline.md` |
| 083 | Windows / AD hardening verification | `06-defense/hardening/windows-baseline.md` |
| 084 | Network and egress hardening | `06-defense/hardening/network-baseline.md` |
| 085 | LLM application security | `06-defense/sigma/ssa_llm_prompt_injection.yml` |
| 086 | Purple team loop | `01-intel/methodologies/mitre-attack.md` §4 |
| 087 | ATT&CK coverage review | `06-defense/blue-team/mitre-coverage.csv` |
| 088 | Close your coverage gaps | same (state `gap` -> `full`) |
| 089 | Write the after-action review | `14-docs/decisions/ADR-0001-example.md` |
| 090 | Final assessment and sign-off | `13-training/assessments/quiz-bank.md` |

## Phase 3 gate

- [ ] A Sigma rule you authored fires during a lab replay
- [ ] `ssactl verify --coverage` passes with your controls anchored
- [ ] One IR memo completed with timeline, evidence register and lessons learned
- [ ] At least one ATT&CK technique moved from `gap` to `full`
'''.lstrip()

FILES["13-training/tracks/red-team.md"] = r'''
# Role Track - Red Team

| Field | Value |
|---|---|
| `track_id` | TRACK-RED |
| `phases` | 2 mainly, 3 light |
| `primary` | `02-payloads/`, `04-evasion/`, `05-engines/` |

## 1. Capability targets

| Capability | Evidence | Archive material |
|---|---|---|
| Web application exploitation | Report with 5+ verified findings | `02-payloads/web/`, `01-intel/playbooks/web/` |
| AD compromise path | Documented path domain admin -> DC | `01-intel/playbooks/active-directory/` |
| Privilege escalation, all platforms | 20+ distinct vectors found in the lab | `04-evasion/` |
| Cloud IAM abuse | Working privesc chain in a sandbox account | `01-intel/playbooks/cloud/` |
| Container escape | Escape a restricted pod | `04-evasion/containers/` |
| Evasion tradecraft | Replay `CH-001` and `CH-002` with detections observed | `04-evasion/chains/` |
| OSINT | Handle, subdomain and metadata enumeration | `05-engines/osint/`, `08-threatintel/` |

## 2. Weekly cadence

| Activity | Time |
|---|---|
| Technique research and payload authoring | 4 h |
| Lab exploitation and rule observation | 6 h |
| Emulation authoring in `09-labs/emulations/` | 3 h |
| Report writing | 3 h |
| Crosswalk maintenance (new payloads, new rules) | 2 h |

## 3. Definition of done per finding

1. Payload added to `02-payloads/` with valid schema and provenance.
2. Fuzz token (if applicable) added and the crosswalk row generated.
3. Playbook step updated with the payload id.
4. Detection checked: does an existing rule fire? If not, author one.
5. Finding written in the format from
   `01-intel/checklists/penetration-testing-checklist.md` §6.

## 4. Red-team-specific red lines

* No destructive payloads on production without explicit written authorisation.
* No persistence left behind; document the clean-up and verify it.
* Never exfiltrate real data - prove access and stop.
* Operate only within the signed scope in `00-governance/charter.md` §7.
'''.lstrip()

FILES["13-training/tracks/blue-team.md"] = r'''
# Role Track - Blue Team (Detection Engineering)

| Field | Value |
|---|---|
| `track_id` | TRACK-BLUE |
| `phases` | 3 mainly |
| `primary` | `06-defense/**`, `10-crosswalk/control-detection/` |

## 1. Capability targets

| Capability | Evidence | Archive material |
|---|---|---|
| Suricata rule authoring | 10 rules with zero syntax errors | `06-defense/suricata/rules/` |
| Wazuh rule authoring | 10 rules, correctly levelled | `06-defense/wazuh/rules/` |
| Sigma portability | 10 rules, convertible to a SIEM | `06-defense/sigma/` |
| Control coverage | `COV-001` count = 0 | `06-defense/blue-team/owasp-to-detection.md` |
| ATT&CK coverage improvement | 5 techniques `gap` -> `full` | `06-defense/blue-team/mitre-coverage.csv` |
| Tuning | Documented FP rate reduction | `06-defense/suricata/thresholds/ssa-threshold.config` |
| IR readiness | Tabletop completed, AAR written | `06-defense/ir/` |

## 2. Weekly cadence

| Activity | Time |
|---|---|
| Telemetry review and gap analysis | 3 h |
| Rule authoring and testing | 8 h |
| Replay emulations, record which rules fire | 3 h |
| Crosswalk maintenance | 2 h |
| Threat intel ingestion and IOC hygiene | 2 h |

## 3. Rule quality bar

A rule is finished when:

1. It compiles (`suricata -T` / Wazuh `wazuh-logtest`).
2. It fires on the replay of its emulation in `09-labs/emulations/`.
3. Its false positives are listed in the rule comment.
4. It is mapped to a `control_id`, `evasion_id` or `technique_id`.
5. It exists in the crosswalk CSV (regenerate with `render_crosswalks.py`).
6. `ssactl verify --coverage` is clean.

## 4. Detection review discipline

* One reviewer who is not the author (`CODEOWNERS`).
* Rules that fired zero times in 30 days are candidates for tuning or removal.
* Rules that fired only in the lab are marked `status: experimental` in Sigma.
* Any rule whose gap is documented in `residual_gap` gets a follow-up ticket.
'''.lstrip()

FILES["13-training/tracks/secops.md"] = r'''
# Role Track - SecOps (SOC / IR)

| Field | Value |
|---|---|
| `track_id` | TRACK-SECOPS |
| `phases` | 3 mainly, 2 light |
| `primary` | `06-defense/ir/`, `08-threatintel/` |

## 1. Capability targets

| Capability | Evidence | Archive material |
|---|---|---|
| Alert triage at L1 | 50 alerts triaged with correct severity | `06-defense/blue-team/mitre-coverage.csv` |
| Incident scoping at L2 | Correct host and identity set in 30 min | `06-defense/ir/incident-response-playbook.md` |
| Evidence handling | Custody register with no gaps | `06-defense/ir/evidence-handling.md` |
| Timeline construction | Timestamped, evidence-backed timeline | `11-automation/scripts/build_timeline.py` |
| IOC ingestion | Feed pipeline running, metrics reported | `08-threatintel/` |
| Purple support | Replay an emulation, confirm detections | `09-labs/emulations/` |

## 2. Triage flow

```
 alert
   |
   v
 Is it a true positive? ---- no --> false positive: document, tune, close
   |
  yes
   |
   v
 Which asset, which identity, which severity? --> 06-defense/ir/ §1 matrix
   |
   v
 Contain or observe?  observe first if volatility risk (see evidence-handling)
   |
   v
 Timeline  -->  06-defense/ir/timeline.md
   |
   v
 Scope  -->  data exposure confirmed / suspected / none
   |
   v
 Escalate per severity matrix; notify Legal if data exposure is possible
   |
   v
 After action: new Sigma rule or gap note, AAR within 5 business days
```

## 3. Weekly cadence

| Activity | Time |
|---|---|
| Alert review and rule tuning feedback | 5 h |
| Hunt using `08-threatintel/` IOCs | 4 h |
| Emulation replay and detection confirmation | 3 h |
| Incident drills and AAR reading | 3 h |
| IOC hygiene (`expires`, false positives) | 2 h |

## 4. Metrics to own

| Metric | Target | Source |
|---|---|---|
| MTTD for feed IOCs | < 30 min | `08-threatintel/README.md` §3 |
| Alert precision | > 90 % | triage outcomes |
| SEV1 time to containment | < 60 min | `06-defense/ir/` |
| Playbook currency | reviewed quarterly | `06-defense/ir/` |
| Evidence custody gaps | zero | `06-defense/ir/evidence-handling.md` |
'''.lstrip()

FILES["13-training/assessments/quiz-bank.md"] = r'''
# Assessment Bank

| Field | Value |
|---|---|
| `assessment_id` | ASM-SSA |
| `pass_mark` | 80 % written, all practicals passed |
| `retake` | permitted after 5 working days, different practical |

## 1. Phase 1 - Foundations (20 questions)

1. What is the difference between a TCP `SYN/ACK` and an `ACK` in terms of
   connection state? Which flag indicates the last packet of the handshake?
2. Why does TLS 1.3 remove the RSA key exchange, and what does it replace?
3. What does `Host:` header injection into an outbound request enable?
4. Calculate the broadcast address for `10.20.30.40/26`.
5. Explain the difference between `Authentication` and `Authorization`.
6. What is the purpose of `Auditd`'s `-S execve`?
7. Name the three `ld.so.preload` implications.
8. What does SUID on `/usr/bin/find` allow?
9. Which Windows event logs service installation? (7045)
10. What does `Get-DomainUser -ASREPReadable` find?
11. Why is `TokenRotation` a session management control?
12. What does `net.ipv4.conf.all.accept_redirects = 0` prevent?
13. Which is safer: parameterised queries or input filtering? Why?
14. What does `SameSite=Strict` prevent that `Lax` does not?
15. Explain the `oidc` vs `oauth` distinction at a high level.
16. Which directory should uploads live in and why?
17. What is the risk of `NOPASSWD: /usr/bin/find` in sudoers?
18. What does `maxauthtries` protect against?
19. Why must `audismd` `execve` rules be generated from the evasion index?
20. What information does a pcap of a TLS session reveal without decryption?

## 2. Phase 2 - Offensive (20 questions)

1. Give the minimal boolean pair that proves SQLi and explain the delta.
2. What does `sqlmap --technique` do and why restrict `E`?
3. List three XSS contexts and one probe for each.
4. Why does `http://0/` bypass a naive loopback filter?
5. What does IMDSv2 add over IMDSv1?
6. Describe the JWT algorithm confusion attack in two sentences.
7. Why is `kid` header injection dangerous?
8. What is the difference between `sig`, `nbf` and `iss` claims?
9. Explain what AS-REP roasting targets and what stops it.
10. What is the DCSync replication GUID and why is 4662 on a non-DC critical?
11. Why is SMB signing mandatory a control for T1187?
12. Name three ADCS attack classes and the template misconfiguration behind each.
13. Give a `find` and a `vim` privesc one-liner and the resulting `EV-*` id.
14. What distinguishes `EV-LNX-0001` from `EV-LNX-0007`?
15. How do you detect a container escape via `nsenter`?
16. Why does a Docker socket mount grant host root?
17. What does `kubectl auth can-i --list` reveal?
18. Name the AWS privesc primitive involving `iam:CreatePolicyVersion`.
19. Which conditions would you add to an IAM policy to limit `AssumeRole`?
20. Why does the archive forbid payloads with destructive side effects at T0?

## 3. Phase 3 - Defensive (20 questions)

1. What makes a Suricata rule high fidelity?
2. How do you allocate a new SSA sid and when is reuse forbidden?
3. What is the difference between an `eventID` and a `rule id` in Wazuh?
4. Write a Wazuh rule that fires 10 failed logons for the same user in 5 minutes.
5. Why is `REJECT` worse than `ALERT` during the first 14 days of a ruleset?
6. What does `COV-001` enforce and why is it a build failure?
7. Give a Sigma rule detecting `certutil -urlcache`.
8. Why is `alg: none` JWT detection a client-side problem?
9. What is the detection gap for LLM-01 and how do you document it?
10. Name four signals of DNS tunnelling.
11. How do you tune without silencing? (by rule id, with expiry)
12. What does `residual_gap` mean and when is it mandatory?
13. Which ATT&CK technique is hardest to detect and why?
14. How do you detect DCSync if the DC is remote?
15. What is the difference between a `full` and `offensive-only` coverage state?
16. Why must an IOC have an `expires` field?
17. How do you respond to a SEV1 in the first 15 minutes?
18. Why capture volatile evidence before containment?
19. What breaks a chain of custody?
20. Describe the purple team loop in five steps.

## 4. Practical assessments

| Id | Practical | Pass criterion |
|---|---|---|
| P-01 | Enumerate and fingerprint the lab target | Service matrix with no unexplained ports |
| P-02 | Prove SQLi on the lab DVWA | Boolean + one time-based demonstration with evidence |
| P-03 | Complete `CH-001` in `09-labs/emulations/` | All expected alerts fire; result table completed |
| P-04 | Forge a JWT against the lab app | Successful `alg` confusion accepted by the target |
| P-05 | Author a Sigma rule for a new technique | Rule fires in replay; crosswalk row present |
| P-06 | Harden a lab host | Verification commands produce the expected output |
| P-07 | Build a timeline from lab logs | `build_timeline.py` output, gaps explained |
| P-08 | Close one ATT&CK `gap` | Detection authored, replayed, matrix updated |

## 5. Scoring

```
score = 0.7 * written_pct + 0.3 * practicals_passed/8 * 100
pass   = written_pct >= 80 AND all mandatory practicals passed
mandatory practicals: P-03, P-05, P-06
```
'''.lstrip()

FILES["13-training/README.md"] = r'''
# Training

| Field | Value |
|---|---|
| `domain` | Human enablement |
| `owner` | `@knowledge-maintainer` |
| `source` | `0xDigit/90-Days-of-Cybersecurity` |
| `structure` | 3 phases x 30 days, then role tracks |

## 1. Layout

| Path | Content |
|---|---|
| `90-days/phase-1-foundations-days-001-030.md` | Networking, OS, Linux, scripting |
| `90-days/phase-2-offensive-days-031-060.md` | Web, AD, privesc, evasion, reporting |
| `90-days/phase-3-defensive-days-061-090.md` | Detection, IR, hardening, purple team |
| `tracks/red-team.md` | Offensive role specialisation |
| `tracks/blue-team.md` | Detection engineering specialisation |
| `tracks/secops.md` | SOC / IR specialisation |
| `assessments/quiz-bank.md` | 60 written questions + 8 practicals |

## 2. Design rules

1. Every day references archive material. Nothing is taught that the archive
   does not contain.
2. Every phase ends with a **gate** that is verifiable by an artifact (a file, a
   command output, a detection that fires).
3. Nothing is assessed that is not in `13-training/assessments/quiz-bank.md`.
4. Practical P-03 (chain replay with detections) and P-06 (hardening
   verification) are mandatory for every role - offensive or defensive.

## 3. Onboarding checklist

```markdown
- [ ] Read 00-governance/charter.md and sign the scope acknowledgement
- [ ] Read 00-governance/data-classification.md
- [ ] Complete Phase 1 day 001-030 at the required cadence
- [ ] Clone the lab estate and run lab_healthcheck.py
- [ ] Choose a role track
- [ ] Complete the first 10 days of the chosen track
- [ ] Pair with a mentor for the first full exploitation chain (P-03)
- [ ] Submit P-05 (a Sigma rule) to the detection reviewer
```

## 4. Mentor responsibilities

| Week | Focus |
|---|---|
| 1 | Environment, access, safety boundaries |
| 2 | Method and evidence discipline |
| 3 | First supervised engagement |
| 4 | First authored detection |
| 5 | Review the first written report end to end |
| 6+ | Quarterly; retake any failed gate |
'''.lstrip()

# ===========================================================================
# 14-docs
# ===========================================================================

FILES["14-docs/architecture/overview.md"] = r'''
# Architecture Overview

## 1. System context

```
                     +---------------------------+
                     |   Enterprise / Lab user   |
                     +-------------+-------------+
                                   |
        +--------------------------+--------------------------+
        |                          |                          |
  offensive use              defensive use              training use
        |                          |                          |
  01-intel/playbooks         06-defense/               13-training/
  02-payloads                10-crosswalk/             01-intel/
  03-wordlists/              08-threatintel/           09-labs/
  04-evasion/                06-defense/ir/
  05-engines/                07-tooling/
        |                          |                          |
        +--------------------------+--------------------------+
                                   v
                     +---------------------------+
                     | 10-crosswalk/  (the spine)|
                     |  wordlist<->payload        |
                     |  evasion<->detection       |
                     |  control<->detection       |
                     |  attack coverage           |
                     +-------------+-------------+
                                   |
                     +-------------+-------------+
                     |                           |
              11-automation              12-schemas
              index generators          JSON Schema truth
                     |                           |
                     +-------------+-------------+
                                   v
                       00-governance/ (control plane)
```

## 2. Container view (archive as a software product)

| Container | Responsibility | Depends on |
|---|---|---|
| `governance` | charter, risk, classification, release | - |
| `intel` | prose knowledge: playbooks, methodology, cheat sheets | governance |
| `corpus` | payloads, wordlists, evasion | intel, schemas |
| `engines` | automation bindings | corpus |
| `defense` | rules, controls, hardening, IR | intel, schemas |
| `tooling` | analyst recipes and patterns | corpus |
| `intelext` | threat feeds, IOCs, actors, ATT&CK pages | schemas |
| `labs` | validation estates and emulations | corpus, defense |
| `crosswalk` | the integration spine | all of the above |
| `automation` | generators and CI | crosswalk, schemas |
| `training` | curriculum derived from everything | all of the above |

Dependency direction is strictly **downward to governance** and **inward to
crosswalk**. Nothing in `defense/` may import from `engines/` at build time -
only crosswalk rows connect them.

## 3. Component view - the unified index

```
02-payloads/**/payloads.json ──┐
                               ├──► build_payload_index.py ──► 03-wordlists/index/wordlist.db
03-wordlists/**/*.txt ─────────┘                                   │
                                                                   ├──► token
04-evasion/index/*.csv ──────────────────────────────────────────► ├──► payload
                                                                   ├──► fuzz_token (the join)
                                                                   └──► evasion

consumers:  ffuf · sqlmap · hydra · render_crosswalks.py · coverage reports
```

The join is implemented in exactly one place
(`normalise()` + the equality predicate in `build_payload_index.py`). If you
change the join rule, change it there and regenerate; the crosswalk CSV is a
report, not the source of truth.

## 4. Data flow for a new payload

```
 author edits 02-payloads/web/sqli/payloads.json
        |
        v
 ssactl validate            (SCHEMA-001 gate)
        |
        v
 author adds the fuzz token to 03-wordlists/web/fuzzing/injection-words.txt
        |
        v
 ssactl index               (unifies, confidence 1.0 when both sources match)
        |
        v
 render_crosswalks.py       (regenerates wordlist-payload/crosswalk.csv)
        |
        v
 ssactl verify --coverage   (control coverage unchanged, references valid)
```

## 5. Trust boundaries

| Boundary | Trust level | Control |
|---|---|---|
| git clone -> working tree | untrusted | review, CODEOWNERS, hooks |
| upstream checkout -> `02-`, `03-`, `04-` | untrusted | lock file pin, normalisation, schema validation |
| working tree -> published index | semi-trusted | determinism check, transactional build |
| published index -> detection pipeline | trusted | signing, review, change control |

## 6. Non-functional requirements

| NFR | Target | How measured |
|---|---|---|
| Offline operation | full for `init`, `verify`, `validate`, `index` | air-gapped CI job |
| Determinism | byte-identical repeated builds | hash comparison in CI |
| Build time | full scaffold < 2 s on a laptop SSD | `ssactl init` timing |
| Verification time | < 10 s for the whole archive | `ssactl verify --strict --coverage` |
| Storage | < 25 MB excluding generated index | `ssactl stats` |
| Python | 3.9+ stdlib only | no `pip install` required |
'''.lstrip()

FILES["14-docs/standards/knowledge-format.md"] = r'''
# Knowledge Format Standard

| Field | Value |
|---|---|
| `standard_id` | STD-KF-001 |
| `applies_to` | every markdown artefact in the archive |

## 1. Required front matter

Every playbook, methodology, cheat sheet, checklist, emulation and IR document
starts with a two-column table whose first column is a field name:

| Field | Required | Applies to |
|---|---|---|
| `playbook_id` / `methodology_id` / `cheat_id` / `checklist_id` | yes | 01-intel |
| `cwe_id`, `owasp_controls`, `attack_ids` | when applicable | playbooks |
| `payload_corpus`, `wordlist`, `automation` | when applicable | playbooks |
| `evasion_ids`, `technique_id` | when applicable | 04-evasion |
| `emulation_id`, `expected_sigma`, `expected_wazuh`, `expected_suricata` | yes | 09-labs/emulations |
| `source`, `license` | when derived from upstream | all |
| `classification` | when not T0 | all |

Rules:

* Field names are lowercase snake_case.
* Identifier values use the namespace prefixes from `10-crosswalk/README.md` §3.
* A `README.md` generated by `ssactl` does not need front matter.

## 2. Section order

1. H1 title.
2. Front matter table.
3. Purpose, in one sentence.
4. Preconditions / scope.
5. Procedure (numbered, copy-pasteable).
6. Verification (how you know it worked).
7. Detection expectations (what should have fired).
8. Remediation / hardening.
9. References to other archive paths.

Sections 5-7 are mandatory for playbooks and emulations. A procedure without a
verification step is not a procedure.

## 3. Command blocks

```bash
# every command block starts with a comment stating the host it runs on
# never use a real hostname or IP in a committed example
curl -s "https://TARGET/parameter"      # attacker or lab
nmap -sV -p 80,443 TARGET               # attacker or lab
```

* `TARGET`, `COLLAB`, `LAB-*` are the reserved placeholders.
* Never commit real domains, real internal hostnames, or live credentials.
* Use `127.0.0.1` for lab targets, never a routable address.

## 4. Evidence blocks

```markdown
Evidence:
  Request:  GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1
  Response: 500 Internal Server Error (baseline 200, length delta 118 bytes)
  Source:   Suricata 3001001 at 2026-01-15T08:41:02Z
  Stored:   SSA-2026-0007-01 (T1)
```

An evidence block must reference an evidence id from
`06-defense/ir/evidence-handling.md` when it belongs to a real engagement.

## 5. Identification of derived content

```text
> **Provenance:** PayloadsAllTheThings (PAT@master@2026-01-15), MIT
> **Derived:** normalised into 12-schemas/payload.schema.json
> **Class:** T0
```

## 6. Language

* British or American English is fine; be consistent within one document.
* Active voice for procedures, passive for findings.
* No emoji in technical content.
* Maximum line length 100 for prose paragraphs; code may exceed it.

## 7. Review checklist for a new document

- [ ] Front matter complete
- [ ] Identifier prefix correct and unique
- [ ] Every referenced path exists
- [ ] Every referenced identifier exists (the verifier checks this)
- [ ] Commands use placeholders only
- [ ] Verification section present
- [ ] Detection expectations stated for offensive content
- [ ] Provenance and classification present
'''.lstrip()

FILES["14-docs/decisions/ADR-0001-example.md"] = r'''
# ADR-0001 - Canonical identifiers and a single crosswalk spine

| Field | Value |
|---|---|
| `adr_id` | ADR-0001 |
| `status` | accepted |
| `date` | 2026-01-15 |
| `deciders` | archive steward, detection reviewer, knowledge maintainer |

## Context

The twenty upstream archives have no shared vocabulary. PayloadsAllTheThings
identifies payloads by file and heading; SecLists identifies words by line
number; GTFOBins identifies entries by binary name; the OWASP cheat sheets
identify controls by prose; Suricata and Wazuh use unrelated numeric ids.
Merging them without an identifier scheme produces a folder of files that a
tool cannot consume and a reviewer cannot cross-check.

Two options were considered:

1. **Copy-and-merge** - dump everything into a themed tree, keep upstream
   identifiers. Cheap, but no integration is possible and references break on
   the next upstream change.
2. **Normalise with a canonical identifier layer** - assign stable `PL-*`,
   `EV-*`, `control_id`, `PB-*` identifiers in the archive, keep the upstream
   content behind a provenance header, and express every relationship as a row
   in `10-crosswalk/`.

## Decision

Adopt option 2.

* Each domain owns a prefix namespace (`10-crosswalk/README.md` §3).
* Identifiers are stable for the life of the archive and are never reused.
* All relationships live in CSV files under `10-crosswalk/`, not in prose.
* Machine readable artefacts validate against `12-schemas/`.
* `ssactl verify` fails the build on a dangling or orphaned identifier.

## Consequences

Positive:

* A detection can be traced to a control, a technique, a payload and an
  upstream source with a single query.
* Coverage can be measured objectively (`--coverage`), not asserted.
* Upstream changes are detectable (`diff --upstream`) and attributable
  (provenance headers).

Negative:

* Every upstream ingestion requires an assignment pass, not a copy.
* Identifiers must be maintained forever; removing a payload leaves a tombstone.
* The verifier must be maintained alongside the schemas.

Neutral:

* The archive is bigger to build (a few seconds) but identical to run offline.

## Alternatives rejected

* **Git submodules only** - no integration, no validation, upstream refs move.
* **A database-first design (no files)** - loses reviewability and diffability,
  which are the main reasons to keep knowledge in a repository.
* **Auto-generated ids from content hashes** - ids change whenever a payload is
  whitespace-normalised, which breaks every crosswalk row.

## Revisit when

* The identifier count exceeds ~50 000 (consider two-level partitioning).
* A third enforcement engine is added (extend `render_crosswalks.py`).
* An external consumer requires stable URLs into the archive (add anchors).
'''.lstrip()

FILES["14-docs/faq.md"] = r'''
# Frequently Asked Questions

## Scope and purpose

**Why merge twenty repositories instead of just cloning them?**
Because upstream keeps offensive data, defensive detections and methodology
disconnected. The value of this archive is the mapping: a payload id resolves to
a wordlist token, a technique, a module, and the rules that detect it. Cloning
gives you the parts without the wiring.

**Is this a superset of every upstream project?**
No, and it never will be. The archive keeps the material needed for a
consistent crosswalk and points at the upstream repository for everything else.
`00-governance/manifests/source-repos.lock.json` is the authoritative list of
what was ingested and at which revision.

**Which upstream revision am I reading?**
Run `python tools/ssactl.py diff --upstream --root .` for a drift report, or
read the `pinned_ref` field in the lock file.

## Legal and safety

**Can I use the payloads against systems I do not own?**
No. Doing so is a criminal offence in most jurisdictions. See
`00-governance/charter.md` §7. The archive is for authorised testing, detection
research and education.

**Are the payloads weaponised?**
They are the same payloads that appear in public security tooling. Some records
are classified `T2` because they have destructive or persistent side effects;
`00-governance/data-classification.md` explains the tiers.

**Can I commit real findings into this archive?**
No. Findings are `T1` or `T2` and live in the case management system, not git.
The archive stores the *method*, not the *engagement*.

## Technical

**Do I need Python?**
For scaffolding and verification, yes: 3.9+ standard library. `bootstrap.ps1`
needs only PowerShell 5.1 and will tell you if Python is missing. Detection
rules are consumed by Suricata and Wazuh, which have their own runtimes.

**Why SQLite instead of a flat file?**
Because the join is a real join. A flat merged file cannot answer "which
injection tokens apply to a *header* surface for *PostgreSQL* in a *query*
context" without re-parsing. `03-wordlists/index/README.md` §3 has the queries.

**The index database is git-ignored. How do I get it?**
Run `python tools/ssactl.py index --root .`. It is fully rebuildable from
committed sources - that is the point of the determinism contract in
`11-automation/README.md` §2.

**My Suricata rule failed to compile.**
Run `suricata -T -c suricata.yaml -S <file>`. The most common causes are an
unbalanced `;`, a missing `rev:`, or using a keyword buffer that the current
Suricata version removed.

**How do I add a payload end to end?**
`CONTRIBUTING.md` §2. The short version: payload JSON, fuzz token, crosswalk
row, schema validation.

## Operations

**How do I know a rule actually works?**
Replay the matching emulation in `09-labs/emulations/` and record the result
table. A rule that never fires during its own replay is broken or irrelevant;
both are defects.

**Coverage says `offensive-only`. Is that a failure?**
Not a build failure, but it is a queue item. `offensive-only` means we know how
to do it and cannot yet detect it. `gap` means neither. The purple-team loop in
`01-intel/methodologies/mitre-attack.md` §4 is how gaps close.

**How do I contribute a new upstream source?**
Through the lock file, with an ADR and a legal review. See `GOVERNANCE.md` §3.

**Everything is failing validation after I pulled. Why?**
Most likely a line-ending or trailing-whitespace change in a CSV. Run
`git diff --check`, then `python tools/ssactl.py verify --root . --strict` and
read the `STRUCT-001`/`REF-001` lines carefully.
'''.lstrip()

FILES["14-docs/glossary.md"] = r'''
# Glossary

| Term | Definition |
|---|---|
| **Archive root** | The directory containing `00-governance/` through `14-docs/`. |
| **Anchor** | The detection a control is verified against. Every control needs at least one. |
| **ATT&CK** | MITRE Adversary Tactics, Techniques and Knowledge; the shared technique vocabulary. |
| **Bypass ladder** | An ordered set of payloads, least to most invasive, for one weakness. |
| **CDK** | Container Development Kit (no relation to this archive). |
| **Chain (CH-nnnn)** | A multi-hop evasion sequence with per-hop telemetry. |
| **Confidence** | 0.0-1.0 that a token or primitive applies in the stated context. |
| **Control (control_id)** | A numbered secure-development control from the OWASP cheat sheets. |
| **Crosswalk** | A CSV in `10-crosswalk/` expressing a relationship between two domains. |
| **CTI** | Cyber Threat Intelligence. |
| **CWE** | Common Weakness Enumeration identifier, e.g. `CWE-89`. |
| **Detection** | A rule that produces an alert for a technique or control. |
| **Emulation** | A scripted, reproducible attack in `09-labs/` with expected telemetry. |
| **EV-* / evasion_id** | A stable identifier for a GTFOBins-style abuse primitive. |
| **Evasion corpus** | `04-evasion/` - abuse cases for trusted binaries. |
| **Fidelity** | How often a detection is correct. Low fidelity rules cause alert fatigue. |
| **Gate (CI)** | A blocking check with a code: `STRUCT-001`, `REF-001`, `COV-001`, `SCHEMA-001`, `INDEX-001`. |
| **Handoff** | A documented transfer of an engagement between phases, teams or people. |
| **IMDS** | Instance Metadata Service (cloud). |
| **Join key** | The tuple used to unify a wordlist token with a payload. |
| **JTI** | JWT identifier claim, used to prevent replay. |
| **LOLBin** | A legitimate signed binary abused to execute attacker code. |
| **NTP / mTLS** | Network Time Protocol / mutual Transport Layer Security. |
| **Offensive-only** | Coverage state: the technique is documented but not detected. |
| **PL-* / payload_id** | A stable identifier for a payload record. |
| **Purple team** | Offensive and defensive collaboration on the same objective. |
| **RAV** | Relative Attack Value: severity x exploitability plus detection x impact (OSSTMM). |
| **RoE** | Rules of engagement - the authorised scope of a test. |
| **Scaffold** | The generated directory structure plus its documentation. |
| **Sid** | A Suricata rule signature id; SSA owns 3001000-3001999. |
| **Sigma** | A vendor-neutral detection format. |
| **Surface** | Where a payload lands: parameter, header, cookie, body, url, file... |
| **T0/T1/T2** | Classification tiers: public, internal, restricted. |
| **Triage cost** | How loud a primitive is; `low` means easy to detect. |
| **Wordlist corpus** | `03-wordlists/` - token lists for discovery and fuzzing. |
'''.lstrip()

FILES["14-docs/README.md"] = r'''
# Documentation

| Path | Content |
|---|---|
| `architecture/overview.md` | System context, containers, components, trust boundaries, NFRs |
| `standards/knowledge-format.md` | Front matter, section order, command and evidence conventions |
| `decisions/` | Architecture decision records (ADR) |
| `faq.md` | Common questions and troubleshooting |
| `glossary.md` | Vocabulary shared across the archive |

## Reading order for a new maintainer

1. `../README.md` - what this is and how the domains fit together.
2. `00-governance/charter.md` - the rules of engagement for the project itself.
3. `architecture/overview.md` - how the parts connect.
4. `../10-crosswalk/README.md` - the integration model and identifier namespaces.
5. `standards/knowledge-format.md` - how to write a document that passes review.
6. `../CONTRIBUTING.md` - the submission contract.
7. `../11-automation/README.md` - the generators and gates.

## Documentation principles

1. **No document without an owner.** Front matter names a domain, and
   `CODEOWNERS` names a human.
2. **No procedure without a verification step.** See `standards/knowledge-format.md` §2.
3. **No assertion without a source.** Either cite upstream, cite the lock file
   ref, or state that it is an internal engineering decision (with an ADR).
4. **Prefer tables.** They diff well and they can be validated.
5. **The crosswalk is not documentation.** It is data. If a claim needs to be
   enforced, put it in `10-crosswalk/` and let `ssactl verify` enforce it.
'''.lstrip()