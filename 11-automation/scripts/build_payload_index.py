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
