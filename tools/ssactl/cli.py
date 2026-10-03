"""ssactl command-line interface."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

from . import spec, render, verify, VERSION, ARCHIVE_ID


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    info = render.materialize(root)
    # manifest
    manifest = render.manifest(root)
    manifests_dir = root / "00-governance" / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    (manifests_dir / "ssa-manifest.json").write_text(
        json.dumps({"archive": ARCHIVE_ID, "version": VERSION, "files": manifest},
                   indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="")
    print(f"initialized {root}")
    print(f"  directories  {info['dirs']}")
    print(f"  files        {info['files']} (curated + manifest)")
    print(f"  manifest     00-governance/manifests/ssa-manifest.json ({len(manifest)} entries)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    problems = []
    problems += verify.verify_structure(root, args.strict)
    problems += verify.verify_references(root)
    if args.coverage:
        problems += verify.verify_coverage(root)
    if problems:
        for p in problems:
            print(p)
        print(f"\n{len(problems)} problem(s)")
        return 2
    print(f"verify OK  ({root.name})")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    script = root / "11-automation" / "scripts" / "validate_schemas.py"
    if not script.is_file():
        print("ERROR validate_schemas.py missing; run `ssactl init` first", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(script), "--root", str(root)]
    if args.strict_json:
        cmd.append("--strict-json")
    return subprocess.call(cmd)


def cmd_index(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    script = root / "11-automation" / "scripts" / "build_payload_index.py"
    if not script.is_file():
        print("ERROR build_payload_index.py missing", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(script), "--root", str(root)]
    if args.stats:
        cmd.append("--stats")
    if args.check:
        cmd.append("--check")
    return subprocess.call(cmd)


def cmd_stats(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    counts: dict[str, int] = {}
    total_bytes = 0
    for path in root.rglob("*"):
        if path.is_file() and ".git" not in path.parts:
            counts[path.parent.relative_to(root).as_posix().split("/")[0]] = \
                counts.get(path.parent.relative_to(root).as_posix().split("/")[0], 0) + 1
            total_bytes += path.stat().st_size
    payloads = sum(
        len(json.loads(p.read_text(encoding="utf-8")).get("payloads", []))
        for p in (root / "02-payloads").rglob("payloads.json")
    )
    wordlists = sum(1 for p in (root / "03-wordlists").rglob("*.txt")
                    if "/index/" not in p.as_posix())
    evasions = sum(1 for _ in (root / "04-evasion/index/evasion-index.csv").open(encoding="utf-8")) - 1 \
        if (root / "04-evasion/index/evasion-index.csv").is_file() else 0
    rules = sum(1 for _ in (root / "06-defense/suricata/rules").glob("*.rules"))
    sigma = sum(1 for _ in (root / "06-defense/sigma").glob("*.yml"))
    print(f"archive: sovereign-security-archive v{VERSION}")
    print(f"  files: {sum(counts.values())}  ({total_bytes/1024:.1f} KiB)")
    print(f"  payload records : {payloads}")
    print(f"  wordlist files  : {wordlists}")
    print(f"  evasion records : {evasions}")
    print(f"  suricata files  : {rules}")
    print(f"  sigma rules     : {sigma}")
    print(f"  top-level dirs  : {len([d for d in root.iterdir() if d.is_dir()])}")
    print(f"  sources tracked : {len(spec.SOURCES)}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    lock = root / "00-governance/manifests/source-repos.lock.json"
    if not lock.is_file():
        print("ERROR lock file missing", file=sys.stderr)
        return 2
    data = json.loads(lock.read_text(encoding="utf-8"))
    if not args.online:
        print("offline mode: cannot reach upstream. showing pinned refs:")
        for s in data["sources"]:
            print(f"  {s['key']:10} {s['pinned_ref']}")
        print("\nDRIFT-UNKNOWN (rerun with network access to confirm)")
        return 0
    # best-effort online check via git ls-remote
    for s in data["sources"]:
        try:
            out = subprocess.run(
                ["git", "ls-remote", "--heads", s["url"], "master", "main"],
                capture_output=True, text=True, timeout=15)
            head = out.stdout.strip().splitlines()[0][:7] if out.stdout.strip() else "?"
            print(f"  {s['key']:10} pinned {s['pinned_ref']:24} upstream {head}")
        except Exception:
            print(f"  {s['key']:10} DRIFT-UNKNOWN")
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    targets = [
        root / "03-wordlists/index/wordlist.db",
        root / "03-wordlists/index/wordlist.db-journal",
        root / "03-wordlists/index/wordlist.db-wal",
        root / "03-wordlists/index/wordlist.db-shm",
        root / "00-governance/manifests/ssa-manifest.json",
    ]
    removed = 0
    for t in targets:
        if t.exists():
            t.unlink()
            removed += 1
    for cache in root.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)
        removed += 1
    print(f"cleaned {removed} generated artefact(s)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ssactl", description="Sovereign Security Archive control plane")
    p.add_argument("--version", action="version", version=f"ssactl {VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, fn, **kw):
        sp = sub.add_parser(name, **kw)
        sp.add_argument("--root", default=".")
        sp.set_defaults(fn=fn)
        return sp

    i = add("init", cmd_init, help="materialize the full archive tree")
    v = add("verify", cmd_verify, help="structure + references + coverage")
    v.add_argument("--strict", action="store_true")
    v.add_argument("--coverage", action="store_true")
    val = add("validate", cmd_validate, help="JSON Schema validation")
    val.add_argument("--strict-json", action="store_true")
    idx = add("index", cmd_index, help="build the unified index")
    idx.add_argument("--stats", action="store_true")
    idx.add_argument("--check", action="store_true")
    add("stats", cmd_stats, help="archive statistics")
    d = add("diff", cmd_diff, help="upstream drift report")
    d.add_argument("--upstream", action="store_true")
    d.add_argument("--online", action="store_true")
    add("clean", cmd_clean, help="remove generated artifacts")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "diff":
        args.online = args.online or args.upstream
    return int(args.fn(args))
