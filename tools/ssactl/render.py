"""Renderer: materializes the SSA tree from spec + curated content."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from . import spec, content_root, content_intel, content_payloads
from . import content_engines, content_defense, content_tools
from . import content_crosswalk, content_platform

SOURCE_LABELS: dict[str, str] = {k: v["name"] for k, v in spec.SOURCES.items()}


def all_files() -> dict[str, str]:
    out: dict[str, str] = {}
    for module in (
        content_root, content_intel, content_payloads, content_engines,
        content_defense, content_tools, content_crosswalk, content_platform,
    ):
        out.update(module.FILES)
    return out


def _dir_readme(path: str, sources: tuple[str, ...], blurb: str, children: list[str]) -> str:
    title = path.split("/")[-1] if path else "sovereign-security-archive"
    lines = [f"# {title}", "", blurb, ""]
    if sources:
        lines.append("## Upstream sources")
        lines.append("")
        lines.append("| Source | Owner | License | Landed here as |")
        lines.append("|---|---|---|---|")
        for key in sources:
            src = spec.SOURCES[key]
            lines.append(f"| {src['name']} | {src['owner']} | {src['license']} | `{src['primary']}` |")
        lines.append("")
    if children:
        lines.append("## Contents")
        lines.append("")
        for child in sorted(children):
            short = child.split("/")[-1]
            lines.append(f"- `{short}/`")
        lines.append("")
    lines.append("## Ownership")
    lines.append("")
    lines.append("See `CODEOWNERS` at the archive root.")
    lines.append("")
    return "\n".join(lines)


def materialize(root: Path) -> dict[str, int]:
    files = all_files()
    root.mkdir(parents=True, exist_ok=True)

    # 1. directories from the spec
    for path, _sources, _blurb in spec.TREE:
        (root / path).mkdir(parents=True, exist_ok=True)

    # 2. curated files
    for rel, content in sorted(files.items()):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if content.endswith("\n") else content + "\n",
                          encoding="utf-8", newline="")

    # 3. auto READMEs for directories that don't have one yet
    children_of: dict[str, set[str]] = {}
    for path, _s, _b in spec.TREE:
        parent = str(Path(path).parent).replace("\\", "/")
        if parent in (".", ""):
            children_of.setdefault("", set()).add(path)
        else:
            children_of.setdefault(parent, set()).add(path)

    for path, sources, blurb in spec.TREE:
        readme = root / path / "README.md"
        if readme.exists():
            continue
        kids = sorted(children_of.get(path, set()))
        readme.write_text(_dir_readme(path, sources, blurb, kids),
                          encoding="utf-8", newline="")

    # top-level dirs without a spec entry still get nothing (spec covers all)

    return {"dirs": len(spec.TREE), "files": len(files) + sum(
        1 for p, _s, _b in spec.TREE if not (root / p / "README.md").exists() or True)}


def manifest(root: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and ".git" not in path.parts:
            rel = path.relative_to(root).as_posix()
            if rel.startswith("03-wordlists/index/wordlist.db"):
                continue
            entries[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return entries
