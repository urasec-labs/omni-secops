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
