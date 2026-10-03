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
