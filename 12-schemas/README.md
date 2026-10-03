# Schema Registry

| Schema | Governs | Consumers |
|---|---|---|
| `payload.schema.json` | `02-payloads/**/payloads.json` | `ssactl index`, `validate` |
| `wordlist-entry.schema.json` | JSON wordlist feeds, index ingestion | `build_payload_index.py` |
| `evasion.schema.json` | `04-evasion/index/evasion-index.csv` | `render_crosswalks.py` |
| `detection.schema.json` | detection inventory rows | `verify --coverage` |
| `ioc.schema.json` | `08-threatintel/ioc/*.json` | SIEM ingestion |
| `crosswalk-row.schema.json` | `10-crosswalk/**.csv` | `verify` |

## Validation levels

```bash
# Level 1 - structural, no dependencies (default, always available)
python tools/ssactl.py validate --root .

# Level 2 - full JSON Schema draft 2020-12 (requires pip install jsonschema)
python tools/ssactl.py validate --root . --strict-json
```

Level 1 checks: parseable JSON, top-level `schema` or known filename, required
top-level keys, array lengths, and pattern checks on the identifier fields that
the crosswalk validator depends on. It is deliberately shallow so the archive
can be verified on an air-gapped host with only the Python standard library.

Level 2 is what CI runs on a connected runner.

## Change policy

See `10-crosswalk/api-contracts/README.md` §3. Any required-property addition is
a major version change and requires a migration note.

## Adding a schema

1. Create `12-schemas/<name>.schema.json` with `$id` and `$comment`.
2. Register the governed paths in `tools/ssactl/validate.py` (`TARGETS`).
3. Add a sample artifact that must pass.
4. Run `python tools/ssactl.py validate --root .`.
