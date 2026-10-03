# Release Process

## 1. Cadence

| Channel | Frequency | Contents |
|---|---|---|
| `main` | continuous | accepted changes |
| `release/x.y` | 4 weeks | stabilisation branch |
| Release | monthly (tag `vX.Y.Z`) | data + rule refresh |
| Emergency | as needed | `vX.Y.Z-hotfix` for detection-critical fixes |

## 2. Checklist (must all pass)

```bash
python tools/ssactl.py verify  --root . --strict
python tools/ssactl.py validate --root .
python tools/ssactl.py index   --root .
python tools/ssactl.py stats   --root .
python tools/ssactl.py diff --upstream --root .
```

Gate matrix:

| Gate | Blocking | Failure code |
|---|---|---|
| Structure | yes | `STRUCT-001` |
| Dangling reference | yes | `REF-001` |
| Schema | yes | `SCHEMA-001` |
| Control coverage | yes | `COV-001` |
| Index determinism | yes | `INDEX-001` |
| Upstream drift | no (warn) | `DRIFT-001` |
| Corpus growth > 20 % | review | `SIZE-001` |

## 3. Version bump rules

* Data-only change → patch.
* New schema field (optional) → minor.
* New required schema field / renamed taxonomy → major + migration map.
* Detection rule change that alters severity → minor, needs detection reviewer.

## 4. Rollback

Reverting is a normal release: tag the previous good commit, re-run gates,
publish `vX.Y.(Z-1)-rollback` and post the reason in `CHANGELOG.md`.
