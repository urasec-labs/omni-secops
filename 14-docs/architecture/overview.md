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
