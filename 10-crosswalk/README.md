# Integration Crosswalk

This directory is the reason the Sovereign Security Archive is an archive and
not a folder of downloaded repositories. Every mapping between the twenty
upstream domains is expressed here as data, validated by `ssactl verify`, and
consumed by the generators in `11-automation/scripts/`.

## 1. The four maps

| Map | File | Joins | Cardinality |
|---|---|---|---|
| Wordlist to payload | `wordlist-payload/crosswalk.csv` | SecLists token x PAT payload | many-to-many via `(sha256, surface, cwe, context)` |
| Evasion to detection | `evasion-detection/evasion-to-detection.csv` | GTFOBins primitive x Sigma/Wazuh/Suricata | one-to-many (sigma, host, network) |
| Control to detection | `control-detection/control-detection.csv` | OWASP control x defensive anchor | one-to-many, **minimum one** |
| Attack coverage | `attack-coverage/attack-coverage.csv` | ATT&CK technique x artifacts | one-to-many, state tracked |

## 2. Architecture

```
  +-----------------+        +-----------------+        +-----------------+
  | 03-wordlists/   |        | 02-payloads/    |        | 04-evasion/     |
  | SecLists tokens |        | PAT records     |        | GTFOBins prim.  |
  +--------+--------+        +--------+--------+        +--------+--------+
           |                          |                          |
           |  token_id                |  payload_id              |  evasion_id
           +------------+-------------+--------------+-----------+
                        |                            |
                        v                            v
             +--------------------+        +--------------------------+
             | wordlist-payload/  |        | evasion-detection/      |
             |  build_payload_     |        |  evasion-to-detection   |
             |  index.py           |        |  .csv                   |
             +----------+---------+        +------------+-------------+
                        |                               |
                        v                               v
             +--------------------+        +--------------------------+
             | 03-wordlists/index/ |        | 06-defense/             |
             |  wordlist.db (FTS5) |        |  sigma/ wazuh/ suricata/|
             +----------+---------+        +------------+-------------+
                        |                               |
                        +---------------+---------------+
                                        v
                             +--------------------+
                             |  10-crosswalk/      |
                             |  attack-coverage/   |
                             |  api-contracts/     |
                             +--------------------+
```

## 3. Identifier namespaces

| Prefix | Meaning | Defined in |
|---|---|---|
| `PL-*` | payload record | `02-payloads/` |
| `EV-*` | evasion primitive | `04-evasion/index/evasion-index.csv` |
| `CH-*` | multi-hop chain | `04-evasion/chains/abuse-chains.md` |
| `PB-*` | playbook | `01-intel/playbooks/` |
| `MTH-*` | methodology | `01-intel/methodologies/` |
| `CS-*` | cheat sheet | `01-intel/cheat-sheets/` |
| `CL-*` | checklist | `01-intel/checklists/` |
| `IR-*` | incident response playbook | `06-defense/ir/` |
| `SID 300xxxx` | Suricata rule | `06-defense/suricata/rules/` |
| `1xxxxx` (Wazuh) | Wazuh rule | `06-defense/wazuh/rules/` |
| `<SHEET>-<n>` | OWASP control | `01-intel/cheat-sheets/owasp/owasp-controls.csv` |
| `Txxxx[.xxx]` | ATT&CK technique | `08-threatintel/attack/` |
| `CWE-<n>` | weakness | everywhere |
| `LAB-*` | lab asset | `09-labs/` |

## 4. Validation gates

```bash
python tools/ssactl.py verify --root . --strict          # REF-001 dangling ids
python tools/ssactl.py verify --root . --coverage        # COV-001 orphan controls
python tools/ssactl.py validate --root .                 # SCHEMA-001
python tools/ssactl.py index --root .                    # INDEX-001 determinism
python tools/ssactl.py stats --root .                    # report
```

| Code | Meaning | Exit |
|---|---|---|
| `STRUCT-001` | a directory in `spec.py` is missing on disk | 2 |
| `REF-001` | a crosswalk row references an unknown id | 2 |
| `COV-001` | a control has no detection anchor | 2 |
| `SCHEMA-001` | a JSON artifact violates `12-schemas/` | 2 |
| `INDEX-001` | the generated index is stale | 2 |
| `DRIFT-001` | an upstream ref moved | 0 (warn) |
| `SIZE-001` | corpus grew more than 20 % | 0 (review) |
