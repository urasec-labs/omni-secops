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
