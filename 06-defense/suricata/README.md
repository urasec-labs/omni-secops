# Suricata Detection Layer

| Field | Value |
|---|---|
| `detection_layer` | network |
| `source` | OISF/suricata @ 7.0.10 |
| `rules_dir` | `06-defense/suricata/rules/` |
| `control_side` | `10-crosswalk/control-detection/control-detection.csv` |
| `evasion_side` | `10-crosswalk/evasion-detection/evasion-to-detection.csv` |

## 1. SID allocation (SSA owned ranges)

| Range | Purpose |
|---|---|
| 3001000-3001199 | Web application attacks (OWASP control anchored) |
| 3001200-3001399 | Evasion / living-off-the-land |
| 3001400-3001599 | Reconnaissance and scanning |
| 3001600-3001799 | Exfiltration and C2 |
| 3001800-3001999 | Cloud, CI/CD and container workloads |

Never reuse a retired sid. Retire by setting `rev:` and adding
`retired: <date>` to `10-crosswalk/control-detection/control-detection.csv`.

## 2. Rule anatomy in this archive

Every SSA rule carries, in the `metadata` and comment header:

* the `control_id` or `evasion_id` it implements,
* the CWE it maps to,
* the confidence rating,
* the archive provenance.

## 3. Validation loop

```bash
# syntax and semantics
suricata -T -c suricata.yaml -S 06-defense/suricata/rules/ssa-web-attacks.rules
suricata -T -c suricata.yaml -S 06-defense/suricata/rules/ssa-evasion.rules

# regression against the lab estate (09-labs/infrastructure)
suricata -c suricata.yaml -r 09-labs/pcaps/CH-001.pcap -l /tmp/ssa-out
evince /tmp/ssa-out/eve.json      # every replay must produce its expected sids
```

## 4. Expected sids per emulation

| Emulation | Expected sids |
|---|---|
| `CH-001.md` | 3001003, 3001201 |
| `CH-002.md` | 3001202, 3001203, 3001204 |
| `CH-003.md` | 3001003, 3001205 |
| `EV-LNX-0007.md` | 3001401 (if scanned) |
| `PB-WEB-AUTHBYPASS` | 3001404 |

A sid in this table that never fires in the lab is a defect. Record it in
`10-crosswalk/attack-coverage/attack-coverage.csv` with state `gap`.

## 5. Deployment modes

| Mode | Use | Caution |
|---|---|---|
| IDS | default | drop nothing |
| IPS (blocking) | perimeter, after validation | false positives become outages |
| EVE JSON only | high volume, tuning | no inline action |

Always run the archive ruleset in IDS mode for at least 14 days before enabling
any rule in blocking mode.
