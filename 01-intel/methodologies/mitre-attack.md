# MITRE ATT&CK Coverage Model

| Field | Value |
|---|---|
| `methodology_id` | MTH-MITRE-ATTACK |
| `version` | ATT&CK v16 (matrix pinned in the lock file) |
| `url` | https://attack.mitre.org/ |

## 1. How the archive expresses coverage

Every offensive artifact in the archive declares one or more ATT&CK technique
IDs, and every defensive artifact declares the technique it detects. The
coverage matrix is generated:

```
  02-payloads/**      -- tags: [attack.t1190]
  04-evasion/**       -- tags: [attack.t1218]
  05-engines/**       -- tags: [attack.t1059.001]
  06-defense/**       -- tags: [attack.t1218]   (detection side)
                    \                        /
                     `-> 10-crosswalk/attack-coverage/attack-coverage.csv`
```

## 2. Coverage states

| State | Meaning | Gate behaviour |
|---|---|---|
| `full` | payload + evasion + module + detection | - |
| `offensive-only` | technique known, no detection | warns on `--strict` |
| `detective-only` | detection exists, no documented offence | informational |
| `gap` | neither | listed in the monthly gap report |

## 3. Tactic view (abridged, generated from the matrix)

| Tactic | Techniques in archive | Detection coverage |
|---|---|---|
| Initial Access | T1190, T1566, T1078 | high |
| Execution | T1059.001-.006, T1204 | high |
| Persistence | T1098, T1505.003, T1547 | medium |
| Privilege Escalation | T1068, T1134, T1548 | medium |
| Defense Evasion | T1218, T1027, T1112 | high |
| Credential Access | T1003, T1110, T1558 | high |
| Discovery | T1087, T1018, T1482 | high |
| Lateral Movement | T1021, T1570, T1090 | medium |
| Collection | T1005, T1560 | low |
| Exfiltration | T1041, T1567 | medium |
| Command and Control | T1071, T1573 | medium |
| Impact | T1486, T1490 | medium |

## 4. Purple-team exercise loop

1. Pick a gap from the coverage CSV.
2. Build an emulation in `09-labs/emulations/`.
3. Run it, observe which rules fire, note the gaps in the emulation file.
4. Add the missing rule to `06-defense/` with a crosswalk row.
5. Update the CSV. The loop is the archive's most important quality mechanism.
