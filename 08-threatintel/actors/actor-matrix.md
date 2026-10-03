# Threat Actor Matrix

| Field | Value |
|---|---|
| `dossier_id` | ACT-* |
| `source` | `08-threatintel/feeds/feed-registry.yaml`, internal analysis |
| `classification` | T1 (contains assessment, not just facts) |

## 1. Tracked actor profiles

| Actor ID | Tracked name | Sector | Initial access | Primary objective | Archive techniques |
|---|---|---|---|---|---|
| ACT-001 | FIN-LEA / financially motivated intrusion cluster | Finance, retail | Phishing, valid accounts | Financial fraud | T1566.002, T1078, T1486 |
| ACT-002 | SUPPLY / CI supply-chain actor | Software, energy | CI/CD compromise | Long-term persistence | T1195.002, T1505.003, T1197 |
| ACT-003 | RANSOM-AGG / ransomware affiliate | Healthcare, manufacturing | RDP, VPN | Encryption + extortion | T1133, T1486, T1490, T1567 |
| ACT-004 | CLOUD-PIVOT / cloud-focused actor | SaaS, technology | Valid cloud sessions | Cloud takeover | T1078.004, T1552.005, T1548.005, T1550.001 |
| ACT-005 | EDGE-APT / espionage actor | Government, telecom | Spearphishing, edge devices | Persistent access | T1190, T1059.008, T1021.001 |
| ACT-006 | LLM-ABUSE / prompt-injection actor | SaaS | Web content | Model tool abuse | T1195, T1204.002, T1567 |

## 2. Profile template

```markdown
### ACT-00X - <tracked name>
- First observed: <YYYY-MM>
- Sector targets: <list>
- Initial vectors:    Txxxx ...
- Persistence:       Txxxx ...
- Evasion:           Txxxx ...
- Credential access: Txxxx ...
- Exfiltration:      Txxxx ...
- Archive coverage:  see 06-defense/blue-team/mitre-coverage.csv rows for <technique list>
- Detection gaps:    <technique ids in state "offensive-only" or "gap">
- Confidence:        high | medium | low  (with basis)
```

## 3. Discipline

* Track **techniques**, not names. Attribution changes; TTP persistence is the
  signal.
* Every "high confidence" attribution needs a stated basis (infrastructure
  overlap, code reuse with a published report, victimology).
* Each actor row must name the archive technique ids it uses so coverage gaps
  are visible immediately.
