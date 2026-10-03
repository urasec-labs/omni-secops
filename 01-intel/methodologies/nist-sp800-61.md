# NIST SP 800-61r2 - Computer Security Incident Handling Guide

| Field | Value |
|---|---|
| `methodology_id` | MTH-NIST-800-61 |
| `reference` | NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide |

## 1. Four-phase lifecycle mapped to `06-defense/ir/`

| NIST phase | Goal | Archive location | Artefacts |
|---|---|---|---|
| Preparation | Capability before the event | `06-defense/ir/incident-response-playbook.md`, `06-defense/sigma/` | Tabletop, contacts, tooling |
| Detection & Analysis | Establish what happened | `08-threatintel/`, `06-defense/ir/timeline.md` | Confirmed incident statement |
| Containment, Eradication, Recovery | Stop, remove, restore | `06-defense/ir/` containment matrix | Clean host evidence |
| Post-Incident Activity | Learn | `14-docs/decisions/`, `CHANGELOG.md` | Lessons learned |

## 2. Incident severity matrix (from the archive's IR playbook)

| Sev | Definition | Response target | Escalation |
|---|---|---|---|
| SEV1 | Confirmed data exfiltration or ransomware encryption | 15 min | CISO + Legal |
| SEV2 | Confirmed compromise, scope unknown | 30 min | SOC lead |
| SEV3 | Suspicious activity, unconfirmed | 4 h | Analyst |
| SEV4 | Policy violation without impact | 1 day | Team lead |

## 3. Evidence handling

Chain of custody: `06-defense/ir/evidence-handling.md`, hashes recorded with
`Get-FileHash -Algorithm SHA256` (PowerShell) and verified before and after
transfer. Never analyse the original; always work on a copy.

## 4. Detection sources mapped to the archive

| Source | Archive artefact |
|---|---|
| Suricata network alerts | `06-defense/suricata/rules/` |
| Wazuh host rules | `06-defense/wazuh/rules/` |
| Sigma portability layer | `06-defense/sigma/` |
| IOC feed ingestion | `08-threatintel/feeds/feed-registry.yaml` |
| CTI context | `08-threatintel/actors/` |
