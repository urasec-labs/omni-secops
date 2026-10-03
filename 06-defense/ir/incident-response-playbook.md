# Incident Response Playbook

| Field | Value |
|---|---|
| `playbook_id` | IR-001 |
| `framework` | NIST SP 800-61r2 |
| `controls` | IR-01, IR-02, IR-03 |
| `sources` | `meirwah/awesome-incident-response`, `SANS` |

## 1. Severity and response targets

| Sev | Definition | First response | Update cadence | Escalation |
|---|---|---|---|---|
| SEV1 | Confirmed exfiltration, encryption, or destructive action | 15 min | hourly | CISO + Legal + comms |
| SEV2 | Confirmed compromise, scope unknown | 30 min | every 2 h | SOC lead + IT |
| SEV3 | Suspicious activity, unconfirmed | 4 h | daily | Analyst |
| SEV4 | Policy violation without impact | 1 day | weekly | Team lead |

## 2. Roles (assign by name before an incident, not during)

| Role | Duty | Backup |
|---|---|---|
| Incident Commander | Owns decisions, severity, comms | SOC lead |
| Technical Lead | Directs investigation | Tier 3 analyst |
| Forensics Lead | Evidence, imaging, chain of custody | DFIR contractor |
| Communications | Internal and external messaging | Legal |
| Scribe | Timeline, decisions, evidence log | Automation (this archive) |

## 3. Phase 1 - Preparation

- [ ] Playbook reviewed quarterly (`IR-03`)
- [ ] Contact tree tested monthly
- [ ] Jump host ready with the tooling in `07-tooling/`
- [ ] Forensic disk / RAM acquisition capability verified
- [ ] Legal and insurer notification path known
- [ ] Log sources confirmed to be reaching the SIEM (see `06-defense/wazuh/`)

## 4. Phase 2 - Detection and analysis

```powershell
# Windows triage
Get-LocalUser | Where-Object { $_.LastLogon -gt (Get-Date).AddDays(-1) }
Get-NetTCPConnection -State Established,Listen | Group-Object OwningProcess
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddHours(-4)} |
  Select TimeCreated,Message
```

```bash
# Linux triage
last -ai | head -40
ss -tulpn
find /tmp /dev/shm -type f -perm -u+x -mtime -2 2>/dev/null
journalctl --since "-4 hours" -p warning
```

Analysis questions:
1. What is the initial access vector?
2. What is the earliest confirmed malicious timestamp?
3. Which identities and hosts are involved?
4. Is there evidence of exfiltration?
5. Which of our detections fired, and which should have?

## 5. Phase 3 - Containment, eradication, recovery

| Option | Impact | Use when |
|---|---|---|
| Network isolation (EAP) | High - user disruption | Active exfiltration or lateral movement |
| Account disable + session kill | Medium | Compromised identity, host still trustworthy |
| Host shutdown (do not power off) | High | Unknown rootkit; image memory first |
| Selective process kill | Low | Single known malicious process |
| Rate limiting / blocking at egress | Low | Ongoing command and control |

**Always capture volatile evidence before containment:** memory, network
connections, running processes, logged-on users.

## 6. Phase 4 - Post-incident

- [ ] After-action review within 5 business days
- [ ] Timeline finalised in `06-defense/ir/timeline.md`
- [ ] Detection gaps turned into Sigma rules (this is the archive's key loop)
- [ ] New ATT&CK techniques recorded in `06-defense/blue-team/mitre-coverage.csv`
- [ ] Playbook, runbooks and training updated
- [ ] Compliance notification obligations tracked (GDPR 72 h, PCI, contracts)

## 7. Communication template

```text
SEV:            <SEV1-4>
Detected:       <UTC timestamp, source>
Summary:        <one sentence, no speculation>
Affected:       <identity/asset count and type>
Data exposure:  <confirmed / suspected / none>
Containment:    <action taken, UTC>
Next update:    <UTC>
Owner:          <Incident Commander>
```
