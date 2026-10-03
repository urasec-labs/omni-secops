# Penetration Testing Checklist

Derived from `j0hnx3r/awesome-pentest` workflow + `meirwah/awesome-incident-response` discipline.

## 1. Pre-engagement

- [ ] Scope document signed: assets, exclusions, window, source IPs, contacts
- [ ] Emergency stop criteria agreed (data destruction, DoS, third-party data)
- [ ] Third-party assets identified and NOT tested
- [ ] Test accounts provided (never test with real user credentials)
- [ ] Backup verified by the client (you might need to restore)

## 2. Reconnaissance

- [ ] WHOIS, ASN, netblock ownership (`01-intel/cheat-sheets/book-of-secret-knowledge.md`)
- [ ] Passive DNS and CT log mining
- [ ] Subdomain enumeration (`03-wordlists/discovery/dns/`)
- [ ] Employee handles (`05-engines/osint/sherlock/`) - note ethics limits
- [ ] Content discovery (`03-wordlists/web/fuzzing/`)
- [ ] Git repository and backup file exposure (`.git`, `.bak`, `.swp`)

## 3. Vulnerability identification

- [ ] Port and service fingerprint (`01-intel/playbooks/network/service-enumeration.md`)
- [ ] Vulnerability scan with version cross-check
- [ ] Injection points on every parameter and header (`02-payloads/web/`)
- [ ] AuthN/AuthZ testing incl. horizontal/vertical privilege escalation
- [ ] Business logic abuse
- [ ] Configuration review against `06-defense/hardening/`
- [ ] Cloud storage permissions (`aws s3 ls` style)

## 4. Exploitation (prove, do not maximise)

- [ ] Prefer read-only proof over data extraction
- [ ] Never leave persistence on client production
- [ ] Document every command with output (evidence)
- [ ] Retest after remediation

## 5. Lateral movement and privilege escalation

- [ ] Document the full access path (`04-evasion/chains/abuse-chains.md`)
- [ ] Identify the escalation primitive ID (`EV-*`)
- [ ] Record the crown-jewel access, then stop

## 6. Reporting

- [ ] Findings with RAV score, evidence, reproduction, remediation
- [ ] Clean-up confirmed (test accounts removed, files deleted, no persistence)
- [ ] Retest scheduled
- [ ] Archive evidence per `00-governance/data-classification.md`

## 7. Deliverable template

```markdown
### SSA-<ENGAGEMENT>-F<n> - <title>
- Severity / RAV: <critical / high ...>  RAV=<n>
- Asset: <host/path>
- CWE / OWASP: CWE-89 / A03:2021
- Control mapping: INJ-1
- Evidence: <request/response, command + output>
- Reproduction: <numbered steps>
- Impact: <business impact, not just technical>
- Remediation: <specific, verifiable>
- Crosswalk: 10-crosswalk/attack-coverage/attack-coverage.csv
```
