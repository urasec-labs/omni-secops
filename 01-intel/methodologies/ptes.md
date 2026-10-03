# PTES - Penetration Testing Execution Standard Mapping

| Field | Value |
|---|---|
| `methodology_id` | MTH-PTES |
| `url` | http://www.pentest-standard.org/ |

## 1. Standard mapping

| PTES section | Archive location | Notes |
|---|---|---|
| 1 Intelligence Gathering | `05-engines/osint/sherlock/`, `08-threatintel/` | Passive first |
| 2 Threat Modelling | `00-governance/threat-model.md`, `01-intel/playbooks/` | Our own threat model is the reference example |
| 3 Vulnerability Identification | `03-wordlists/`, `05-engines/metasploit/modules/` | Continuous, not one-shot |
| 4 Exploitation | `02-payloads/`, `05-engines/sqlmap/` | Least-invasive-first ladder |
| 5 Post Exploitation | `04-evasion/`, `01-intel/playbooks/active-directory/` | Document the access path |
| 6 Reporting | `14-docs/standards/knowledge-format.md` §4 | RAV + remediation + evidence |

## 2. Engagement phases

```
  PLAN ----> RECON ----> SCAN ----> ENUM ----> EXPLOIT ----> PRIVESC ----> REPORT
   |            |          |          |            |            |            |
   v            v          v          v            v            v            v
 charter    sherlock   wordlists  service-    payloads/    04-evasion   14-docs/
 00-gov     08-threat  03-        enumeration sqlmap      active-dir   standards
            intel      wordlists  playbook               kerberos
```

## 3. Rules of engagement minimums

* Scope: CIDRs, domains, wildcards, explicitly excluded assets.
* Time window and timezone; out-of-band contacts.
* Source IP(s) and whether they will be detected on purpose.
* Emergency contact; stop conditions (data destruction, DoS, third-party data).
* Evidence handling and retention period (see
  `00-governance/data-classification.md`).
