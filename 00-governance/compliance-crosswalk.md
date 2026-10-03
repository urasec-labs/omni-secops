# Compliance Crosswalk

| Archive control | NIST SP 800-53 | ISO 27001:2022 | CIS Controls v8 | MITRE ATT&CK |
|---|---|---|---|---|
| `01-intel/cheat-sheets/owasp/CSRF-2` | SC-7 | A.8.25 | 16.1 | T1190 |
| `01-intel/cheat-sheets/owasp/AUTH-7` | AC-6, IA-2 | A.5.15 | 6.3 | T1078, T1110 |
| `01-intel/cheat-sheets/owasp/AUTHZ-3` | AC-3 | A.5.3 | 3.3 | T1068 |
| `01-intel/cheat-sheets/owasp/SESSION-4` | SC-10 | A.8.24 | 6.4 | T1539 |
| `01-intel/cheat-sheets/owasp/DES-3` | SC-13 | A.8.24 | 3.11 | T1552 |
| `01-intel/cheat-sheets/owasp/INPUT-4` | SI-10 | A.8.26 | 16.1 | T1190 |
| `01-intel/cheat-sheets/owasp/CRYPTO-1` | SC-13 | A.8.24 | 3.11 | T1557 |
| `06-defense/wazuh/rules/1000` | AU-2, AU-6 | A.8.15 | 8.2 | - |
| `06-defense/suricata/rules/ssa-web-attacks` | SI-4 | A.8.16 | 13.4 | T1190 |
| `06-defense/hardening/linux-baseline` | CM-6 | A.8.9 | 4.1 | T1059 |
| `06-defense/ir/incident-response-playbook` | IR-4 | A.5.24 | 17.1 | - |
| `00-governance/charter.md` | PM-9 | A.5.1 | 4.1 | - |

## How to read this

* **NIST SP 800-53** - control families used for US federal system baselines.
* **ISO 27001:2022** - Annex A control references.
* **CIS Controls v8** - Implementation Group (IG1/IG2/IG3) safeguards.
* **MITRE ATT&CK** - technique the control mitigates.

The authoritative machine readable version lives at
`10-crosswalk/control-detection/control-detection.csv`.
