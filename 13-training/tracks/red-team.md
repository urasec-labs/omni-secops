# Role Track - Red Team

| Field | Value |
|---|---|
| `track_id` | TRACK-RED |
| `phases` | 2 mainly, 3 light |
| `primary` | `02-payloads/`, `04-evasion/`, `05-engines/` |

## 1. Capability targets

| Capability | Evidence | Archive material |
|---|---|---|
| Web application exploitation | Report with 5+ verified findings | `02-payloads/web/`, `01-intel/playbooks/web/` |
| AD compromise path | Documented path domain admin -> DC | `01-intel/playbooks/active-directory/` |
| Privilege escalation, all platforms | 20+ distinct vectors found in the lab | `04-evasion/` |
| Cloud IAM abuse | Working privesc chain in a sandbox account | `01-intel/playbooks/cloud/` |
| Container escape | Escape a restricted pod | `04-evasion/containers/` |
| Evasion tradecraft | Replay `CH-001` and `CH-002` with detections observed | `04-evasion/chains/` |
| OSINT | Handle, subdomain and metadata enumeration | `05-engines/osint/`, `08-threatintel/` |

## 2. Weekly cadence

| Activity | Time |
|---|---|
| Technique research and payload authoring | 4 h |
| Lab exploitation and rule observation | 6 h |
| Emulation authoring in `09-labs/emulations/` | 3 h |
| Report writing | 3 h |
| Crosswalk maintenance (new payloads, new rules) | 2 h |

## 3. Definition of done per finding

1. Payload added to `02-payloads/` with valid schema and provenance.
2. Fuzz token (if applicable) added and the crosswalk row generated.
3. Playbook step updated with the payload id.
4. Detection checked: does an existing rule fire? If not, author one.
5. Finding written in the format from
   `01-intel/checklists/penetration-testing-checklist.md` §6.

## 4. Red-team-specific red lines

* No destructive payloads on production without explicit written authorisation.
* No persistence left behind; document the clean-up and verify it.
* Never exfiltrate real data - prove access and stop.
* Operate only within the signed scope in `00-governance/charter.md` §7.
