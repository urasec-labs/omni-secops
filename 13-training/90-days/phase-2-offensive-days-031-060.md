# Phase 2 - Offensive Operations (Days 031-060)

| Field | Value |
|---|---|
| `phase_id` | TRN-P2 |
| `window` | day 031 - 060 |
| `outcome` | Complete a scoped web + AD assessment with a written report |
| `gate` | Full exploitation chain in `09-labs` with detections observed |
| `playbooks` | `01-intel/playbooks/web/`, `.../active-directory/`, `.../network/` |

## Week 5 - Web application attack surface (031-037)

| Day | Topic | Material | Practical |
|---|---|---|---|
| 031 | Recon: subdomains, endpoints, JS | `05-engines/osint/sherlock/` | Enumerate the lab app |
| 032 | Content discovery and hidden paths | `03-wordlists/web/content-words.txt` | `ffuf` the lab |
| 033 | Injection: SQLi | `01-intel/playbooks/web/sql-injection.md` | Boolean and time based |
| 034 | Injection: XSS in every context | `01-intel/playbooks/web/xss.md` | Find one stored XSS |
| 035 | SSRF and XXE | `01-intel/playbooks/web/ssrf.md` | IMDSv2 token retrieval in the lab |
| 036 | AuthN / session / JWT | `02-payloads/api/jwt-hs256-confusion.md` | Forge an HS256 token |
| 037 | Access control / IDOR / BOLA | `02-payloads/api/payloads.json` | Horizontal escalation |

## Week 6 - Windows and AD (038-044)

| Day | Topic | Material | Practical |
|---|---|---|---|
| 038 | AD reconnaissance | `05-engines/metasploit/modules/modules-index.csv` | BloodHound on the lab domain |
| 039 | Kerberos mechanics | `01-intel/playbooks/active-directory/kerberos-attacks.md` | Explain ticket flow on a whiteboard |
| 040 | AS-REP roast and Kerberoast | same | Execute both in the lab |
| 041 | DCSync and delegation | same | Detect DCSync off-domain |
| 042 | SMB relay and signing | `06-defense/hardening/windows-baseline.md` | Verify signing is enforced |
| 043 | Lateral movement | `04-evasion/windows/sushi.md` | `psexec`, `wmiexec`, `smb_delivery` |
| 044 | ADCS abuse (ESC1-ESC8) | `06-defense/sigma/ssa_ad_dcsync.yml` | Identify a vulnerable template |

## Week 7 - Privilege escalation and evasion (045-051)

| Day | Topic | Material | Practical |
|---|---|---|---|
| 045 | Linux privesc survey | `04-evasion/linux/sudo-lpe.md` | Find every vector on the lab host |
| 046 | Windows privesc | `05-engines/metasploit/post-exploitation/privesc-map.md` | 8 vectors in the lab |
| 047 | Container escape | `04-evasion/containers/docker-escape.md` | Privileged run + socket |
| 048 | Pivoting and tunnelling | `01-intel/playbooks/network/pivoting.md` | chisel + proxychains |
| 049 | Cloud IAM privesc | `01-intel/playbooks/cloud/aws-iam-privesc.md` | `simulate-principal-policy` |
| 050 | Evasion chains | `04-evasion/chains/abuse-chains.md` | Replay `CH-001` |
| 051 | Payload adaptation | `02-payloads/templates/payload.template.json` | Add one payload end to end |

## Week 8 - Method, evidence, reporting (052-060)

| Day | Topic | Material | Practical |
|---|---|---|---|
| 052 | PTES phases | `01-intel/methodologies/ptes.md` | Fill the plan template |
| 053 | OSSTMM phases and RAV | `01-intel/methodologies/osstmm.md` | Score five findings |
| 054 | Evidence discipline | `06-defense/ir/evidence-handling.md` | Build a custody register |
| 055 | Finding writing | `01-intel/checklists/penetration-testing-checklist.md` §6 | Write three findings |
| 056 | Crosswalk literacy | `10-crosswalk/README.md` | Query the unified index |
| 057 | Detection engineering basics | `06-defense/blue-team/owasp-to-detection.md` | Write one Sigma rule |
| 058 | Report assembly | `14-docs/standards/knowledge-format.md` | Draft the report |
| 059 | Peer review | - | Review a colleague's report |
| 060 | Phase 2 assessment | `13-training/assessments/quiz-bank.md` | See gate below |

## Phase 2 gate

- [ ] Complete `CH-001` in `09-labs/emulations/` and observe every expected alert
- [ ] Produce a report with at least 5 findings, each with RAV, CWE and remediation
- [ ] Demonstrate one wordlist+payload crosswalk query and explain the join
- [ ] Add one payload **and** its Sigma rule **and** its crosswalk row; `ssactl verify --coverage` passes
