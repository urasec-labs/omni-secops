# SOVEREIGN SECURITY ARCHIVE (SSA)

> **OBSIDIAN VAULT** - one archive, twenty legends, zero duplication.
> A sovereign, offline-first, vendor-neutral consolidation of the twenty most
> consequential public security repositories ever produced, re-engineered into
> a single modular mega-repo with machine readable crosswalks between them.

```
                      ┌──────────────────────────────────────────┐
                      │        SOVEREIGN SECURITY ARCHIVE         │
                      │              OBSIDIAN VAULT               │
                      └───────────────────┬──────────────────────┘
                                          │
   ┌──────────────┬───────────────┬───────┴────────┬──────────────┬──────────────┐
   │  01-intel    │ 02-payloads   │ 03-wordlists   │ 04-evasion   │ 05-engines   │
   │   KNOWLEDGE  │   PAYLOADS    │   WORDLISTS    │   EVASION    │   ENGINES    │
   │  HackTricks  │  PayloadsAll  │    SecLists    │   GTFOBins   │  Metasploit   │
   │  h4cker      │  TheThings    │                │              │  sqlmap       │
   │  BookOfSecK  │               │                │              │  Sherlock     │
   ├──────────────┴───────────────┴───────┬────────┴──────────────┴──────────────┤
   │                                      │                                      │
   │   ┌──────────────┐            ┌──────┴───────┐                     ┌────────────┴────────┐
   │   │ 06-defense   │            │ 07-tooling   │                     │     08-threatintel  │
   │   │  Wazuh       │            │  CyberChef   │                     │ Awesome Threat      │
   │   │  Suricata    │            │  ImHex       │                     │ Intelligence        │
   │   │  OWASP CS    │            └──────────────┘                     └─────────────────────┘
   │   └──────┬───────┘
   │          │  ▲  10-crosswalk  (wordlist↔payload, evasion↔detection, control↔rule)
   └──────────┼──┴────────────────────────────────────────────────────────────────────┐
              ▼                                                                        │
   ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────────┐   │
   │  11-automation       │   │  12-schemas          │   │  09-labs                 │   │
   │  indexers, CI        │   │  JSON Schema truth   │   │  DVWA, Terraform, atomic │◄──┘
   └──────────┬───────────┘   └──────────┬───────────┘   └──────────────────────────┘
              └──────────────────────────┼───────────────────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │ 13-training  |  14-docs       │
                         │ 90-day paths | architecture   │
                         └───────────────────────────────┘
```

---

## 1. MISSION

Public security knowledge is fragmented. A penetration tester holds payloads in
one tab, wordlists in a second, hardening advice in a third, and detection logic
in a fourth - none of which reference each other. **The Sovereign Security
Archive closes that gap.** Every artifact in this repository carries an
identifier, and every identifier resolves across domains through the
`10-crosswalk/` layer.

| # | Upstream archive | Owner | Lands in | Role in SSA |
|---|---|---|---|---|
| 01 | PayloadsAllTheThings | swisskyrepo | `02-payloads/` | Payload corpus of record |
| 02 | SecLists | danielmiessler | `03-wordlists/` | Wordlist corpus of record |
| 03 | GTFOBins | GTFOBins | `04-evasion/` | Trusted-binary abuse catalogue |
| 04 | HackTricks | carlospolop | `01-intel/playbooks/` | Technique runbooks |
| 05 | Book of Secret Knowledge | dmknght | `01-intel/cheat-sheets/` | Operator toolbox |
| 06 | The Art of Hacking | The-Art-of-Hacking | `01-intel/playbooks/` | Deep technical curriculum |
| 07 | 90 Days of Cyber Security | 0xDigit | `13-training/` | Onboarding path |
| 08 | Awesome Hacking | 0xdea | `09-labs/` | Operator tool index |
| 09 | Awesome Pentest | j0hnx3r | `01-intel/methodologies/` | Engagement workflow |
| 10 | Awesome Incident Response | meirwah | `06-defense/ir/` | IR playbooks |
| 11 | Awesome Threat Intelligence | amittmadan | `08-threatintel/` | CTI pipeline |
| 12 | Metasploit Framework | rapid7 | `05-engines/metasploit/` | Exploitation engine |
| 13 | sqlmap | sqlmapproject | `05-engines/sqlmap/` | SQLi automation |
| 14 | Sherlock | sherlock-project | `05-engines/osint/` | Handle OSINT |
| 15 | ImHex | WerWolv | `07-tooling/imhex/` | Binary forensics |
| 16 | Wazuh | wazuh | `06-defense/wazuh/` | Host XDR |
| 17 | Suricata | OISF | `06-defense/suricata/` | Network IDS/IPS |
| 18 | CyberChef | gchq | `07-tooling/cyberchef/` | Data transformation |
| 19 | OWASP Cheat Sheet Series | OWASP | `01-intel/cheat-sheets/owasp/` | Control catalogue |
| 20 | Personal Security Checklist | 0xNaN | `01-intel/checklists/` | Individual baseline |

Full machine readable inventory: `00-governance/manifests/source-repos.lock.json`.

---

## 2. QUICK START

```powershell
# Windows / PowerShell 5.1+
.\bootstrap.ps1                 # bootstrap the archive in place
.\bootstrap.ps1 -Root C:\SSA    # bootstrap into another location
.\bootstrap.ps1 -Verify         # validate an existing archive, no writes
```

```bash
# Linux / macOS / any POSIX shell
python3 tools/ssactl.py init --root .
python3 tools/ssactl.py verify --root .
python3 tools/ssactl.py index  --root .     # build the unified wordlist/payload index
python3 tools/ssactl.py stats --root .
```

```powershell
# PowerShell 5.1 native entry point (no python required for verify)
.\bootstrap.ps1 -Mode Verify
```

---

## 3. DIRECTORY MAP

| Path | Domain | Fed by | Contract |
|---|---|---|---|
| `00-governance/` | Control plane | - | Charter, threat model, classification, compliance |
| `01-intel/` | Knowledge | HackTricks, h4cker, BookOfSecretKnowledge, OWASP CS | Playbook front-matter |
| `02-payloads/` | Offensive data | PayloadsAllTheThings | `12-schemas/payload.schema.json` |
| `03-wordlists/` | Offensive data | SecLists | `12-schemas/wordlist-entry.schema.json` |
| `04-evasion/` | Offensive data | GTFOBins | Evasion record schema |
| `05-engines/` | Automation | Metasploit, sqlmap, Sherlock | Module index CSV |
| `06-defense/` | Defensive | Wazuh, Suricata, OWASP CS, Awesome IR | `12-schemas/detection.schema.json` |
| `07-tooling/` | Analyst | CyberChef, ImHex | Recipe / pattern formats |
| `08-threatintel/` | Intelligence | Awesome Threat Intelligence | `12-schemas/ioc.schema.json` |
| `09-labs/` | Validation | Awesome Hacking | Compose + Terraform |
| `10-crosswalk/` | **Integration** | all twenty | `10-crosswalk/api-contracts/` |
| `11-automation/` | Build | - | `make verify` |
| `12-schemas/` | Truth | - | JSON Schema draft 2020-12 |
| `13-training/` | Human | 90 Days of Cyber Security | Phase checklist |
| `14-docs/` | Human | - | ADR, standards, glossary |

---

## 4. INTEGRATION MODEL

### 4.1 Wordlist ↔ Payload (one optimized database)

```
  03-wordlists/web/fuzzing/*.txt          02-payloads/web/**/*.json
            │                                       │
            │  tokenize()                           │  normalize()
            ▼                                       ▼
   ┌────────────────────────────────────────────────────────┐
   │  03-wordlists/index/wordlist.db  (SQLite, FTS5)        │
   │  ┌──────────────┐   ┌──────────────────┐               │
   │  │ token        │◄──┤ fuzz_token       │               │
   │  │ token_id  PK │  │ payload_id  FK   │               │
   │  │ surface      │   │ confidence 0..1  │               │
   │  │ (IN 2..5)    │   │ origin (fuzz|pay)│               │
   │  └──────────────┘   └──────────────────┘               │
   └────────────────────────────────────────────────────────┘
            │  join key:  (cwe_id, context, surface)
            ▼
   10-crosswalk/wordlist-payload/crosswalk.csv
```

* A SecLists fuzzing entry and a PayloadsAllTheThings payload that share the
  same `(cwe, context, surface)` tuple collapse into **one** row in the index.
* The unified row stores both origins, so `ssactl index` never duplicates and a
  consumer can ask for "all injection tokens for parameter `id` on a PHP
  endpoint" from a single query.
* Consumer example:

```sql
SELECT p.payload, p.context, w.token, w.origin
FROM   fuzz_token f
JOIN   token      t ON t.token_id  = f.token_id
JOIN   payload    p ON p.payload_id= f.payload_id
WHERE  p.cwe_id = 'CWE-89' AND p.context = 'query' AND t.surface IN ('parameter','header');
```

### 4.2 Evasion ↔ Metasploit ↔ HackTricks

```
  04-evasion/linux/sudo-lpe.md        (GTFOBins primitive: sudo abuse)
            │  primitive_id = EV-LNX-0007
            ▼
  05-engines/metasploit/post-exploitation/privesc-map.md   (module + stager)
            │  module = exploit/multi/handler ; technique_id = EV-LNX-0007
            ▼
  01-intel/playbooks/linux/privilege-escalation.md          (HackTricks runbook)
            │  runbook step 3 == EV-LNX-0007
            ▼
  10-crosswalk/evasion-detection/evasion-to-detection.csv
            │
            ├──► 06-defense/wazuh/rules/  (rule 86651, Sysmon EventID 4672 / 4688)
            └──► 06-defense/suricata/rules/ssa-evasion.rules (alert dns/http exfil)
```

Every GTFOBins entry is promoted to a stable `EV-*` identifier in
`04-evasion/index/evasion-index.csv`. Metasploit post-exploitation modules and
HackTricks runbook steps **must** cite that identifier; the validator
(`ssactl verify`) fails the build when a dangling reference appears.

### 4.3 OWASP Cheat Sheet ↔ Wazuh / Suricata (Blue Team)

```
  01-intel/cheat-sheets/owasp/index.md            control: CSRF-1, AUTH-3, LLM-02 ...
            │
            ▼  10-crosswalk/control-detection/control-detection.csv
   ┌────────┴───────────────────────────┐
   │ control_id  severity  layer        │
   ├────────────────────────────────────┤
   │ CSRF-2    CRITICAL   network       │──► suricata/rules/ssa-web-attacks.rules
   │ AUTH-7    HIGH       host          │──► wazuh/rules/ssa-baseline.xml  (4625, 4728)
   │ DES-3     MEDIUM     audit         │──► sigma/ssa_privilege_abuse.yml
   │ LLM-01    HIGH       application   │──► sigma/ssa_llm_prompt_leak.yml
   └────────────────────────────────────┘
```

* Every OWASP control line is given a `control_id`, a severity, and **at least
  one** defensive anchor (network, host, or log-analytic).
* Controls with no anchor are a build failure - a documented, machine-checked
  coverage requirement, not a convention.

---

## 5. USE-CASE MATRIX

| Operator | Primary surface | Secondary surface | Time to value |
|---|---|---|---|
| Web app pentester | `02-payloads/web/` | `01-intel/playbooks/web/` | 5 min |
| Full-scope pentester | `01-intel/methodologies/` | `10-crosswalk/attack-coverage/` | 30 min |
| Red team operator | `04-evasion/` | `05-engines/metasploit/post-exploitation/` | 15 min |
| Detection engineer | `10-crosswalk/control-detection/` | `06-defense/` | 10 min |
| SOC analyst L1/L2 | `06-defense/ir/` | `08-threatintel/` | 20 min |
| Cloud security | `01-intel/playbooks/cloud/` | `06-defense/hardening/` | 30 min |
| New joiner (0-90d) | `13-training/90-days/` | `01-intel/playbooks/web/sqli.md` | day 1 |
| DFIR analyst | `07-tooling/imhex/` | `06-defense/ir/` | 15 min |
| CTF / lab author | `09-labs/` | `02-payloads/` | 10 min |

---

## 6. 90-DAY PATHS

```
 Day 001 ────────────── 030 ────────────── 060 ────────────── 090
   │  PHASE 1               │  PHASE 2          │  PHASE 3        │
   │  FOUNDATIONS           │  OFFENSIVE         │  DEFENSIVE       │
   │  networking, Linux,    │  web, AD, cloud,   │  SIEM rules,     │
   │  HTTP, crypto, recon   │  privesc, evasion  │  IR, ATT&CK      │
   ▼                        ▼                   ▼                 ▼
 13-training/90-days/phase-1-...md   phase-2-...md   phase-3-...md
```

| Phase | Days | Outcome | Gate |
|---|---|---|---|
| 1 - Foundations | 001-030 | Can enumerate, read a packet, explain an HTTP request | Lab: build & scan a lab host |
| 2 - Offensive | 031-060 | Complete a scoped web + AD assessment write-up | Gate: `09-labs` exploitation chain |
| 3 - Defensive | 061-090 | Ship one Sigma detection + one Wazuh rule + IR memo | Gate: detection fires in lab |

Role specialisations live in `13-training/tracks/`
(`red-team.md`, `blue-team.md`, `secops.md`).

---

## 7. DATA FLOW

```
   01-intel ─────┐
   02-payloads ───┤
   03-wordlists ──┼──► 11-automation/scripts/build_payload_index.py
   04-evasion ─────┤            │
   05-engines ─────┤            ▼
   08-threatintel ─┘      03-wordlists/index/wordlist.db
                         10-crosswalk/*.csv
                                  │
             ┌────────────────────┼────────────────────┐
             ▼                    ▼                    ▼
      06-defense/wazuh    06-defense/suricata    13-training
      (host detections)   (network detections)  (curriculum refresh)
```

---

## 8. QUALITY GATES

| Gate | Tool | Fails when |
|---|---|---|
| Structure | `ssactl verify` | A directory in `spec.py` is missing from disk |
| Schema | `ssactl validate --schema` | A JSON artifact violates `12-schemas/*.json` |
| Reference | `ssactl verify` | A `EV-*`, `control_id`, `cwe_id` or `payload_id` dangles |
| Coverage | `ssactl verify --coverage` | An OWASP control has no detection anchor |
| Index | `ssactl index` | Duplicate `(token, cwe, context)` triples appear |
| Drift | `ssactl diff --upstream` | A locked upstream revision moved |

---

## 9. GOVERNANCE

* **Licensing** - each upstream archive keeps its own licence; see
  `00-governance/manifests/source-repos.lock.json`. This repository is MIT.
* **Classification** - `T0` public / `T1` internal / `T2` restricted. Payload
  fragments that can damage a live system are `T2`; see
  `00-governance/data-classification.md`.
* **Legal** - use only against systems you own or are contractually authorised
  to test. `00-governance/charter.md` §7 is the signed scope statement.

---

## 10. LICENSE

MIT - see `LICENSE`. Upstream content remains under its original licence.
