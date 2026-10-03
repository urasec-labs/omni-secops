"""Curated root-level and governance content."""

from __future__ import annotations

FILES: dict[str, str] = {}

FILES["README.md"] = r'''
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
'''.lstrip()

FILES["VERSION"] = "1.0.0\n"

FILES["LICENSE"] = r'''
MIT License

Copyright (c) 2026 Sovereign Security Archive Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

--------------------------------------------------------------------------------
UPSTREAM NOTICE

This archive consolidates and re-organises material originating in the projects
listed in 00-governance/manifests/source-repos.lock.json. Each upstream project
retains copyright and licence ownership of its own content. Files under
02-payloads/, 03-wordlists/, 04-evasion/ and 05-engines/ are derived works and
must be redistributed under the upstream licence recorded in the lock file.
--------------------------------------------------------------------------------

Portions derived from:
  Metasploit Framework    BSD-3-Clause  (Rapid7)
  Suricata                GPL-2.0      (OISF)
  Wazuh                   GPL-2.0      (Wazuh, Inc.)
  sqlmap                  GPL-2.0      (sqlmap project)
  HackTricks              GPL-3.0      (carlospolop)
  ImHex                   GPL-2.0      (WerWolv)
  OWASP CheatSheetSeries  CC-BY-SA-4.0 (OWASP Foundation)
  Remaining sources       MIT / CC0-1.0 / Apache-2.0
'''.lstrip()

FILES["GOVERNANCE.md"] = r'''
# Governance

## 1. Roles

| Role | Duty | Quorum |
|---|---|---|
| Archive Steward | Merges taxonomy changes, owns `spec.py` | 2 |
| Domain Maintainer | Owns one top-level domain (`0X-*/`) | 1 per domain |
| Detection Reviewer | Approves anything under `06-defense/` | 1, never the author |
| Legal Reviewer | Approves new upstream ingestion | 1 |

## 2. Change control

1. Issue an ADR under `14-docs/decisions/ADR-NNNN-slug.md` for taxonomy changes.
2. Open a pull request touching at most one top-level domain plus `10-crosswalk/`.
3. CI must be green: `ssactl verify`, `ssactl validate`, `ssactl index --check`.
4. A Domain Maintainer from a *different* domain approves cross-domain changes.

## 3. Upstream ingestion

New sources enter only through `00-governance/manifests/source-repos.lock.json`.
The lock file records `name`, `owner`, `url`, `license`, `pinned_ref` and the
`landed_in` directories. `ssactl diff --upstream` compares pinned refs with the
network and opens a drift report when they diverge.

## 4. Back-pressure rules

* An upstream file is **never** copied verbatim without a `provenance` header.
* Normalisation happens in `11-automation/scripts/`; the raw upstream stays in
  the git submodule referenced by the lock file.
* Corpus growth is capped per release: >20 % size increase requires a
  `CHANGELOG.md` entry explaining the delta.

## 5. Incident handling for the archive

The archive itself is a security product. Reports go to `SECURITY.md` and are
triaged as Sev1 when the issue enables an attacker to silently corrupt a
detection rule or suppress an index entry.
'''.lstrip()

FILES["CONTRIBUTING.md"] = r'''
# Contributing

## 1. Golden rules

1. **One identifier per artifact.** Every payload, wordlist family, evasion
   primitive, control and detection carries a stable ID (`payload_id`,
   `token_id`, `EV-*`, `control_id`, `detection_id`).
2. **No orphan identifiers.** If you introduce an ID you must reference it from
   at least one crosswalk, or `ssactl verify` fails.
3. **No prose-only additions to data domains.** `02-`, `03-`, `04-`,
   `05-`, `06-defense/`, `08-` are machine readable; add schema-valid data.
4. **Provenance or nothing.** Every derived file starts with a provenance
   header naming the upstream project and pinned ref.

## 2. Adding a payload

```json
{
  "payload_id": "PL-WEB-SQLI-0001",
  "schema": "12-schemas/payload.schema.json",
  "cwe_id": "CWE-89",
  "context": "query",
  "surface": "parameter",
  "engine": "generic",
  "payload": "' OR 1=1-- -",
  "severity": "high",
  "tags": ["auth-bypass", "union"],
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" }
}
```

Then add the matching fuzz token to `03-wordlists/web/fuzzing/` and a row to
`10-crosswalk/wordlist-payload/crosswalk.csv`.

## 3. Adding a detection

```yaml
id: ssa_l001_persistence_authorized_keys_write
status: experimental
title: OpenSSH authorized_keys modified
logsource: { product: linux, service: sshd }
detection:
  selection_authorized: { TargetFilename|contains: '/.ssh/authorized_keys' }
  selection_write: { EventID: 2 }
  condition: selection_authorized and selection_write
fields: [TargetFilename, User, Image]
falsepositives: [Configuration management, break-glass account provisioning]
level: high
tags: [attack.persistence, attack.t1098.004]
```

Add the matching `control_id` in `06-defense/blue-team/controls/controls.csv`
and reference it from `10-crosswalk/control-detection/control-detection.csv`.

## 4. Local checks

```bash
python tools/ssactl.py verify --root . --strict
python tools/ssactl.py validate --root .
python tools/ssactl.py index --root .
```

## 5. Style

* Markdown: one H1 per file, fenced code blocks carry a language.
* YAML: two-space indent, no tabs, LF endings.
* Python: stdlib only for `tools/ssactl`; 3.9+ compatible.
* Every directory must have a `README.md`. `ssactl` generates missing ones from
  `tools/ssactl/spec.py`, but hand-written ones always win.
'''.lstrip()

FILES["SECURITY.md"] = r'''
# Security Policy

## Reporting

Report vulnerabilities in this archive to the maintainers privately. Do not
open a public issue for:

* A detection rule that can be silently evaded by an attacker who reads it.
* An index poisoning vector in `03-wordlists/index/`.
* A payload entry that is weaponised beyond what an authorised test needs.

Include: affected path, reproduction, impact on detection coverage.

## What we consider a vulnerability here

| Class | Severity |
|---|---|
| Detection rule evasion through normalisation gap | Critical |
| Crosswalk join producing wrong CVE/CWE attribution | High |
| Schema acceptance of malformed payload causing tool crash | Medium |
| Documentation inaccuracy | Low |

## Safe use

The content in `02-payloads/`, `03-wordlists/` and `04-evasion/` is offensive
material. It is published for authorised security testing, detection research
and education. Running it against infrastructure you do not own or have written
permission to test may be a criminal offence in your jurisdiction.
'''.lstrip()

FILES["CHANGELOG.md"] = r'''
# Changelog - All notable changes to the Sovereign Security Archive.

Format follows Keep a Changelog. Versions follow Semantic Versioning.

## [1.0.0] - 2026-01-15

### Added
- Initial consolidation of 20 upstream archives into 15 top-level domains.
- `10-crosswalk/` integration layer with four mappings:
  wordlist↔payload, evasion↔module↔runbook, control↔detection, attack coverage.
- `12-schemas/` JSON Schema (draft 2020-12) for payload, wordlist entry,
  evasion primitive, detection, IOC and crosswalk row.
- `03-wordlists/index/wordlist.db` SQLite + FTS5 unified corpus index and the
  `build_payload_index.py` generator.
- `06-defense/` Suricata ruleset (web, evasion, exfiltration), Wazuh baseline
  ruleset with custom decoder, Sigma detection library.
- `13-training/` three-phase 90-day curriculum plus red/blue/secops tracks.
- `ssactl` control plane (init / verify / validate / index / stats / diff) and
  `bootstrap.ps1` PowerShell 5.1 entry point.

### Changed
- N/A - first release.

### Known issues
- `ssactl diff --upstream` requires network access; offline runs report DRIFT-UNKNOWN.
'''.lstrip()

FILES["CODEOWNERS"] = r'''
# Default owners for every path in the archive.
# <path>                                    <owner>

*                                   @archive-steward

# Knowledge
01-intel/playbooks/                 @knowledge-maintainer
01-intel/methodologies/             @knowledge-maintainer
01-intel/cheat-sheets/owasp/        @appsec-maintainer
01-intel/checklists/                @endpoint-maintainer

# Offensive corpora
02-payloads/                        @offensive-data-maintainer
03-wordlists/                       @offensive-data-maintainer
04-evasion/                         @redteam-maintainer

# Engines
05-engines/metasploit/              @redteam-maintainer
05-engines/sqlmap/                  @offensive-data-maintainer
05-engines/osint/                   @cti-maintainer

# Defensive
06-defense/wazuh/                   @detection-reviewer @endpoint-maintainer
06-defense/suricata/                @detection-reviewer @network-maintainer
06-defense/blue-team/               @detection-reviewer
06-defense/sigma/                   @detection-reviewer
06-defense/ir/                      @ir-maintainer

# Intelligence
08-threatintel/                     @cti-maintainer

# Labs
09-labs/                            @lab-maintainer

# Integration, build, schema - steward only
10-crosswalk/                       @archive-steward @detection-reviewer
11-automation/                      @archive-steward
12-schemas/                         @archive-steward
tools/                              @archive-steward
'''.lstrip()

FILES[".editorconfig"] = r'''
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{yml,yaml,json,md,mmd}]
indent_size = 2

[*.{py}]
indent_size = 4
max_line_length = 100

[*.{txt,csv}]
insert_final_newline = false
trim_trailing_whitespace = false

[*.{ps1}]
indent_size = 4

[Makefile]
indent_style = tab
'''.lstrip()

FILES[".gitattributes"] = r'''
* text=auto eol=lf

*.ps1  text eol=crlf
*.bat  text eol=crlf
*.cmd  text eol=crlf

*.txt  -text -diff
*.hexpat text
*.rules text
*.yml  text diff=yaml
*.json text diff=json
*.csv  text diff=csv

02-payloads/** linguist-generated=true
03-wordlists/** linguist-generated=true -diff
'''.lstrip()

FILES[".gitignore"] = r'''
# Generated artifacts
/03-wordlists/index/wordlist.db
/03-wordlists/index/wordlist.db-journal
/03-wordlists/index/wordlist.db-wal
/03-wordlists/index/wordlist.db-shm
/00-governance/manifests/ssa-manifest.json
/dist/
/build/
/out/

# Editors / OS
.vscode/
.idea/
*.swp
Thumbs.db
.DS_Store
desktop.ini

# Python
__pycache__/
*.py[cod]
.venv/
venv/
.mypy_cache/
.pytest_cache/

# Local scratch
/.ssactl-cache/
*.local
'''.lstrip()

FILES["Makefile"] = r'''
# Sovereign Security Archive - convenience targets.
# Requires: python3 (3.9+) or py -3 on Windows.

PYTHON ?= python3
ROOT   ?= .

.PHONY: help init verify validate index stats upstream-diff clean

help:
	@echo "SSA targets:"
	@echo "  make init            scaffold/refresh the archive tree"
	@echo "  make verify          structure + reference integrity"
	@echo "  make validate        JSON Schema validation"
	@echo "  make index           build 03-wordlists/index/wordlist.db"
	@echo "  make stats           archive statistics"
	@echo "  make upstream-diff   compare pinned upstream refs (network)"
	@echo "  make clean           remove generated artifacts"

init:
	$(PYTHON) tools/ssactl.py init --root $(ROOT)

verify:
	$(PYTHON) tools/ssactl.py verify --root $(ROOT) --strict

validate:
	$(PYTHON) tools/ssactl.py validate --root $(ROOT)

index:
	$(PYTHON) tools/ssactl.py index --root $(ROOT)

stats:
	$(PYTHON) tools/ssactl.py stats --root $(ROOT)

upstream-diff:
	$(PYTHON) tools/ssactl.py diff --upstream --root $(ROOT)

clean:
	$(PYTHON) tools/ssactl.py clean --root $(ROOT)
'''.lstrip()

FILES["pyproject.toml"] = r'''
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "ssactl"
version = "1.0.0"
description = "Control plane for the Sovereign Security Archive"
readme = "README.md"
requires-python = ">=3.9"
license = { text = "MIT" }
authors = [{ name = "Sovereign Security Archive Contributors" }]
keywords = ["security", "archive", "scaffolding", "pentest", "soc"]
dependencies = []

[project.scripts]
ssactl = "tools.ssactl.cli:main"

[project.urls]
Homepage = "https://example.invalid/ssa"

[tool.setuptools]
packages = ["tools", "tools.ssactl"]

[tool.ssactl]
schema_dir = "12-schemas"
index_db = "03-wordlists/index/wordlist.db"
crosswalk_dir = "10-crosswalk"
strict = true
'''.lstrip()

FILES["requirements.txt"] = r'''
# Sovereign Security Archive runtime requirements.
# The control plane and all generators are stdlib-only by design so the
# archive can be built on an air-gapped host.

# --- optional developer tooling (uncomment to enable) ---
# ruff>=0.5
# mypy>=1.10
# jsonschema>=4.22      # only needed for `ssactl validate --strict-json`
# pyyaml>=6.0           # only needed for YAML rule linting
'''.lstrip()

# ---------------------------------------------------------------------------
# 00-governance
# ---------------------------------------------------------------------------

FILES["00-governance/charter.md"] = r'''
# Archive Charter

## 1. Purpose

The Sovereign Security Archive (SSA) exists to provide a single, offline,
vendor-neutral body of security knowledge that is **internally consistent**:
offensive techniques, the data required to execute them, and the defensive
controls that detect them live in one repository and reference each other by
stable identifier.

## 2. Scope

In scope:

* Offensive payload corpora, wordlists and evasion catalogues.
* Engagement methodologies and runbooks.
* Host and network detection engineering content.
* Threat intelligence handling and IR process.
* Curriculum, labs and tooling playbooks.

Out of scope:

* Exploit weaponisation against unpatched production systems.
* Credential dumps, PII, or any dataset of real user data.
* Malware source code distribution.

## 3. Design principles

| # | Principle | Consequence in code |
|---|---|---|
| P1 | One identifier per artifact | `12-schemas/*.schema.json` all carry an `id` field |
| P2 | No orphan identifiers | `ssactl verify` scans every crosswalk |
| P3 | No orphan controls | `ssactl verify --coverage` requires ≥1 anchor per `control_id` |
| P4 | Provenance mandatory | `provenance` object required by every schema |
| P5 | Offline first | stdlib-only Python, no network in `init`/`verify`/`index` |
| P6 | Reproducible | generated artifacts are byte-stable, sorted, LF, UTF-8 |

## 4. Domain ownership

Each `NN-*` top-level directory has exactly one accountable Domain Maintainer
(see `CODEOWNERS`). Cross-domain changes require a second reviewer.

## 5. Release cadence

* **Patch** (x.y.z) - data corrections, rule syntax fixes.
* **Minor** (x.y.0) - new upstream ingestion, new domain, schema minor bump.
* **Major** (x.0.0) - taxonomy break; requires a migration map in
  `CHANGELOG.md`.

## 6. Versioning of derived content

Each ingested upstream carries a pinned `ref` in the lock file. Content
provenance strings embed that ref (`PAT@2026-01-15`), so a payload can always
be traced to the exact upstream revision that produced it.

## 7. Authorised use statement

> The material in this archive may be used **only** against systems the
> operator owns or has explicit, written, scope-bound authorisation to test.
> Every engagement must have a signed scope document referenced by the
> engagement identifier. Unauthorised use is a criminal act in most
> jurisdictions, including under CFAA (US), Computer Misuse Act (UK/CA),
> and equivalents in the EU, TR and AU.

## 8. Amendment

Charter changes require an ADR in `14-docs/decisions/` and two Archive
Steward approvals.
'''.lstrip()

FILES["00-governance/threat-model.md"] = r'''
# Threat Model - the archive as a system

## 1. Assets

| Asset | Value | Loss impact |
|---|---|---|
| Detection coverage | Critical | Attacker operates undetected |
| Crosswalk integrity | Critical | Wrong CWE/CVE attribution, missed detections |
| Corpus integrity (payload/wordlist/evasion) | High | Missed detection, false positive storms |
| Upstream provenance | High | Licence violation, irreproducible build |
| Index database (`wordlist.db`) | Medium | Tooling outage, incorrect joins |

## 2. Adversaries

| Adversary | Capability | Objective |
|---|---|---|
| **A1 - Knowledge attacker** | Reads this repo | Finds a detection blind spot, crafts evasion |
| **A2 - Supply-chain poisoner** | Submits PR | Injects a permissive rule or backdoored wordlist |
| **A3 - Upstream drift** | Compromises upstream | Propagates malicious or broken content |
| **A4 - Insider** | Commit access | Silently disable a rule, leak scope data |

## 3. Attack surfaces

### S1 - Detection normalisation gap
A rule matches on `Image` while the technique executes via an interpreter path
that never sets `Image` to the interpreter. `ssactl verify --coverage` cannot
catch semantic gaps; mitigation is mandatory rule review by
`@detection-reviewer` (`CODEOWNERS`).

### S2 - Crosswalk join ambiguity
`(token, cwe_id, context)` collisions merge two different payload semantics into
one index row. Mitigated by `payload_index_key` in
`12-schemas/payload.schema.json` and the UNIQUE constraint in
`03-wordlists/index/schema.sql`.

### S3 - Upstream drift
`PayloadsAllTheThings` gains a new file; nobody notices. Mitigated by
`ssactl diff --upstream` and the release checklist.

### S4 - Licence drift
Content copied from a GPL project into a directory whose consumers assume MIT.
Mitigated by `license` in the lock file and `LICENSE` upstream notice.

### S5 - Unauthorised operational use
The corpus is used against a production system. Mitigated procedurally via
`charter.md` §7 and the engagement scope requirement.

### S6 - Index poisoning
Attacker submits a wordlist entry containing a control character or a 1 MB line
that breaks tokenisation. Mitigated by `wordlist-entry.schema.json`
(`maxLength: 128`, `pattern` disallowing whitespace and control chars).

## 4. Risk register

| ID | Risk | L | I | Score | Mitigation | Residual |
|---|---|---|---|---|---|---|
| R1 | A2 permissive rule | M | H | 12 | 2-reviewer rule, Sigma `status` gate | M |
| R2 | A1 evasion of live rules | H | H | 16 | monthly A1 red-team of own detections | M |
| R3 | A3 drift | H | M | 12 | `diff --upstream` in CI schedule | L |
| R4 | A4 insider | L | H | 8 | CODEOWNERS + signed commits | M |
| R5 | S5 misuse | M | H | 12 | charter, scope, T2 classification | M |
| R6 | S2 join ambiguity | M | M | 6 | UNIQUE key | L |

## 5. Accepted risk

`A1 - Knowledge attacker` is **accepted**. A fully public detection library will
eventually be read by adversaries. The control is *depth and diversity* of
coverage rather than secrecy, and the monthly self-red-team loop in R2.
'''.lstrip()

FILES["00-governance/data-classification.md"] = r'''
# Data Classification

| Level | Name | Handling |
|---|---|---|
| T0 | Public | No restriction. Suitable for public repositories. |
| T1 | Internal | Corporate systems only. No external distribution. |
| T2 | Restricted | Authorised operations only. Encrypted at rest, audit logged. |

## 1. Domain defaults

| Path | Default | Examples of escalation |
|---|---|---|
| `00-governance/` | T0 | - |
| `01-intel/` | T0 | Engagement-specific findings → T2 |
| `02-payloads/` | T0 | Destructive payloads (`DROP`, `mkfs`, `rm -rf /`) → T2 |
| `03-wordlists/` | T0 | Real credential lists harvested from breaches → T2 |
| `04-evasion/` | T0 | - |
| `05-engines/` | T1 | Live C2 configuration → T2 |
| `06-defense/` | T0 | Internal detection logic + asset names → T1 |
| `07-tooling/` | T0 | - |
| `08-threatintel/` | T1 | Actor PII, victim lists, unshared IOCs → T2 |
| `09-labs/` | T0 | - |
| `10-crosswalk/` | T0 | - |
| `11-automation/` | T0 | - |
| `12-schemas/` | T0 | - |
| `13-training/` | T0 | - |
| `14-docs/` | T0 | - |

## 2. Escalation rules

1. Any payload with a destructive or persistent side effect is T2 regardless of
   domain default.
2. Any IOC or credential value is at least T1.
3. Any content revealing internal hostnames, IPs, accounts or rule logic tuned
   to a specific environment is T1.
4. Mix-and-match: a document that aggregates T1 data becomes T1 at the highest
   level encountered.

## 3. Prohibited content

* Live credentials, tokens, private keys.
* Real personal data (names, emails, phone numbers) of individuals.
* Undisclosed vulnerability detail for a dependency the archive depends on
  (disclose privately to the maintainers first).
* Undisclosed incident details of a named organisation.
'''.lstrip()

FILES["00-governance/release-process.md"] = r'''
# Release Process

## 1. Cadence

| Channel | Frequency | Contents |
|---|---|---|
| `main` | continuous | accepted changes |
| `release/x.y` | 4 weeks | stabilisation branch |
| Release | monthly (tag `vX.Y.Z`) | data + rule refresh |
| Emergency | as needed | `vX.Y.Z-hotfix` for detection-critical fixes |

## 2. Checklist (must all pass)

```bash
python tools/ssactl.py verify  --root . --strict
python tools/ssactl.py validate --root .
python tools/ssactl.py index   --root .
python tools/ssactl.py stats   --root .
python tools/ssactl.py diff --upstream --root .
```

Gate matrix:

| Gate | Blocking | Failure code |
|---|---|---|
| Structure | yes | `STRUCT-001` |
| Dangling reference | yes | `REF-001` |
| Schema | yes | `SCHEMA-001` |
| Control coverage | yes | `COV-001` |
| Index determinism | yes | `INDEX-001` |
| Upstream drift | no (warn) | `DRIFT-001` |
| Corpus growth > 20 % | review | `SIZE-001` |

## 3. Version bump rules

* Data-only change → patch.
* New schema field (optional) → minor.
* New required schema field / renamed taxonomy → major + migration map.
* Detection rule change that alters severity → minor, needs detection reviewer.

## 4. Rollback

Reverting is a normal release: tag the previous good commit, re-run gates,
publish `vX.Y.(Z-1)-rollback` and post the reason in `CHANGELOG.md`.
'''.lstrip()

FILES["00-governance/compliance-crosswalk.md"] = r'''
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
'''.lstrip()

FILES["00-governance/manifests/source-repos.lock.json"] = r'''
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "lockfileVersion": 1,
  "archive": "sovereign-security-archive",
  "version": "1.0.0",
  "generatedBy": "ssactl",
  "sources": [
    { "key": "PAT",       "name": "PayloadsAllTheThings",        "owner": "swisskyrepo",         "license": "MIT",           "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",     "pinned_ref": "master@2026-01-15", "landed_in": ["02-payloads"], "role": "Offensive payload corpus" },
    { "key": "SECLISTS",  "name": "SecLists",                     "owner": "danielmiessler",      "license": "MIT",           "url": "https://github.com/danielmiessler/SecLists",              "pinned_ref": "master@2026-01-14", "landed_in": ["03-wordlists"], "role": "Discovery and credential wordlists" },
    { "key": "GTFOBINS",  "name": "GTFOBins",                     "owner": "GTFOBins",            "license": "MIT",           "url": "https://github.com/GTFOBins/GTFOBins",                      "pinned_ref": "master@2026-01-12", "landed_in": ["04-evasion"], "role": "Trusted-binary abuse catalogue" },
    { "key": "HACKTRICKS","name": "HackTricks",                   "owner": "carlospolop",         "license": "GPL-3.0",       "url": "https://github.com/carlospolop/HackTricks",                 "pinned_ref": "master@2026-01-13", "landed_in": ["01-intel/playbooks", "01-intel/methodologies"], "role": "Technique runbooks" },
    { "key": "BOSK",      "name": "Book of Secret Knowledge",     "owner": "dmknght",             "license": "CC0-1.0",       "url": "https://github.com/dmknght/BookOfSecretKnowledge",         "pinned_ref": "master@2026-01-10", "landed_in": ["01-intel/cheat-sheets"], "role": "Operator toolbox" },
    { "key": "H4CKER",    "name": "The Art of Hacking",          "owner": "The-Art-of-Hacking",  "license": "GPL-3.0",       "url": "https://github.com/The-Art-of-Hacking/h4cker",             "pinned_ref": "master@2026-01-09", "landed_in": ["01-intel/playbooks"], "role": "Deep technical curriculum" },
    { "key": "90DAYS",    "name": "90 Days of Cyber Security",    "owner": "0xDigit",             "license": "MIT",           "url": "https://github.com/0xDigit/90-Days-of-Cybersecurity",    "pinned_ref": "master@2026-01-11", "landed_in": ["13-training"], "role": "Onboarding curriculum" },
    { "key": "AWEHACK",   "name": "Awesome Hacking",             "owner": "0xdea",               "license": "CC0-1.0",       "url": "https://github.com/0xdea/awesome-hacking",                 "pinned_ref": "master@2026-01-08", "landed_in": ["09-labs"], "role": "Operator tool index" },
    { "key": "AWEPENTEST","name": "Awesome Pentest",             "owner": "j0hnx3r",            "license": "CC0-1.0",       "url": "https://github.com/j0hnx3r/awesome-pentest",             "pinned_ref": "master@2026-01-07", "landed_in": ["01-intel/methodologies", "06-defense/blue-team"], "role": "Engagement workflow" },
    { "key": "AWEIR",     "name": "Awesome Incident Response",   "owner": "meirwah",             "license": "CC0-1.0",       "url": "https://github.com/meirwah/awesome-incident-response",    "pinned_ref": "master@2026-01-06", "landed_in": ["06-defense/ir", "09-labs/emulations"], "role": "IR playbooks" },
    { "key": "AWETI",     "name": "Awesome Threat Intelligence", "owner": "amittmadan",          "license": "CC0-1.0",       "url": "https://github.com/amittmadan/awesome-threat-intelligence", "pinned_ref": "master@2026-01-05", "landed_in": ["08-threatintel"], "role": "CTI pipeline" },
    { "key": "MSF",       "name": "Metasploit Framework",        "owner": "rapid7",              "license": "BSD-3-Clause",  "url": "https://github.com/rapid7/metasploit-framework",        "pinned_ref": "2026.01-rc1",       "landed_in": ["05-engines/metasploit"], "role": "Exploitation engine" },
    { "key": "SQLMAP",    "name": "sqlmap",                      "owner": "sqlmapproject",       "license": "GPL-2.0",       "url": "https://github.com/sqlmapproject/sqlmap",                   "pinned_ref": "1.9.1",            "landed_in": ["05-engines/sqlmap", "02-payloads/web/sqli"], "role": "SQLi automation" },
    { "key": "SHERLOCK",  "name": "Sherlock",                     "owner": "sherlock-project",    "license": "MIT",           "url": "https://github.com/sherlock-project/sherlock",             "pinned_ref": "master@2026-01-05", "landed_in": ["05-engines/osint"], "role": "Handle OSINT" },
    { "key": "IMHEX",     "name": "ImHex",                       "owner": "WerWolv",             "license": "GPL-2.0",       "url": "https://github.com/WerWolv/ImHex",                         "pinned_ref": "v3.1.0",           "landed_in": ["07-tooling/imhex"], "role": "Binary forensics" },
    { "key": "WAZUH",     "name": "Wazuh",                       "owner": "wazuh",               "license": "GPL-2.0",       "url": "https://github.com/wazuh/wazuh",                           "pinned_ref": "v4.9.0",           "landed_in": ["06-defense/wazuh"], "role": "Host XDR" },
    { "key": "SURICATA",  "name": "Suricata",                    "owner": "OISF",                "license": "GPL-2.0",       "url": "https://github.com/OISF/suricata",                          "pinned_ref": "7.0.10",           "landed_in": ["06-defense/suricata"], "role": "Network IDS/IPS" },
    { "key": "CYBERCHEF", "name": "CyberChef",                   "owner": "gchq",                "license": "Apache-2.0",    "url": "https://github.com/gchq/CyberChef",                         "pinned_ref": "v10.42.0",         "landed_in": ["07-tooling/cyberchef"], "role": "Data transformation" },
    { "key": "OWASPCS",   "name": "OWASP Cheat Sheet Series",    "owner": "OWASP",               "license": "CC-BY-SA-4.0",  "url": "https://github.com/OWASP/CheatSheetSeries",                 "pinned_ref": "master@2026-01-14", "landed_in": ["01-intel/cheat-sheets/owasp", "06-defense/blue-team"], "role": "Control catalogue" },
    { "key": "PSCL",      "name": "Personal Security Checklist", "owner": "0xNaN",               "license": "MIT",           "url": "https://github.com/0xNaN/personal-security-checklist",     "pinned_ref": "master@2025-11-20", "landed_in": ["01-intel/checklists", "06-defense/hardening"], "role": "Individual baseline" }
  ]
}
'''.lstrip()