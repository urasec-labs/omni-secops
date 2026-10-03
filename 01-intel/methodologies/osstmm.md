# OSSTMM - Operational Security Testing Methodology Mapping

| Field | Value |
|---|---|
| `methodology_id` | MTH-OSSTMM |
| `version` | 3.x |
| `url` | http://www.osstmm.org/ |

## 1. Phase mapping into the archive

| OSSTMM phase | Activity | Archive location | Output |
|---|---|---|---|
| 1 Network Rules | Map rules, ports, trust boundaries | `01-intel/playbooks/network/service-enumeration.md` | Rule map |
| 2 Network Map | Discover hosts and services | `03-wordlists/network/` | Asset inventory |
| 3 Network Service Identification | Fingerprint daemons | `03-wordlists/network/banners.txt` | Service matrix |
| 4 Service Enumeration | Enumerate each service | `01-intel/playbooks/network/` | Per-service notes |
| 5 Service Component Identification | Components and versions | `02-payloads/` | Version matrix |
| 6 Service Attack | Test vulnerabilities | `02-payloads/`, `05-engines/` | Findings |
| 7 Post Attack | Lateral movement, privesc | `04-evasion/`, `01-intel/playbooks/active-directory/` | Access paths |
| 8 Organisation | Social / process | `01-intel/cheat-sheets/book-of-secret-knowledge.md` | Process findings |

## 2. RAV scoring

`RAV = (Vulnerability severity x Exploitability) + (Detection difficulty x Impact)`

Report ordering is by RAV, not by scanner severity. Store the score in the
finding record so `13-training/assessments` can grade consistency.

## 3. Evidence requirement

Every test in every phase must leave evidence: command line, timestamp,
request/response pair. `06-defense/ir/` and `05-engines/` both expect this
format; see `14-docs/standards/knowledge-format.md` §4.
