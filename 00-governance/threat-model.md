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
