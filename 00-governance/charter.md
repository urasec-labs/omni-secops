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
