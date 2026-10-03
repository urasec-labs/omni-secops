# OWASP Cheat Sheet Series - Control Ingestion

| Field | Value |
|---|---|
| `catalog_id` | OWASP-CS |
| `source` | OWASP/CheatSheetSeries |
| `license` | CC-BY-SA-4.0 |
| `ingest` | `01-intel/cheat-sheets/owasp/owasp-controls.csv` |

## 1. Why a CSV and not just markdown

The upstream cheat sheets are prose. The archive needs them as **identifiable,
severity-bearing, detection-anchored rows** so that `06-defense/` can be proven
complete against them. `owasp-controls.csv` is that projection.

## 2. Column contract

| Column | Type | Notes |
|---|---|---|
| `control_id` | string | `<SHEET>-<N>`, e.g. `CSRF-2` |
| `sheet` | string | Upstream file slug |
| `title` | string | Control statement, trimmed to 120 chars |
| `severity` | enum | critical / high / medium / low / info |
| `cwe_id` | string | optional |
| `owasp_top10` | string | 2021 category |
| `anchor_layer` | enum | network / host / audit / application |
| `anchor_id` | string | sid, Wazuh rule id or sigma rule id |
| `provenance` | string | `OWASPCS@master@2026-01-14` |

## 3. Sheets ingested

| Sheet | Control prefix | Example control |
|---|---|---|
| Authentication | AUTH | AUTH-7 - generic error messages |
| Authorization | AUTHZ | AUTHZ-3 - enforce server-side checks |
| Session Management | SESSION | SESSION-4 - cookie attributes |
| Cross Site Request Forgery | CSRF | CSRF-2 - per-request token |
| Input Validation | INPUT | INPUT-4 - server-side validation |
| Injection Prevention | INJ | INJ-1 - parameterised queries |
| XSS Prevention | DOM | DOM-1 - context-aware output encoding |
| Deserialization | DES | DES-3 - cryptographic integrity |
| File Upload | UPL | UPL-2 - extension allow-list |
| Logging | LOG | LOG-4 - log injection prevention |
| Cryptographic Storage | CRYPTO | CRYPTO-1 - modern algorithms |
| Secrets Management | SECRETS | SECRETS-3 - rotation |
| REST Security | REST | REST-1 - HTTPS only |
| GraphQL | GQL | GQL-2 - introspection disabled in prod |
| LLM Prompt Injection | LLM | LLM-01 - segregate untrusted content |

## 4. Coverage rule

`ssactl verify --coverage` fails when any row has an empty `anchor_id`. Adding a
control without a detection is not allowed; adding a control *and* a rule is
the required unit of work.

## 5. Update procedure

```bash
# 1. refresh the upstream checkout pinned in the lock file
git -C .upstream/CheatSheetSeries pull
# 2. regenerate the CSV from the upstream markdown
python tools/ssactl.py index --root . --refresh-owasp
# 3. re-verify: new controls will appear as COV-001 failures until anchored
python tools/ssactl.py verify --root . --coverage
```
