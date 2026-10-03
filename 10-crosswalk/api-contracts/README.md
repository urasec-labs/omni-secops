# API Contracts

The archive is consumed by tools. This directory defines the contracts those
tools may rely on. Anything not described here is an implementation detail and
may change without a major version bump.

## 1. Artefacts and their consumers

| Artefact | Format | Producer | Consumers |
|---|---|---|---|
| `02-payloads/**/payloads.json` | `12-schemas/payload.schema.json` | humans (reviewed) | `ssactl index`, `render_crosswalks` |
| `03-wordlists/**.txt` | one token per line | upstream ingestion | `ffuf`, `hydra`, `sqlmap` |
| `03-wordlists/index/wordlist.db` | SQLite 3.35+ | `ssactl index` | SQL clients, scripts |
| `04-evasion/index/evasion-index.csv` | CSV | humans | `render_crosswalks`, docs |
| `06-defense/suricata/rules/*.rules` | Suricata rule syntax | humans | Suricata |
| `06-defense/wazuh/rules/*.xml` | Wazuh `<group>` XML | humans | Wazuh manager |
| `06-defense/sigma/*.yml` | Sigma 2.0 | humans | SIEM converters |
| `10-crosswalk/*.csv` | CSV, header required | `render_crosswalks` | docs, audits |
| `08-threatintel/ioc/*.json` | `12-schemas/ioc.schema.json` | feeds + humans | SIEM, proxies |

## 2. CSV dialect (normative)

* Encoding UTF-8, LF endings, **no** BOM.
* First row is a header, snake_case.
* No trailing spaces in fields.
* A field may contain `|` as a multi-value separator (never `,`).
* Empty field = not applicable; the string `n/a` is only allowed where the
  schema says so.
* Line ordering is deterministic (sorted by the join key) so `git diff` stays
  readable and the manifest hash stays stable.

## 3. Schema compatibility

* Schemas declare `$id` and `$schema: https://json-schema.org/draft/2020-12/schema`.
* Adding an **optional** property is a minor change.
* Adding a **required** property or changing a pattern is a major change and
  requires a `CHANGELOG.md` entry plus a migration note in
  `14-docs/standards/knowledge-format.md`.
* Every schema has a `$comment` stating which validator features it needs.

## 4. The unified index contract

`03-wordlists/index/wordlist.db` promises:

| Promise | Guarantee |
|---|---|
| Stable schema | `index_meta.schema_version` |
| Deterministic build | same inputs -> byte-identical logical content |
| Idempotent | `ssactl index` twice == once |
| Transactional | a failed build leaves the previous DB intact (temp file + rename) |
| Recoverable | `wordlist.db` is git-ignored and rebuildable from committed sources |
