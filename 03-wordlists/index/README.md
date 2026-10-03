# Unified Corpus Index

`03-wordlists/index/wordlist.db` is the single optimised database that every
tool in the archive reads. It merges two corpora that upstream keep separate:

* **SecLists** - flat text files: one token per line.
* **PayloadsAllTheThings** - structured JSON records with CWE, context and
  surface metadata.

## 1. Schema

```
CREATE TABLE token (
    token_id     INTEGER PRIMARY KEY,
    token        TEXT NOT NULL,
    surface      TEXT NOT NULL,          -- parameter|header|cookie|url|path|body
    length       INTEGER NOT NULL,
    sha256       TEXT NOT NULL,
    UNIQUE (sha256, surface)
);

CREATE TABLE payload (
    payload_id   TEXT PRIMARY KEY,
    token_id     INTEGER NOT NULL REFERENCES token(token_id),
    cwe_id       TEXT NOT NULL,
    context      TEXT NOT NULL,
    engine       TEXT,
    severity     TEXT NOT NULL,
    classification TEXT NOT NULL,
    tags         TEXT NOT NULL           -- JSON array
);

CREATE TABLE fuzz_token (
    token_id     INTEGER NOT NULL REFERENCES token(token_id),
    payload_id   TEXT    NOT NULL REFERENCES payload(payload_id),
    origin       TEXT    NOT NULL CHECK (origin IN ('fuzz','payload','both')),
    confidence   REAL    NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    PRIMARY KEY (token_id, payload_id)
);

CREATE TABLE evasion (
    evasion_id   TEXT PRIMARY KEY,
    platform     TEXT NOT NULL,
    binary       TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    primitive    TEXT NOT NULL
);

CREATE VIRTUAL TABLE token_fts USING fts5(token, content='token', content_rowid='token_id');

CREATE INDEX ix_payload_cwe   ON payload(cwe_id, context);
CREATE INDEX ix_fuzz_conf     ON fuzz_token(confidence);
CREATE INDEX ix_evasion_tech  ON evasion(technique_id);
```

## 2. The merge rule

A SecLists line and a PayloadsAllTheThings payload unify when **all** of these
hold:

1. `sha256(normalised_token)` is equal - normalisation = strip, collapse
   internal whitespace, unquote, NFC unicode.
2. `surface` is equal.
3. `cwe_id` and `context` are equal, or the wordlist entry is `surface`-only and
   inherits the payload's `cwe_id`/`context` (this is the `origin='fuzz'` case).

Unified rows get `origin='both'` and `confidence=1.0`; single-source rows keep
`0.6` (payload-only) or `0.4` (wordlist-only).

## 3. Queries

```sql
-- all injection tokens for a PHP parameter, deduped
SELECT DISTINCT t.token, p.context, f.origin, f.confidence
FROM   fuzz_token f
JOIN   token      t ON t.token_id   = f.token_id
JOIN   payload    p ON p.payload_id = f.payload_id
WHERE  p.cwe_id='CWE-89' AND t.surface='parameter'
ORDER  BY f.confidence DESC, LENGTH(t.token);

-- surfaces not covered by any payload (blind spot report)
SELECT DISTINCT t.token, t.surface
FROM token t LEFT JOIN fuzz_token f ON f.token_id=t.token_id
WHERE f.token_id IS NULL;

-- coverage of the injection corpus
SELECT cwe_id, COUNT(*) n FROM payload GROUP BY cwe_id ORDER BY n DESC;
```

## 4. Building and verifying

```bash
python tools/ssactl.py index --root .            # build
python tools/ssactl.py index --root . --check    # fail if the DB is stale
python tools/ssactl.py index --root . --stats    # human readable summary
```

`--check` compares the content hash recorded in
`00-governance/manifests/ssa-manifest.json` against the DB and exits `2` when
they diverge - that is the `INDEX-001` gate.

## 5. Consumers

| Consumer | Query |
|---|---|
| `ffuf` | `SELECT token FROM token WHERE surface='path' AND length BETWEEN 3 AND 12` |
| `sqlmap` | `--tamper` selection from `payload.context` |
| `hydra` | `SELECT token FROM token WHERE surface='parameter' AND cwe_id IS NULL` (username set) |
| Sigma generation | `SELECT payload_id, cwe_id FROM payload` joined with `fuzz_token` |

Note that `ffuf`, `sqlmap` and `hydra` cannot execute SQL. They consume the
derived exports written next to the DB:

* `03-wordlists/index/export/fuzz-words.txt`
* `03-wordlists/index/export/injection-contexts.csv`
