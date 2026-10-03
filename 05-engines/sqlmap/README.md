# sqlmap Engine Integration

| Field | Value |
|---|---|
| `engine_id` | ENG-SQLMAP |
| `source` | sqlmapproject/sqlmap @ 1.9.1 |
| `license` | GPL-2.0 |
| `payload_corpus` | `02-payloads/web/sqli/` |
| `fuzz_wordlist` | `03-wordlists/web/fuzzing/injection-words.txt` |

## 1. Purpose

sqlmap is the archive's reference automation for `CWE-89`. The archive's job is
to make sqlmap's behaviour **explicit and reproducible**: which payload family
produces which result, which tamper script maps to which bypass, and which
detection fires.

## 2. Baseline invocation

```bash
sqlmap -u "https://TARGET/?id=1" \
       --batch --random-agent \
       --level=3 --risk=1 \
       --technique=BEUST \
       --dbms= \
       --string="Welcome back" \
       --tamper=space2comment \
       --output-dir=/tmp/ssactl-evidence/sqmap
```

Escalate `level`/`risk` only after recording the level at which the target
becomes unstable.

## 3. Evidence contract

sqlmap writes a filesystem dump by default. For the archive's reporting format:

```bash
python tools/ssactl.py verify --root .
# store only the request file and the first-row output; everything else is T1/T2
cp /tmp/ssactl-evidence/sqmap/10.10.10.5/log /secure/evidence/SSA-<ID>-sqlmap.log
```

## 4. Tamper library

See `tamper/tamper-library.md`. Mapping to `02-payloads/web/sqli/payloads.json`:

| Tamper | Payload family | Purpose |
|---|---|---|
| `space2comment` | `PL-WEB-SQLI-0002` | replace space with `/**/` |
| `space2hash` | MySQL | replace space with `#` |
| `charencode` | `PL-WEB-SQLI-0050` | URL-encode single quote |
| `between` | `PL-WEB-SQLI-0010` | replace `=` with `BETWEEN` |
| `randomcase` | `PL-WEB-SQLI-0001` | random case of `OR` |
| `randomcomments` | all | inject inline comments |
| `versionedmorekeywords` | MySQL | `/*! ... */` |
| `chardoubleencode` | `PL-WEB-SQLI-0090` | double URL-encode |

## 5. Safety rails

| Rail | Reason |
|---|---|
| `--technique=BEUST` before allowing `E` (stacked queries) | `E` can write data |
| `--dbs` before any `DROP`/`UPDATE` | Data destruction |
| never `--os-shell` on production | Command execution |
| always `--batch` + `--output-dir` | Non-interactive + evidence |
| keep `--threads` ≤ 3 for stateful targets | Session integrity |

## 6. Exit criteria

| Stage | Done when |
|---|---|
| Fingerprint | `dbms`, `dbms_version`, `os`, `current user` known |
| Columns | column count and names enumerated |
| Extent | row count known for the target table only |
| Extraction | stopped at the minimum required by RoE |
| Detection | at least one `ssa_web_sqli_probe.yml` alert observed |
