# sqlmap Tamper Script Crosswalk

| Tamper script | Purpose | Payload ids | Fails against |
|---|---|---|---|
| `space2comment` | `or 1=1` -> `or/**/1=1` | `PL-WEB-SQLI-0001` | WAFs blocking `/**/` |
| `space2hash` | space -> `#` (MySQL only) | `PL-WEB-SQLI-0003` | PostgreSQL, MSSQL, Oracle |
| `space2plus` | space -> `+` | `PL-WEB-SQLI-0002` | strict parsers |
| `space2randomblank` | space -> random blanks | `PL-WEB-SQLI-0001` | WAFs normalising whitespace |
| `between` | `=` -> `BETWEEN` | `PL-WEB-SQLI-0010` | numeric-only columns |
| `randomcase` | random keyword case | `PL-WEB-SQLI-0001` | case-sensitive engines |
| `charencode` | URL-encode `'` | `PL-WEB-SQLI-0090` | double-decode absent |
| `chardoubleencode` | double URL-encode | `PL-WEB-SQLI-0090` | servers decoding once |
| `percentage` | space -> `%20` | `PL-WEB-SQLI-0002` | non-HTTP contexts |
| `unionall` | `UNION SELECT` -> `UNION ALL SELECT` | `PL-WEB-SQLI-0020` | - |
| `versionedmorekeywords` | MySQL `/*! */` | `PL-WEB-SQLI-0050` | non-MySQL |
| `versionedgreaterthan` | `>` -> `/*! >*/` | `PL-WEB-SQLI-0010` | non-MySQL |
| `randomcomments` | inject `--`, `/* */`, `#` | all | aggressive WAF |
| `appendnull` | `%00` terminator | `PL-WEB-SQLI-0004` | modern engines |
| `equaltolike` | `=` -> `LIKE` | `PL-WEB-SQLI-0010` | - |
| `lowercase` | lowercase everything | `PL-WEB-SQLI-0001` | - |
| `uppercase` | uppercase everything | `PL-WEB-SQLI-0001` | - |
| `truncation` | truncate to 1 char | - | desync bugs |
| `space2mysqldash` | space -> MySQL `-- -` | `PL-WEB-SQLI-0003` | requires `-- -` suffix |

## Combination strategy

```bash
# WAF present, MySQL, keyword based
sqlmap -u "$URL" --tamper="space2comment,between,randomcomments" --technique=BEUS

# WAF present, generic
sqlmap -u "$URL" --tamper="between,randomcase,space2comment,charencode,space2hash"
```

## Adding a new tamper mapping

1. Record the tamper script in this table.
2. Ensure at least one `payload_id` in `02-payloads/web/sqli/payloads.json`
   represents the shape it produces.
3. Add a row to `10-crosswalk/wordlist-payload/crosswalk.csv`.
4. `python tools/ssactl.py verify --root . --strict`
