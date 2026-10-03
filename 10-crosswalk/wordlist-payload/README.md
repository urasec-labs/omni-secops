# Wordlist to Payload Crosswalk

## 1. The problem this solves

SecLists gives you `UNION SELECT NULL,NULL` in `SQL-Injection.txt` with no
knowledge of whether it targets MySQL, MSSQL or a PHP parameter. PayloadsAllTheThings
gives you a rich record with `engine`, `context`, `surface` and `severity` but
you must know the id to find it. The archive needs one table where a
fuzzing tool and a payload library meet.

## 2. Join rule (normative)

Two records unify when **all** hold:

```
sha256(normalise(a.token)) == sha256(normalise(b.payload))
AND a.surface == b.surface
AND a.cwe_id == b.cwe_id
AND a.context == b.context
```

where

```python
def normalise(t: str) -> str:
    t = unicodedata.normalize("NFC", t)   # unicode canonical form
    t = t.strip()                          # leading/trailing whitespace
    t = re.sub(r"\s+", " ", t)             # collapse internal whitespace
    t = t.strip("'\"")                     # surrounding quotes
    return t
```

A wordlist entry that cannot be attributed to a CWE/context is recorded with
`origin=fuzz`, `payload_id` empty and `confidence=0.4`. It is still indexed,
so a consumer can distinguish "known injection token" from "blind guess".

## 3. Confidence model

| `origin` | Meaning | `confidence` |
|---|---|---|
| `both` | present in SecLists *and* PAT with matching normalisation | 1.0 |
| `payload` | PAT only, no wordlist equivalent | 0.6 |
| `fuzz` | SecLists only, unattributed | 0.4 |

## 4. Consumption examples

```bash
# export the highest-confidence SQLi tokens for a parameter surface
python - <<'PY'
import csv
rows = [r for r in csv.DictReader(open('10-crosswalk/wordlist-payload/crosswalk.csv'))
        if r['cwe_id'] == 'CWE-89' and r['surface'] == 'parameter']
for r in sorted(rows, key=lambda r: -float(r['confidence'] or 0)):
    print(r['confidence'], r['token'][:60])
PY
```

```bash
# feed ffuf directly
cut -d, -f4 10-crosswalk/wordlist-payload/crosswalk.csv | grep -v '^$' | \
  sort -u > /tmp/ssa-words.txt
ffuf -w /tmp/ssa-words.txt -u https://TARGET/FUZZ -mc all -ac
```

## 5. Maintenance

This file is **generated** by `11-automation/scripts/build_payload_index.py`
from the payload JSON files plus the wordlist exports. Edit the generators and
the payload corpus, never this file.
