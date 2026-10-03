# IOC Normalisation Contract

Machine readable schema: `12-schemas/ioc.schema.json`.
This page explains the decisions; the schema is the authority.

## 1. Observable types

| `observable_type` | Meaning | Validation |
|---|---|---|
| `ipv4` | IPv4 address | dotted quad, no leading zeros |
| `ipv6` | IPv6 address | RFC 4291 compressed form |
| `domain` | FQDN | lowercase, IDNA punycode, <= 253 |
| `url` | full URL | scheme + host + optional path |
| `file` | hash | sha256/md5/sha1/imphash |
| `email` | mailbox | RFC 5322 minimal |
| `registry` | Windows registry key | `HKLM\...` form |
| `mutex` | named mutex | literal |
| `user-agent` | HTTP UA | literal |

## 2. Mandatory fields

```json
{
  "id": "IOC-2026-000001",
  "type": "domain",
  "value": "malicious.example",
  "confidence": 90,
  "severity": "high",
  "source": "FEED-002",
  "first_seen": "2026-01-14T00:00:00Z",
  "last_seen": "2026-01-15T00:00:00Z",
  "tlp": "amber",
  "tags": ["c2", "phishing"],
  "mitre": ["T1071.001"],
  "expires": "2026-04-15T00:00:00Z",
  "context": "observed in DNS exfiltration sample SSA-2026-0007"
}
```

## 3. Rules that prevent alert fatigue

1. **Never block on `confidence < 70` with reliability `C`.** Score it.
2. **Always set `expires`.** IOCs rot; an unbounded IOC list is a false-positive
   generator within a year.
3. **Prefer infrastructure indicators** (`ipv4`, `domain`) over file hashes for
   blocking: hashes do not survive a rebuild.
4. **Store the source feed id**, never only the name - feeds get replaced.
5. **TLP markings are respected end to end** (see `08-threatintel/README.md`).

## 4. Validation

```bash
python tools/ssactl.py validate --root .
# or, with the optional jsonschema dependency
pip install jsonschema
python tools/ssactl.py validate --root . --strict-json
```
