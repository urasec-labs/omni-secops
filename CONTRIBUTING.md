# Contributing

## 1. Golden rules

1. **One identifier per artifact.** Every payload, wordlist family, evasion
   primitive, control and detection carries a stable ID (`payload_id`,
   `token_id`, `EV-*`, `control_id`, `detection_id`).
2. **No orphan identifiers.** If you introduce an ID you must reference it from
   at least one crosswalk, or `ssactl verify` fails.
3. **No prose-only additions to data domains.** `02-`, `03-`, `04-`,
   `05-`, `06-defense/`, `08-` are machine readable; add schema-valid data.
4. **Provenance or nothing.** Every derived file starts with a provenance
   header naming the upstream project and pinned ref.

## 2. Adding a payload

```json
{
  "payload_id": "PL-WEB-SQLI-0001",
  "schema": "12-schemas/payload.schema.json",
  "cwe_id": "CWE-89",
  "context": "query",
  "surface": "parameter",
  "engine": "generic",
  "payload": "' OR 1=1-- -",
  "severity": "high",
  "tags": ["auth-bypass", "union"],
  "provenance": { "source": "PAT", "ref": "master@2026-01-15" }
}
```

Then add the matching fuzz token to `03-wordlists/web/fuzzing/` and a row to
`10-crosswalk/wordlist-payload/crosswalk.csv`.

## 3. Adding a detection

```yaml
id: ssa_l001_persistence_authorized_keys_write
status: experimental
title: OpenSSH authorized_keys modified
logsource: { product: linux, service: sshd }
detection:
  selection_authorized: { TargetFilename|contains: '/.ssh/authorized_keys' }
  selection_write: { EventID: 2 }
  condition: selection_authorized and selection_write
fields: [TargetFilename, User, Image]
falsepositives: [Configuration management, break-glass account provisioning]
level: high
tags: [attack.persistence, attack.t1098.004]
```

Add the matching `control_id` in `06-defense/blue-team/controls/controls.csv`
and reference it from `10-crosswalk/control-detection/control-detection.csv`.

## 4. Local checks

```bash
python tools/ssactl.py verify --root . --strict
python tools/ssactl.py validate --root .
python tools/ssactl.py index --root .
```

## 5. Style

* Markdown: one H1 per file, fenced code blocks carry a language.
* YAML: two-space indent, no tabs, LF endings.
* Python: stdlib only for `tools/ssactl`; 3.9+ compatible.
* Every directory must have a `README.md`. `ssactl` generates missing ones from
  `tools/ssactl/spec.py`, but hand-written ones always win.
