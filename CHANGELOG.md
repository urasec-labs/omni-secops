# Changelog - All notable changes to the Sovereign Security Archive.

Format follows Keep a Changelog. Versions follow Semantic Versioning.

## [1.0.0] - 2026-01-15

### Added
- Initial consolidation of 20 upstream archives into 15 top-level domains.
- `10-crosswalk/` integration layer with four mappings:
  wordlist↔payload, evasion↔module↔runbook, control↔detection, attack coverage.
- `12-schemas/` JSON Schema (draft 2020-12) for payload, wordlist entry,
  evasion primitive, detection, IOC and crosswalk row.
- `03-wordlists/index/wordlist.db` SQLite + FTS5 unified corpus index and the
  `build_payload_index.py` generator.
- `06-defense/` Suricata ruleset (web, evasion, exfiltration), Wazuh baseline
  ruleset with custom decoder, Sigma detection library.
- `13-training/` three-phase 90-day curriculum plus red/blue/secops tracks.
- `ssactl` control plane (init / verify / validate / index / stats / diff) and
  `bootstrap.ps1` PowerShell 5.1 entry point.

### Changed
- N/A - first release.

### Known issues
- `ssactl diff --upstream` requires network access; offline runs report DRIFT-UNKNOWN.
