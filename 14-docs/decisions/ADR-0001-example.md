# ADR-0001 - Canonical identifiers and a single crosswalk spine

| Field | Value |
|---|---|
| `adr_id` | ADR-0001 |
| `status` | accepted |
| `date` | 2026-01-15 |
| `deciders` | archive steward, detection reviewer, knowledge maintainer |

## Context

The twenty upstream archives have no shared vocabulary. PayloadsAllTheThings
identifies payloads by file and heading; SecLists identifies words by line
number; GTFOBins identifies entries by binary name; the OWASP cheat sheets
identify controls by prose; Suricata and Wazuh use unrelated numeric ids.
Merging them without an identifier scheme produces a folder of files that a
tool cannot consume and a reviewer cannot cross-check.

Two options were considered:

1. **Copy-and-merge** - dump everything into a themed tree, keep upstream
   identifiers. Cheap, but no integration is possible and references break on
   the next upstream change.
2. **Normalise with a canonical identifier layer** - assign stable `PL-*`,
   `EV-*`, `control_id`, `PB-*` identifiers in the archive, keep the upstream
   content behind a provenance header, and express every relationship as a row
   in `10-crosswalk/`.

## Decision

Adopt option 2.

* Each domain owns a prefix namespace (`10-crosswalk/README.md` §3).
* Identifiers are stable for the life of the archive and are never reused.
* All relationships live in CSV files under `10-crosswalk/`, not in prose.
* Machine readable artefacts validate against `12-schemas/`.
* `ssactl verify` fails the build on a dangling or orphaned identifier.

## Consequences

Positive:

* A detection can be traced to a control, a technique, a payload and an
  upstream source with a single query.
* Coverage can be measured objectively (`--coverage`), not asserted.
* Upstream changes are detectable (`diff --upstream`) and attributable
  (provenance headers).

Negative:

* Every upstream ingestion requires an assignment pass, not a copy.
* Identifiers must be maintained forever; removing a payload leaves a tombstone.
* The verifier must be maintained alongside the schemas.

Neutral:

* The archive is bigger to build (a few seconds) but identical to run offline.

## Alternatives rejected

* **Git submodules only** - no integration, no validation, upstream refs move.
* **A database-first design (no files)** - loses reviewability and diffability,
  which are the main reasons to keep knowledge in a repository.
* **Auto-generated ids from content hashes** - ids change whenever a payload is
  whitespace-normalised, which breaks every crosswalk row.

## Revisit when

* The identifier count exceeds ~50 000 (consider two-level partitioning).
* A third enforcement engine is added (extend `render_crosswalks.py`).
* An external consumer requires stable URLs into the archive (add anchors).
