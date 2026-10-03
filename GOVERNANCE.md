# Governance

## 1. Roles

| Role | Duty | Quorum |
|---|---|---|
| Archive Steward | Merges taxonomy changes, owns `spec.py` | 2 |
| Domain Maintainer | Owns one top-level domain (`0X-*/`) | 1 per domain |
| Detection Reviewer | Approves anything under `06-defense/` | 1, never the author |
| Legal Reviewer | Approves new upstream ingestion | 1 |

## 2. Change control

1. Issue an ADR under `14-docs/decisions/ADR-NNNN-slug.md` for taxonomy changes.
2. Open a pull request touching at most one top-level domain plus `10-crosswalk/`.
3. CI must be green: `ssactl verify`, `ssactl validate`, `ssactl index --check`.
4. A Domain Maintainer from a *different* domain approves cross-domain changes.

## 3. Upstream ingestion

New sources enter only through `00-governance/manifests/source-repos.lock.json`.
The lock file records `name`, `owner`, `url`, `license`, `pinned_ref` and the
`landed_in` directories. `ssactl diff --upstream` compares pinned refs with the
network and opens a drift report when they diverge.

## 4. Back-pressure rules

* An upstream file is **never** copied verbatim without a `provenance` header.
* Normalisation happens in `11-automation/scripts/`; the raw upstream stays in
  the git submodule referenced by the lock file.
* Corpus growth is capped per release: >20 % size increase requires a
  `CHANGELOG.md` entry explaining the delta.

## 5. Incident handling for the archive

The archive itself is a security product. Reports go to `SECURITY.md` and are
triaged as Sev1 when the issue enables an attacker to silently corrupt a
detection rule or suppress an index entry.
