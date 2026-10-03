# Frequently Asked Questions

## Scope and purpose

**Why merge twenty repositories instead of just cloning them?**
Because upstream keeps offensive data, defensive detections and methodology
disconnected. The value of this archive is the mapping: a payload id resolves to
a wordlist token, a technique, a module, and the rules that detect it. Cloning
gives you the parts without the wiring.

**Is this a superset of every upstream project?**
No, and it never will be. The archive keeps the material needed for a
consistent crosswalk and points at the upstream repository for everything else.
`00-governance/manifests/source-repos.lock.json` is the authoritative list of
what was ingested and at which revision.

**Which upstream revision am I reading?**
Run `python tools/ssactl.py diff --upstream --root .` for a drift report, or
read the `pinned_ref` field in the lock file.

## Legal and safety

**Can I use the payloads against systems I do not own?**
No. Doing so is a criminal offence in most jurisdictions. See
`00-governance/charter.md` §7. The archive is for authorised testing, detection
research and education.

**Are the payloads weaponised?**
They are the same payloads that appear in public security tooling. Some records
are classified `T2` because they have destructive or persistent side effects;
`00-governance/data-classification.md` explains the tiers.

**Can I commit real findings into this archive?**
No. Findings are `T1` or `T2` and live in the case management system, not git.
The archive stores the *method*, not the *engagement*.

## Technical

**Do I need Python?**
For scaffolding and verification, yes: 3.9+ standard library. `bootstrap.ps1`
needs only PowerShell 5.1 and will tell you if Python is missing. Detection
rules are consumed by Suricata and Wazuh, which have their own runtimes.

**Why SQLite instead of a flat file?**
Because the join is a real join. A flat merged file cannot answer "which
injection tokens apply to a *header* surface for *PostgreSQL* in a *query*
context" without re-parsing. `03-wordlists/index/README.md` §3 has the queries.

**The index database is git-ignored. How do I get it?**
Run `python tools/ssactl.py index --root .`. It is fully rebuildable from
committed sources - that is the point of the determinism contract in
`11-automation/README.md` §2.

**My Suricata rule failed to compile.**
Run `suricata -T -c suricata.yaml -S <file>`. The most common causes are an
unbalanced `;`, a missing `rev:`, or using a keyword buffer that the current
Suricata version removed.

**How do I add a payload end to end?**
`CONTRIBUTING.md` §2. The short version: payload JSON, fuzz token, crosswalk
row, schema validation.

## Operations

**How do I know a rule actually works?**
Replay the matching emulation in `09-labs/emulations/` and record the result
table. A rule that never fires during its own replay is broken or irrelevant;
both are defects.

**Coverage says `offensive-only`. Is that a failure?**
Not a build failure, but it is a queue item. `offensive-only` means we know how
to do it and cannot yet detect it. `gap` means neither. The purple-team loop in
`01-intel/methodologies/mitre-attack.md` §4 is how gaps close.

**How do I contribute a new upstream source?**
Through the lock file, with an ADR and a legal review. See `GOVERNANCE.md` §3.

**Everything is failing validation after I pulled. Why?**
Most likely a line-ending or trailing-whitespace change in a CSV. Run
`git diff --check`, then `python tools/ssactl.py verify --root . --strict` and
read the `STRUCT-001`/`REF-001` lines carefully.
