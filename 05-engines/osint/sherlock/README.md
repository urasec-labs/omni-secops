# Sherlock OSINT Engine

| Field | Value |
|---|---|
| `engine_id` | ENG-SHERLOCK |
| `source` | sherlock-project/sherlock @ master@2026-01-05 |
| `license` | MIT |
| `compliance` | `00-governance/charter.md` §7 |

## 1. What it does

Given one username, Sherlock queries a catalogue of platforms and reports
which exist. In the archive it is used for:

* Employee handle discovery during authorised assessments.
* Brand/typosquat candidate enumeration for defenders.
* Seed generation for `08-threatintel/` lookups.

## 2. Usage

```bash
sherlock target_handle
sherlock --csv --output out.csv alice bob
sherlock --site github,gitlab,reddit --proxy http://proxy:8080 handle
sherlock --json --output evidence.json handle
```

## 3. Output contract for the archive

```csv
username,site,url,status,http_status,checked_at
alice,GitHub,https://github.com/alice,Claimed,200,2026-01-15T09:00:00Z
```

Store under the engagement evidence directory, classification `T1` - a
username-to-identity mapping is personal data.

## 4. Handling false positives

| Source of FP | Mitigation |
|---|---|
| Platform returns 200 for every handle | Cross-check with a second platform |
| Parked domains | Check for registrar/parking signatures |
| Reserved usernames | Maintain a `reserved-usernames.txt` deny list |
| Rate limits masking existence | Retry with backoff, never parallel-blast |

## 5. Ethics and legal boundary

Running Sherlock against third-party platforms for reconnaissance is
documented personal data processing. Under GDPR this requires a legitimate
interest assessment; under CFAA, mass automated collection from third parties
without authorisation is risky. Add an explicit clause to the engagement
scope before using this engine outside your own estate. See
`01-intel/checklists/penetration-testing-checklist.md` §2.
