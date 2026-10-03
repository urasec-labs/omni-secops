# Data Classification

| Level | Name | Handling |
|---|---|---|
| T0 | Public | No restriction. Suitable for public repositories. |
| T1 | Internal | Corporate systems only. No external distribution. |
| T2 | Restricted | Authorised operations only. Encrypted at rest, audit logged. |

## 1. Domain defaults

| Path | Default | Examples of escalation |
|---|---|---|
| `00-governance/` | T0 | - |
| `01-intel/` | T0 | Engagement-specific findings → T2 |
| `02-payloads/` | T0 | Destructive payloads (`DROP`, `mkfs`, `rm -rf /`) → T2 |
| `03-wordlists/` | T0 | Real credential lists harvested from breaches → T2 |
| `04-evasion/` | T0 | - |
| `05-engines/` | T1 | Live C2 configuration → T2 |
| `06-defense/` | T0 | Internal detection logic + asset names → T1 |
| `07-tooling/` | T0 | - |
| `08-threatintel/` | T1 | Actor PII, victim lists, unshared IOCs → T2 |
| `09-labs/` | T0 | - |
| `10-crosswalk/` | T0 | - |
| `11-automation/` | T0 | - |
| `12-schemas/` | T0 | - |
| `13-training/` | T0 | - |
| `14-docs/` | T0 | - |

## 2. Escalation rules

1. Any payload with a destructive or persistent side effect is T2 regardless of
   domain default.
2. Any IOC or credential value is at least T1.
3. Any content revealing internal hostnames, IPs, accounts or rule logic tuned
   to a specific environment is T1.
4. Mix-and-match: a document that aggregates T1 data becomes T1 at the highest
   level encountered.

## 3. Prohibited content

* Live credentials, tokens, private keys.
* Real personal data (names, emails, phone numbers) of individuals.
* Undisclosed vulnerability detail for a dependency the archive depends on
  (disclose privately to the maintainers first).
* Undisclosed incident details of a named organisation.
