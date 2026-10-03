# Security Policy

## Reporting

Report vulnerabilities in this archive to the maintainers privately. Do not
open a public issue for:

* A detection rule that can be silently evaded by an attacker who reads it.
* An index poisoning vector in `03-wordlists/index/`.
* A payload entry that is weaponised beyond what an authorised test needs.

Include: affected path, reproduction, impact on detection coverage.

## What we consider a vulnerability here

| Class | Severity |
|---|---|
| Detection rule evasion through normalisation gap | Critical |
| Crosswalk join producing wrong CVE/CWE attribution | High |
| Schema acceptance of malformed payload causing tool crash | Medium |
| Documentation inaccuracy | Low |

## Safe use

The content in `02-payloads/`, `03-wordlists/` and `04-evasion/` is offensive
material. It is published for authorised security testing, detection research
and education. Running it against infrastructure you do not own or have written
permission to test may be a criminal offence in your jurisdiction.
