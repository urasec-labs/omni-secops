# CTF Material

| Field | Value |
|---|---|
| `domain` | CTF / training |
| `owner` | `@lab-maintainer` |
| `use` | internal training, skill validation, interview practice |

## 1. Category map to the archive

| CTF category | Archive material | Skill measured |
|---|---|---|
| pwn | `02-payloads/os/`, `09-labs/emulations/` | memory corruption, ROP |
| web | `02-payloads/web/`, `01-intel/playbooks/web/` | injection, auth, logic |
| crypto | `01-intel/playbooks/crypto/` | classical/modern misuse |
| forensics | `07-tooling/imhex/`, `06-defense/ir/` | file carving, timeline |
| reversing | `07-tooling/imhex/` | static analysis |
| recon / osint | `05-engines/osint/`, `08-threatintel/` | information gathering |
| cloud | `01-intel/playbooks/cloud/` | IAM abuse, metadata |
| AD | `01-intel/playbooks/active-directory/` | Kerberos, ACL abuse |

## 2. Write-your-own rule

For each of the 10 windows in `13-training/assessments/quiz-bank.md`, the
practical is: write the payload, execute it in the lab, and record which
archive rule fired. A submission is accepted only when the detection fires and
the finding is written up in the format from
`01-intel/checklists/penetration-testing-checklist.md` §6.

## 3. Tenancy and legality

* Only infrastructure you own or are authorised to use.
* Keep CTF assets separate from the lab estate and from production identity
  providers.
* Do not reuse lab credentials anywhere else; `06-defense/ir/evidence-handling.md`
  applies if evidence must be produced.
