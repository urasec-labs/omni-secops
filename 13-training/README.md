# Training

| Field | Value |
|---|---|
| `domain` | Human enablement |
| `owner` | `@knowledge-maintainer` |
| `source` | `0xDigit/90-Days-of-Cybersecurity` |
| `structure` | 3 phases x 30 days, then role tracks |

## 1. Layout

| Path | Content |
|---|---|
| `90-days/phase-1-foundations-days-001-030.md` | Networking, OS, Linux, scripting |
| `90-days/phase-2-offensive-days-031-060.md` | Web, AD, privesc, evasion, reporting |
| `90-days/phase-3-defensive-days-061-090.md` | Detection, IR, hardening, purple team |
| `tracks/red-team.md` | Offensive role specialisation |
| `tracks/blue-team.md` | Detection engineering specialisation |
| `tracks/secops.md` | SOC / IR specialisation |
| `assessments/quiz-bank.md` | 60 written questions + 8 practicals |

## 2. Design rules

1. Every day references archive material. Nothing is taught that the archive
   does not contain.
2. Every phase ends with a **gate** that is verifiable by an artifact (a file, a
   command output, a detection that fires).
3. Nothing is assessed that is not in `13-training/assessments/quiz-bank.md`.
4. Practical P-03 (chain replay with detections) and P-06 (hardening
   verification) are mandatory for every role - offensive or defensive.

## 3. Onboarding checklist

```markdown
- [ ] Read 00-governance/charter.md and sign the scope acknowledgement
- [ ] Read 00-governance/data-classification.md
- [ ] Complete Phase 1 day 001-030 at the required cadence
- [ ] Clone the lab estate and run lab_healthcheck.py
- [ ] Choose a role track
- [ ] Complete the first 10 days of the chosen track
- [ ] Pair with a mentor for the first full exploitation chain (P-03)
- [ ] Submit P-05 (a Sigma rule) to the detection reviewer
```

## 4. Mentor responsibilities

| Week | Focus |
|---|---|
| 1 | Environment, access, safety boundaries |
| 2 | Method and evidence discipline |
| 3 | First supervised engagement |
| 4 | First authored detection |
| 5 | Review the first written report end to end |
| 6+ | Quarterly; retake any failed gate |
