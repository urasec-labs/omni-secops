# Role Track - SecOps (SOC / IR)

| Field | Value |
|---|---|
| `track_id` | TRACK-SECOPS |
| `phases` | 3 mainly, 2 light |
| `primary` | `06-defense/ir/`, `08-threatintel/` |

## 1. Capability targets

| Capability | Evidence | Archive material |
|---|---|---|
| Alert triage at L1 | 50 alerts triaged with correct severity | `06-defense/blue-team/mitre-coverage.csv` |
| Incident scoping at L2 | Correct host and identity set in 30 min | `06-defense/ir/incident-response-playbook.md` |
| Evidence handling | Custody register with no gaps | `06-defense/ir/evidence-handling.md` |
| Timeline construction | Timestamped, evidence-backed timeline | `11-automation/scripts/build_timeline.py` |
| IOC ingestion | Feed pipeline running, metrics reported | `08-threatintel/` |
| Purple support | Replay an emulation, confirm detections | `09-labs/emulations/` |

## 2. Triage flow

```
 alert
   |
   v
 Is it a true positive? ---- no --> false positive: document, tune, close
   |
  yes
   |
   v
 Which asset, which identity, which severity? --> 06-defense/ir/ §1 matrix
   |
   v
 Contain or observe?  observe first if volatility risk (see evidence-handling)
   |
   v
 Timeline  -->  06-defense/ir/timeline.md
   |
   v
 Scope  -->  data exposure confirmed / suspected / none
   |
   v
 Escalate per severity matrix; notify Legal if data exposure is possible
   |
   v
 After action: new Sigma rule or gap note, AAR within 5 business days
```

## 3. Weekly cadence

| Activity | Time |
|---|---|
| Alert review and rule tuning feedback | 5 h |
| Hunt using `08-threatintel/` IOCs | 4 h |
| Emulation replay and detection confirmation | 3 h |
| Incident drills and AAR reading | 3 h |
| IOC hygiene (`expires`, false positives) | 2 h |

## 4. Metrics to own

| Metric | Target | Source |
|---|---|---|
| MTTD for feed IOCs | < 30 min | `08-threatintel/README.md` §3 |
| Alert precision | > 90 % | triage outcomes |
| SEV1 time to containment | < 60 min | `06-defense/ir/` |
| Playbook currency | reviewed quarterly | `06-defense/ir/` |
| Evidence custody gaps | zero | `06-defense/ir/evidence-handling.md` |
