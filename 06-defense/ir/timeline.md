# Incident Timeline Template

Copy this table per incident. Times are UTC. Never edit a completed row -
append a correction row and reference the original.

| # | Timestamp (UTC) | Source | Actor | Action | Evidence ID | Analyst | Notes |
|---|---|---|---|---|---|---|---|
| 1 | 2026-01-15T08:41:02Z | `suricata` 3001006 | unknown | XSS probe on `/search` | SSA-2026-0001-LOG | analyst.a | first alert |
| 2 | 2026-01-15T08:41:15Z | `wazuh` 100020 | unknown | SQLi probe on `/product?id=` | SSA-2026-0001-LOG | analyst.a | |
| 3 | 2026-01-15T08:52:44Z | `proxy` | 10.20.3.44 | request to `169.254.169.254` | SSA-2026-0001-LOG | analyst.a | **SSRF confirmed** |
| 4 | 2026-01-15T08:52:51Z | `wazuh` 100022 | app-svc | SSRF rule fired | SSA-2026-0002-ALERT | auto | |
| 5 | 2026-01-15T08:53:10Z | `wazuh` 100011 | svc_deploy | 20 failed logons, 1 success | SSA-2026-0002-ALERT | auto | spray succeeded |
| 6 | 2026-01-15T09:03:33Z | `cloudtrail` | svc_deploy | `iam:CreatePolicyVersion` | SSA-2026-0003-CT | analyst.b | escalation |
| 7 | 2026-01-15T09:20:00Z | responder | - | EC2 isolated, key revoked | SSA-2026-0004-ACT | analyst.a | containment |

## Correlation queries

```bash
# all events for a host
grep 'WEB-03' 06-defense/ir/timeline.md

# gaps between consecutive steps (a >20 minute gap may mean evasion)
awk -F'|' 'NR>2 {if (prev) { gsub(/[TZ: -]/,"",$2); gsub(/[TZ: -]/,"",prev);
    d=$2-prev; if (d>1200) print "GAP", $2, d "s" } prev=$2 }' 06-defense/ir/timeline.md
```

## Required fields discipline

* Every row needs `Evidence ID` - a timeline without evidence is opinion.
* `Actor` uses an identity (`user@domain`, `IP`, `role-arn`), not "attacker".
* `Action` is what the system recorded, not what you assume it means.
