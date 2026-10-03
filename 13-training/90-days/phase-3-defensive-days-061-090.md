# Phase 3 - Defensive Operations (Days 061-090)

| Field | Value |
|---|---|
| `phase_id` | TRN-P3 |
| `window` | day 061 - 090 |
| `outcome` | Ship a detection, run an IR exercise, write an after-action review |
| `gate` | One Sigma rule fires in the lab; one IR memo reviewed |
| `material` | `06-defense/**`, `08-threatintel/**` |

## Week 9 - Detection fundamentals (061-067)

| Day | Topic | Material |
|---|---|---|
| 061 | What a detection must have: fidelity, coverage, cost | `06-defense/blue-team/owasp-to-detection.md` |
| 062 | Suricata rule anatomy and sid discipline | `06-defense/suricata/README.md` |
| 063 | Writing Suricata HTTP rules | `06-defense/suricata/rules/ssa-web-attacks.rules` |
| 064 | Wazuh rules, decoders, levels | `06-defense/wazuh/rules/ssa-baseline.xml` |
| 065 | Wazuh agent hardening | `06-defense/wazuh/agents/linux-server.xml` |
| 066 | Sigma portability | `06-defense/sigma/ssa_ad_dcsync.yml` |
| 067 | Alert triage and false-positive control | `06-defense/suricata/thresholds/ssa-threshold.config` |

## Week 10 - AD and cloud detection (068-074)

| Day | Topic | Material |
|---|---|---|
| 068 | Kerberos telemetry | `06-defense/sigma/ssa_ad_kerberoast.yml` |
| 069 | DCSync and privileged telemetry | `06-defense/sigma/ssa_ad_dcsync.yml` |
| 070 | LOLBin detection patterns | `06-defense/sigma/ssa_windows_lolbin_anomaly.yml` |
| 071 | Cloud audit detection | `06-defense/sigma/ssa_cloud_metadata_access.yml` |
| 072 | Kubernetes and container audit | `04-evasion/containers/docker-escape.md` |
| 073 | Identity provider (Entra/Okta) detection | `06-defense/blue-team/controls/controls.csv` AD-* |
| 074 | Threat intelligence ingestion | `08-threatintel/feeds/feed-registry.yaml` |

## Week 11 - Incident response (075-081)

| Day | Topic | Material |
|---|---|---|
| 075 | NIST SP 800-61 lifecycle | `01-intel/methodologies/nist-sp800-61.md` |
| 076 | Roles and severity | `06-defense/ir/incident-response-playbook.md` |
| 077 | Volatile evidence | `06-defense/ir/evidence-handling.md` |
| 078 | Windows triage | `06-defense/ir/incident-response-playbook.md` §4 |
| 079 | Linux triage | same |
| 080 | Timeline construction | `11-automation/scripts/build_timeline.py` |
| 081 | Tabletop exercise | `06-defense/ir/incident-response-playbook.md` §3 |

## Week 12 - Hardening, purple team, review (082-090)

| Day | Topic | Material |
|---|---|---|
| 082 | Linux hardening verification | `06-defense/hardening/linux-baseline.md` |
| 083 | Windows / AD hardening verification | `06-defense/hardening/windows-baseline.md` |
| 084 | Network and egress hardening | `06-defense/hardening/network-baseline.md` |
| 085 | LLM application security | `06-defense/sigma/ssa_llm_prompt_injection.yml` |
| 086 | Purple team loop | `01-intel/methodologies/mitre-attack.md` §4 |
| 087 | ATT&CK coverage review | `06-defense/blue-team/mitre-coverage.csv` |
| 088 | Close your coverage gaps | same (state `gap` -> `full`) |
| 089 | Write the after-action review | `14-docs/decisions/ADR-0001-example.md` |
| 090 | Final assessment and sign-off | `13-training/assessments/quiz-bank.md` |

## Phase 3 gate

- [ ] A Sigma rule you authored fires during a lab replay
- [ ] `ssactl verify --coverage` passes with your controls anchored
- [ ] One IR memo completed with timeline, evidence register and lessons learned
- [ ] At least one ATT&CK technique moved from `gap` to `full`
