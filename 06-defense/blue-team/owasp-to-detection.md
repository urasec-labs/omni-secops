# OWASP Cheat Sheet to Defensive Detection Mapping

Every OWASP control in `01-intel/cheat-sheets/owasp/owasp-controls.csv` must
have at least one anchor. This page explains the method; the machine readable
result is `10-crosswalk/control-detection/control-detection.csv`.

## 1. Detection layer selection

| Layer | Best suited for | Suricata | Wazuh | Sigma |
|---|---|---|---|---|
| network | requests an attacker sends | yes | no | limited |
| host | what the request caused | no | yes | yes |
| audit | identity and privilege activity | no | yes | yes |
| application | logic the network cannot see | no | via app log | yes |

## 2. Worked example - AUTH-7

| Step | Value |
|---|---|
| Control | AUTH-7 "authentication error messages must be generic" |
| Failure mode | username enumeration through distinct error text |
| Network layer | Cannot see response bodies without TLS termination |
| Host/audit layer | 4625 burst followed by 4624 (spray succeeded) |
| Application layer | Delta on `/login` responses by status/body hash |
| **Chosen anchor** | `audit` - Wazuh `100012` and `100011` |
| Sigma portability | `ssa_win_failed_logon_then_success.yml` |
| Residual gap | Enumeration on a system with no successful logon is invisible |

## 3. Worked example - LLM-01

| Step | Value |
|---|---|
| Control | LLM-01 "segregate untrusted content from instructions" |
| Failure mode | prompt injection from retrieved documents |
| Network layer | TLS-terminated bodies only; heuristics on instruction keywords |
| Host layer | LLM gateway logs: role markers appearing in user content |
| Application layer | Tool invocation without prior user confirmation |
| **Chosen anchor** | `application` - Sigma `ssa_llm_prompt_injection.yml` |
| Sigma portability | yes (LLM gateway logs) |
| Residual gap | Semantic attacks that mimic legitimate instructions |

## 4. Coverage verification

```bash
python tools/ssactl.py verify --root . --coverage
```

Output semantics:

```
COV-001 ok      30 controls, 30 anchored, 0 orphaned
COV-001 ERROR  control_id=LLM-05 has no anchor_id
```

Exit code `2` blocks CI.

## 5. Adding a control

1. Add the row to `owasp-controls.csv` with `anchor_layer` and `anchor_id`.
2. Implement the anchor in `06-defense/suricata/rules/` or
   `06-defense/wazuh/rules/` (allocate a sid or rule id from the SSA ranges).
3. Add the row to `10-crosswalk/control-detection/control-detection.csv`.
4. Run the verifier.
