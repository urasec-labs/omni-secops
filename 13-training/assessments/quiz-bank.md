# Assessment Bank

| Field | Value |
|---|---|
| `assessment_id` | ASM-SSA |
| `pass_mark` | 80 % written, all practicals passed |
| `retake` | permitted after 5 working days, different practical |

## 1. Phase 1 - Foundations (20 questions)

1. What is the difference between a TCP `SYN/ACK` and an `ACK` in terms of
   connection state? Which flag indicates the last packet of the handshake?
2. Why does TLS 1.3 remove the RSA key exchange, and what does it replace?
3. What does `Host:` header injection into an outbound request enable?
4. Calculate the broadcast address for `10.20.30.40/26`.
5. Explain the difference between `Authentication` and `Authorization`.
6. What is the purpose of `Auditd`'s `-S execve`?
7. Name the three `ld.so.preload` implications.
8. What does SUID on `/usr/bin/find` allow?
9. Which Windows event logs service installation? (7045)
10. What does `Get-DomainUser -ASREPReadable` find?
11. Why is `TokenRotation` a session management control?
12. What does `net.ipv4.conf.all.accept_redirects = 0` prevent?
13. Which is safer: parameterised queries or input filtering? Why?
14. What does `SameSite=Strict` prevent that `Lax` does not?
15. Explain the `oidc` vs `oauth` distinction at a high level.
16. Which directory should uploads live in and why?
17. What is the risk of `NOPASSWD: /usr/bin/find` in sudoers?
18. What does `maxauthtries` protect against?
19. Why must `audismd` `execve` rules be generated from the evasion index?
20. What information does a pcap of a TLS session reveal without decryption?

## 2. Phase 2 - Offensive (20 questions)

1. Give the minimal boolean pair that proves SQLi and explain the delta.
2. What does `sqlmap --technique` do and why restrict `E`?
3. List three XSS contexts and one probe for each.
4. Why does `http://0/` bypass a naive loopback filter?
5. What does IMDSv2 add over IMDSv1?
6. Describe the JWT algorithm confusion attack in two sentences.
7. Why is `kid` header injection dangerous?
8. What is the difference between `sig`, `nbf` and `iss` claims?
9. Explain what AS-REP roasting targets and what stops it.
10. What is the DCSync replication GUID and why is 4662 on a non-DC critical?
11. Why is SMB signing mandatory a control for T1187?
12. Name three ADCS attack classes and the template misconfiguration behind each.
13. Give a `find` and a `vim` privesc one-liner and the resulting `EV-*` id.
14. What distinguishes `EV-LNX-0001` from `EV-LNX-0007`?
15. How do you detect a container escape via `nsenter`?
16. Why does a Docker socket mount grant host root?
17. What does `kubectl auth can-i --list` reveal?
18. Name the AWS privesc primitive involving `iam:CreatePolicyVersion`.
19. Which conditions would you add to an IAM policy to limit `AssumeRole`?
20. Why does the archive forbid payloads with destructive side effects at T0?

## 3. Phase 3 - Defensive (20 questions)

1. What makes a Suricata rule high fidelity?
2. How do you allocate a new SSA sid and when is reuse forbidden?
3. What is the difference between an `eventID` and a `rule id` in Wazuh?
4. Write a Wazuh rule that fires 10 failed logons for the same user in 5 minutes.
5. Why is `REJECT` worse than `ALERT` during the first 14 days of a ruleset?
6. What does `COV-001` enforce and why is it a build failure?
7. Give a Sigma rule detecting `certutil -urlcache`.
8. Why is `alg: none` JWT detection a client-side problem?
9. What is the detection gap for LLM-01 and how do you document it?
10. Name four signals of DNS tunnelling.
11. How do you tune without silencing? (by rule id, with expiry)
12. What does `residual_gap` mean and when is it mandatory?
13. Which ATT&CK technique is hardest to detect and why?
14. How do you detect DCSync if the DC is remote?
15. What is the difference between a `full` and `offensive-only` coverage state?
16. Why must an IOC have an `expires` field?
17. How do you respond to a SEV1 in the first 15 minutes?
18. Why capture volatile evidence before containment?
19. What breaks a chain of custody?
20. Describe the purple team loop in five steps.

## 4. Practical assessments

| Id | Practical | Pass criterion |
|---|---|---|
| P-01 | Enumerate and fingerprint the lab target | Service matrix with no unexplained ports |
| P-02 | Prove SQLi on the lab DVWA | Boolean + one time-based demonstration with evidence |
| P-03 | Complete `CH-001` in `09-labs/emulations/` | All expected alerts fire; result table completed |
| P-04 | Forge a JWT against the lab app | Successful `alg` confusion accepted by the target |
| P-05 | Author a Sigma rule for a new technique | Rule fires in replay; crosswalk row present |
| P-06 | Harden a lab host | Verification commands produce the expected output |
| P-07 | Build a timeline from lab logs | `build_timeline.py` output, gaps explained |
| P-08 | Close one ATT&CK `gap` | Detection authored, replayed, matrix updated |

## 5. Scoring

```
score = 0.7 * written_pct + 0.3 * practicals_passed/8 * 100
pass   = written_pct >= 80 AND all mandatory practicals passed
mandatory practicals: P-03, P-05, P-06
```
