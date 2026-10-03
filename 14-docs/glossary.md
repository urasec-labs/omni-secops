# Glossary

| Term | Definition |
|---|---|
| **Archive root** | The directory containing `00-governance/` through `14-docs/`. |
| **Anchor** | The detection a control is verified against. Every control needs at least one. |
| **ATT&CK** | MITRE Adversary Tactics, Techniques and Knowledge; the shared technique vocabulary. |
| **Bypass ladder** | An ordered set of payloads, least to most invasive, for one weakness. |
| **CDK** | Container Development Kit (no relation to this archive). |
| **Chain (CH-nnnn)** | A multi-hop evasion sequence with per-hop telemetry. |
| **Confidence** | 0.0-1.0 that a token or primitive applies in the stated context. |
| **Control (control_id)** | A numbered secure-development control from the OWASP cheat sheets. |
| **Crosswalk** | A CSV in `10-crosswalk/` expressing a relationship between two domains. |
| **CTI** | Cyber Threat Intelligence. |
| **CWE** | Common Weakness Enumeration identifier, e.g. `CWE-89`. |
| **Detection** | A rule that produces an alert for a technique or control. |
| **Emulation** | A scripted, reproducible attack in `09-labs/` with expected telemetry. |
| **EV-* / evasion_id** | A stable identifier for a GTFOBins-style abuse primitive. |
| **Evasion corpus** | `04-evasion/` - abuse cases for trusted binaries. |
| **Fidelity** | How often a detection is correct. Low fidelity rules cause alert fatigue. |
| **Gate (CI)** | A blocking check with a code: `STRUCT-001`, `REF-001`, `COV-001`, `SCHEMA-001`, `INDEX-001`. |
| **Handoff** | A documented transfer of an engagement between phases, teams or people. |
| **IMDS** | Instance Metadata Service (cloud). |
| **Join key** | The tuple used to unify a wordlist token with a payload. |
| **JTI** | JWT identifier claim, used to prevent replay. |
| **LOLBin** | A legitimate signed binary abused to execute attacker code. |
| **NTP / mTLS** | Network Time Protocol / mutual Transport Layer Security. |
| **Offensive-only** | Coverage state: the technique is documented but not detected. |
| **PL-* / payload_id** | A stable identifier for a payload record. |
| **Purple team** | Offensive and defensive collaboration on the same objective. |
| **RAV** | Relative Attack Value: severity x exploitability plus detection x impact (OSSTMM). |
| **RoE** | Rules of engagement - the authorised scope of a test. |
| **Scaffold** | The generated directory structure plus its documentation. |
| **Sid** | A Suricata rule signature id; SSA owns 3001000-3001999. |
| **Sigma** | A vendor-neutral detection format. |
| **Surface** | Where a payload lands: parameter, header, cookie, body, url, file... |
| **T0/T1/T2** | Classification tiers: public, internal, restricted. |
| **Triage cost** | How loud a primitive is; `low` means easy to detect. |
| **Wordlist corpus** | `03-wordlists/` - token lists for discovery and fuzzing. |
