# Multi-Hop Evasion Chains

Each chain is a sequence of `EV-*` primitives. Every hop has a detection
anchor, and the whole chain is replayable in `09-labs/emulations/`.

| Field | Value |
|---|---|
| `chain_id` | CH-* |
| `provenance` | `GTFOBins`, `HackTricks`, `Metasploit` |
| `telemetry_expectation` | Sigma + Wazuh + Suricata, per hop |

## CH-001 - Web to root on an internet-facing Linux host

| Hop | Primitive | Action | Telemetry |
|---|---|---|---|
| 1 | `PL-WEB-SSRF-0021` | SSRF to Redis `gopher://` writes a web shell | Suricata `3001002`, app 500 with gopher URI |
| 2 | - | webshell executes | Wazuh 86800 web process spawning shell |
| 3 | `EV-LNX-0016` | `crontab -l` persistence | `ssa_linux_cron_persistence.yml` |
| 4 | `EV-LNX-0008` | SUID shell copy | `ssa_linux_suid_shell_copy.yml` |
| 5 | - | root shell, `useradd` | Wazuh 86801 new account |

**Expected aggregate:** 3 alerts within 10 minutes on one host. Detection
confidence: high.

## CH-002 - Windows phishing to domain admin

| Hop | Primitive | Action | Telemetry |
|---|---|---|---|
| 1 | `EV-WIN-0005` | `certutil` download | `ssa_windows_certutil.yml` |
| 2 | `EV-WIN-0003` | `schtasks /create` persistence | `ssa_windows_schtasks.yml` |
| 3 | - | credential materialisation in memory | Sysmon 10 (ProcessAccess) |
| 4 | `EV-LNX-0005`/`EV-WIN-0013` | `wmic process call create` lateral | `ssa_windows_wmi_exec.yml`, 4624 type 3 |
| 5 | - | DCSync | 4662 + replication GUID, non-DC -> `ssa_ad_dcsync.yml` |

**Expected aggregate:** 5 alerts, two hosts, privilege escalation. Detection
confidence: high, provided 4662 is collected off-domain.

## CH-003 - Cloud metadata to account takeover

| Hop | Primitive | Action | Telemetry |
|---|---|---|---|
| 1 | `PL-WEB-SSRF-0011` | IMDSv2 token fetch from an odd user agent | CloudTrail, proxy log |
| 2 | `PL-CLOUD-0002` | role credentials read | metadata call from non-web user agent |
| 3 | - | `sts:AssumeRole` to a different role | CloudTrail unusual role chain |
| 4 | - | `iam:CreatePolicyVersion` | CloudTrail + GuardDuty |

**Expected aggregate:** CloudTrail `GetInstanceMetadata` + AssumeRole +
CreatePolicyVersion from one principal in 15 minutes.

## CH-004 - CI/CD to production

| Hop | Primitive | Action | Telemetry |
|---|---|---|---|
| 1 | `EV-CI-0003` | fork PR runs with repo secrets | Actions audit log: `pull_request_target` + checkout |
| 2 | - | secret exfiltration to a public gist | egress proxy alert |
| 3 | - | malicious image pushed | registry audit, digest change on `:latest` |
| 4 | - | deployment from the tampered image | CD audit |

## Replay instructions

```bash
# dry run against the lab estate in 09-labs/infrastructure
python tools/ssactl.py index --root .
powershell -File bootstrap.ps1 -Mode Verify
# then follow 09-labs/emulations/CH-001.md
```

Every emulation records which rules **should** fire. A rule that never fires
during a replay is either broken or irrelevant; both are defects tracked in
`10-crosswalk/attack-coverage/attack-coverage.csv` (state `gap`).
