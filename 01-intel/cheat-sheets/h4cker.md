# The Art of Hacking (h4cker) - Deep Curriculum Map

| Field | Value |
|---|---|
| `cheat_id` | CS-H4CKER |
| `source` | The-Art-of-Hacking/h4cker |
| `license` | GPL-3.0 |
| `role` | Depth-first technical curriculum for offensive engineers |

## 1. Curriculum → archive mapping

| h4cker pillar | Archive home | Depth |
|---|---|---|
| Networking deep dive | `01-intel/playbooks/network/` | packet to protocol |
| Operating systems internals | `04-evasion/`, `06-defense/hardening/` | syscalls, memory |
| Reverse engineering | `07-tooling/imhex/` | file format analysis |
| Web application security | `01-intel/playbooks/web/`, `02-payloads/` | full coverage |
| Binary exploitation | `01-intel/playbooks/os/` (via `02-payloads/os`) | memory corruption |
| Hardware / IoT | `09-labs/apps/` | firmware analysis |
| Cryptography | `01-intel/playbooks/crypto/` | practical misuse |
| Automation | `11-automation/`, `05-engines/` | at scale |

## 2. Study path

```
 Networking  ->  OS internals  ->  Reverse engineering  ->  Exploitation
      |                |                   |                    |
      v                v                   v                    v
 playbooks/       hardening/          tooling/imhex      payloads/os
      |                |                   |                    |
      +----------------+-------------------+--------------------+
                                       |
                                       v
                              ethics + governance (00-governance)
```

## 3. Self-hosted tooling pattern

h4cker ships small self-contained tools. The archive prefers wrapping them
behind a documented CLI contract in `11-automation/scripts/` so they can be
validated in CI, rather than vendoring opaque binaries.

| Tool | Contract |
|---|---|
| `sha1-crack` | `sha1-crack --hash <h> --wordlist <w> --stdout` |
| `zscan` | `zscan --range <cidr> --thread 50 --output json` |
| `http-header-check` | `http-header-check --url <u> --json` |
