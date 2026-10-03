# Phase 1 - Foundations (Days 001-030)

| Field | Value |
|---|---|
| `phase_id` | TRN-P1 |
| `window` | day 001 - 030 |
| `outcome` | Read a packet, explain an HTTP request, enumerate a lab host |
| `gate` | Enumerate and fingerprint `09-labs` target, write findings |
| `playbooks` | `01-intel/playbooks/network/`, `01-intel/playbooks/crypto/` |

## Week 1 - Networking (001-007)

| Day | Topic | Archive material | Practical |
|---|---|---|---|
| 001 | OSI/TCP-IP model, encapsulation | `14-docs/glossary.md` | Draw the stack from memory |
| 002 | IP addressing, CIDR, routing | `03-wordlists/network/ports.txt` | Compute subnets for `10.10.10.0/24` |
| 003 | TCP handshake, states, flags | - | Capture a handshake with tcpdump |
| 004 | UDP, ICMP, ARP | - | Explain ARP spoofing in 3 sentences |
| 005 | DNS resolution, records, DNSSEC | `03-wordlists/discovery/dns/` | `dig` a record and read the flags |
| 006 | TLS 1.2/1.3 handshake | `06-defense/hardening/network-baseline.md` | Read a handshake in Wireshark |
| 007 | HTTP/1.1, headers, methods | `01-intel/playbooks/web/authentication-bypass.md` | Explain `Transfer-Encoding` vs `Content-Length` |

## Week 2 - Operating systems (008-014)

| Day | Topic | Practical |
|---|---|---|
| 008 | Linux filesystem, permissions, SUID/SGID | Map `/usr/bin` SUID set |
| 009 | Processes, signals, namespaces | Explain `/proc/<pid>/exe` |
| 010 | Users, groups, sudo, PAM | `04-evasion/linux/sudo-lpe.md` |
| 011 | Windows processes, services, tokens | `04-evasion/windows/sushi.md` |
| 012 | Windows registry, event log | Read 4624 by hand |
| 013 | Active Directory objects, LDAP | `01-intel/playbooks/active-directory/kerberos-attacks.md` |
| 014 | macOS architecture, launchd, SIP | `04-evasion/macos/sudo.md` |

## Week 3 - Linux and shell (015-021)

| Day | Topic | Practical |
|---|---|---|
| 015 | Shell, quoting, expansion | Explain the 4 quoting contexts |
| 016 | File descriptors, redirection, pipes | Build a one-liner that parses access logs |
| 017 | Process control, backgrounding, nohup | - |
| 018 | Permissions in depth, umask | Predict a file mode |
| 019 | systemd units, timers, sockets | Write a hardened unit from `06-defense/wazuh/agents/linux-server.xml` |
| 020 | Package management, repositories | Verify a package signature |
| 021 | Auditd, sysctl, capabilities | Add an execve rule for `/usr/bin/find` |

## Week 4 - Scripting and tooling (022-030)

| Day | Topic | Practical |
|---|---|---|
| 022 | Python 3 essentials for security | Parse a JSON IOC file |
| 023 | Bash for security work | Write a log triage script |
| 024 | `curl`, `wget`, HTTP clients | Fetch and follow redirects safely |
| 025 | `jq`, `yq`, `grep` on structured data | Extract `alert.signature` from `eve.json` |
| 026 | `nmap` fundamentals | `nmap -sV -sC` against the lab |
| 027 | `tcpdump`, `tshark` | Extract a credential from a pcap (lab only) |
| 028 | Git fundamentals and history forensics | Use `git log -S` to find a removed secret |
| 029 | Python standard library for crypto | Hash, encode, verify a signature |
| 030 | GitHub Actions and CI secrets | Read a workflow, list exposed secrets |

## Phase 1 gate

```bash
# 1. enumerate the lab target and produce a service matrix
nmap -sV -sC -p- 127.0.0.1 > /tmp/phase1-scan.txt
# 2. explain, in writing, why 3306 and 6379 are dangerous when unauthenticated
# 3. list ten Linux hardening items from 06-defense/hardening/linux-baseline.md and
#    run the verification command for each
```

Sign-off criteria:
- [ ] Service matrix produced with no unexplained ports
- [ ] Written explanation of the HTTP request smuggling prerequisite chain
- [ ] Ten hardening items verified with command output attached
- [ ] Quiz: `13-training/assessments/quiz-bank.md` Phase 1 section, >= 80 %
