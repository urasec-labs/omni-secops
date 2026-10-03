# Playbook - Network Service Enumeration

| Field | Value |
|---|---|
| `playbook_id` | PB-NET-ENUM |
| `phase` | Reconnaissance / Scanning (PTES) |
| `wordlists` | `03-wordlists/network/ports.txt`, `03-wordlists/network/banners.txt` |
| `automation` | `05-engines/` (Metasploit auxiliary scanners) |

## 1. Order of operations

```bash
# 0. Passive first - no packets to the target
whois TARGET                     # registrar, netscope
amass enum -passive -d TARGET    # CT logs, passive DNS
shodan host TARGET               # historical banner index

# 1. Host discovery
nmap -sn -PR TARGET-CIDR         # ARP sweep on-segment
nmap -sn -PU --min-rate 1000 CIDR

# 2. Port scan (choose by noise tolerance)
nmap -sS -T4 -p- --min-rate 1000 TARGET      # stealth SYN, full range
nmap -sV -sC -p 22,80,443,445,3389 TARGET    # version + default scripts

# 3. UDP (slow, rate limited)
nmap -sU --top-ports 50 --max-retries 1 TARGET

# 4. Service -> template pipeline
nmap -sV -oN sweep.txt TARGET
cut -d' ' -f3 sweep.txt | sort -u | while read p; do \
  echo "== port $p"; searchsploit "$p"; done
```

## 2. Triage matrix

| Service | Version | Immediate questions | Playbook |
|---|---|---|---|
| SSH 22 | old (<= 8.2p1) | weak kex? password auth? | `playbooks/network/pivoting.md` |
| SMB 445 | Windows | signing enabled? shares? | `playbooks/active-directory/smb-relay.md` |
| RDP 3389 | any | NLA? creds reuse? | `playbooks/network/pivoting.md` |
| WinRM 5985 | any | auth required? | `playbooks/active-directory/` |
| MySQL 3306 | any | anonymous login? | `playbooks/web/sql-injection.md` |
| Redis 6379 | any | no AUTH? | `playbooks/network/pivoting.md` (RCE chain) |
| HTTP 80/443 | any | framework? headers? | `playbooks/web/` |
| Docker API 2375 | any | unauthenticated? | `04-evasion/containers/` |
| Kubernetes 6443 | any | anonymous auth? | `04-evasion/containers/` |

## 3. Low-and-slow alternatives

| Need | Noisy tool | Quiet tool |
|---|---|---|
| Port scan | nmap default | `nmap -T2 --max-retries 2 --scan-delay 500ms` |
| Web content | gobuster (parallel 50) | `gobuster -t 4 -r 1s` |
| DNS brute | fierce default | `fierce -dns -s 8.8.8.8 -t 40 -delay 10` |
| Password spray | hydra parallel | `hydra -P -t 4 -W 3 -f` |

## 4. Detection of the scan itself

* Suricata `ssa-scanning.rules`: SYN to >20 distinct ports in 60 s from one source.
* Wazuh rule `86700`: repeated connection attempts across services.
* Expect to be detected; for covert engagements agree a source IP or
  "scan window" in the rules of engagement.
