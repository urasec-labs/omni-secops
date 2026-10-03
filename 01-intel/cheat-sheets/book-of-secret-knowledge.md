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
