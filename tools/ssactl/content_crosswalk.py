"""Curated content for 10-crosswalk and 12-schemas."""

from __future__ import annotations

FILES: dict[str, str] = {}

# ===========================================================================
# 10-crosswalk
# ===========================================================================

FILES["10-crosswalk/README.md"] = r'''
# Integration Crosswalk

This directory is the reason the Sovereign Security Archive is an archive and
not a folder of downloaded repositories. Every mapping between the twenty
upstream domains is expressed here as data, validated by `ssactl verify`, and
consumed by the generators in `11-automation/scripts/`.

## 1. The four maps

| Map | File | Joins | Cardinality |
|---|---|---|---|
| Wordlist to payload | `wordlist-payload/crosswalk.csv` | SecLists token x PAT payload | many-to-many via `(sha256, surface, cwe, context)` |
| Evasion to detection | `evasion-detection/evasion-to-detection.csv` | GTFOBins primitive x Sigma/Wazuh/Suricata | one-to-many (sigma, host, network) |
| Control to detection | `control-detection/control-detection.csv` | OWASP control x defensive anchor | one-to-many, **minimum one** |
| Attack coverage | `attack-coverage/attack-coverage.csv` | ATT&CK technique x artifacts | one-to-many, state tracked |

## 2. Architecture

```
  +-----------------+        +-----------------+        +-----------------+
  | 03-wordlists/   |        | 02-payloads/    |        | 04-evasion/     |
  | SecLists tokens |        | PAT records     |        | GTFOBins prim.  |
  +--------+--------+        +--------+--------+        +--------+--------+
           |                          |                          |
           |  token_id                |  payload_id              |  evasion_id
           +------------+-------------+--------------+-----------+
                        |                            |
                        v                            v
             +--------------------+        +--------------------------+
             | wordlist-payload/  |        | evasion-detection/      |
             |  build_payload_     |        |  evasion-to-detection   |
             |  index.py           |        |  .csv                   |
             +----------+---------+        +------------+-------------+
                        |                               |
                        v                               v
             +--------------------+        +--------------------------+
             | 03-wordlists/index/ |        | 06-defense/             |
             |  wordlist.db (FTS5) |        |  sigma/ wazuh/ suricata/|
             +----------+---------+        +------------+-------------+
                        |                               |
                        +---------------+---------------+
                                        v
                             +--------------------+
                             |  10-crosswalk/      |
                             |  attack-coverage/   |
                             |  api-contracts/     |
                             +--------------------+
```

## 3. Identifier namespaces

| Prefix | Meaning | Defined in |
|---|---|---|
| `PL-*` | payload record | `02-payloads/` |
| `EV-*` | evasion primitive | `04-evasion/index/evasion-index.csv` |
| `CH-*` | multi-hop chain | `04-evasion/chains/abuse-chains.md` |
| `PB-*` | playbook | `01-intel/playbooks/` |
| `MTH-*` | methodology | `01-intel/methodologies/` |
| `CS-*` | cheat sheet | `01-intel/cheat-sheets/` |
| `CL-*` | checklist | `01-intel/checklists/` |
| `IR-*` | incident response playbook | `06-defense/ir/` |
| `SID 300xxxx` | Suricata rule | `06-defense/suricata/rules/` |
| `1xxxxx` (Wazuh) | Wazuh rule | `06-defense/wazuh/rules/` |
| `<SHEET>-<n>` | OWASP control | `01-intel/cheat-sheets/owasp/owasp-controls.csv` |
| `Txxxx[.xxx]` | ATT&CK technique | `08-threatintel/attack/` |
| `CWE-<n>` | weakness | everywhere |
| `LAB-*` | lab asset | `09-labs/` |

## 4. Validation gates

```bash
python tools/ssactl.py verify --root . --strict          # REF-001 dangling ids
python tools/ssactl.py verify --root . --coverage        # COV-001 orphan controls
python tools/ssactl.py validate --root .                 # SCHEMA-001
python tools/ssactl.py index --root .                    # INDEX-001 determinism
python tools/ssactl.py stats --root .                    # report
```

| Code | Meaning | Exit |
|---|---|---|
| `STRUCT-001` | a directory in `spec.py` is missing on disk | 2 |
| `REF-001` | a crosswalk row references an unknown id | 2 |
| `COV-001` | a control has no detection anchor | 2 |
| `SCHEMA-001` | a JSON artifact violates `12-schemas/` | 2 |
| `INDEX-001` | the generated index is stale | 2 |
| `DRIFT-001` | an upstream ref moved | 0 (warn) |
| `SIZE-001` | corpus grew more than 20 % | 0 (review) |
'''.lstrip()

FILES["10-crosswalk/wordlist-payload/crosswalk.csv"] = r'''
cwe_id,context,surface,token,sha256,origin,payload_id,fuzz_wordlist,confidence,playbook,detections
CWE-89,query,parameter,' OR '1'='1,,both,PL-WEB-SQLI-0001,injection-words.txt,1.0,PB-WEB-SQLI,3001001|100020
CWE-89,query,parameter,' OR '1'='1'-- -,,,both,PL-WEB-SQLI-0002,injection-words.txt,1.0,PB-WEB-SQLI,3001001|100020
CWE-89,query,parameter,' OR '1'='1#,,,both,PL-WEB-SQLI-0003,injection-words.txt,1.0,PB-WEB-SQLI,3001001|100020
CWE-89,query,parameter,admin'-- -,,,payload,PL-WEB-SQLI-0004,injection-words.txt,0.6,PB-WEB-SQLI,3001001|100020
CWE-89,query,parameter,') OR ('1'='1,,,both,PL-WEB-SQLI-0005,injection-words.txt,1.0,PB-WEB-SQLI,3001001|100020
CWE-89,numeric,parameter,1 OR 1=1,,,both,PL-WEB-SQLI-0006,injection-words.txt,1.0,PB-WEB-SQLI,3001001|100020
CWE-89,identifier,parameter,ORDER BY 10,,,both,PL-WEB-SQLI-0010,injection-words.txt,1.0,PB-WEB-SQLI,3001001
CWE-89,query,parameter,UNION SELECT NULL,,,both,PL-WEB-SQLI-0020,injection-words.txt,1.0,PB-WEB-SQLI,3001001
CWE-89,query,parameter,UNION SELECT NULL,NULL,,,both,PL-WEB-SQLI-0021,injection-words.txt,1.0,PB-WEB-SQLI,3001001
CWE-89,query,parameter,UNION SELECT NULL,NULL,NULL,,,both,PL-WEB-SQLI-0022,injection-words.txt,1.0,PB-WEB-SQLI,3001001
CWE-89,query,parameter,SLEEP(5),,,both,PL-WEB-SQLI-0080,injection-words.txt,1.0,PB-WEB-SQLI,3001001
CWE-89,query,parameter,pg_sleep(5),,,payload,PL-WEB-SQLI-0081,injection-words.txt,0.6,PB-WEB-SQLI,3001001
CWE-89,query,parameter,WAITFOR DELAY,,,payload,PL-WEB-SQLI-0082,injection-words.txt,0.6,PB-WEB-SQLI,3001001
CWE-89,header,header,OR 1=1,,,payload,PL-WEB-SQLI-0090,injection-words.txt,0.6,PB-WEB-SQLI,100020
CWE-89,cookie,cookie,OR 1=1,,,payload,PL-WEB-SQLI-0091,injection-words.txt,0.6,PB-WEB-AUTHBYPASS,100020
CWE-79,html-text,parameter,<script>alert(1)</script>,,,both,PL-WEB-XSS-0001,xss-words.txt,1.0,PB-WEB-XSS,3001006|100021
CWE-79,html-text,parameter,<img src=x onerror=alert(1)>,,,both,PL-WEB-XSS-0002,xss-words.txt,1.0,PB-WEB-XSS,3001006|100021
CWE-79,html-text,parameter,<svg/onload=alert(1)>,,,both,PL-WEB-XSS-0003,xss-words.txt,1.0,PB-WEB-XSS,3001006|100021
CWE-79,attribute,parameter," onmouseover=alert(1) x=",,,both,PL-WEB-XSS-0004,xss-words.txt,1.0,PB-WEB-XSS,3001006
CWE-79,attribute,parameter,' onmouseover=alert(1) x=',,,both,PL-WEB-XSS-0005,xss-words.txt,1.0,PB-WEB-XSS,3001006
CWE-79,script,parameter,</script><img src=x onerror=alert(1)>,,,both,PL-WEB-XSS-0006,xss-words.txt,1.0,PB-WEB-XSS,3001006
CWE-79,js-string,parameter,'-alert(1)-',,,payload,PL-WEB-XSS-0007,xss-words.txt,0.6,PB-WEB-XSS,100021
CWE-79,url,parameter,javascript:alert(1),,,both,PL-WEB-XSS-0008,xss-words.txt,1.0,PB-WEB-XSS,3001006
CWE-79,dom,parameter,document.domain,,,payload,PL-WEB-XSS-0009,xss-words.txt,0.6,PB-WEB-XSS,100021
CWE-79,html-text,parameter,{{7*7}},,,both,PL-WEB-XSS-0010,ssti-words.txt,1.0,PB-WEB-XSS,3001006
CWE-79,html-text,parameter,${7*7},,,both,PL-WEB-XSS-0011,ssti-words.txt,1.0,PB-WEB-XSS,3001006
CWE-79,html-text,parameter,{{constructor.constructor('alert(1)')()}},,,payload,PL-WEB-XSS-0014,ssti-words.txt,0.6,PB-WEB-XSS,100021
CWE-918,url,url,http://127.0.0.1/,,,both,PL-WEB-SSRF-0001,ssrf-words.txt,1.0,PB-WEB-SSRF,3001003
CWE-918,url,url,http://0/,,,both,PL-WEB-SSRF-0002,ssrf-words.txt,1.0,PB-WEB-SSRF,3001003
CWE-918,url,url,http://[::1]/,,,both,PL-WEB-SSRF-0003,ssrf-words.txt,1.0,PB-WEB-SSRF,3001003
CWE-918,url,url,http://2130706433/,,,both,PL-WEB-SSRF-0004,ssrf-words.txt,1.0,PB-WEB-SSRF,3001003
CWE-918,url,url,http://0x7f.0.0.1/,,,both,PL-WEB-SSRF-0005,ssrf-words.txt,1.0,PB-WEB-SSRF,3001003
CWE-918,url,url,http://127.1/,,,both,PL-WEB-SSRF-0006,ssrf-words.txt,1.0,PB-WEB-SSRF,3001003
CWE-918,url,url,http://169.254.169.254/latest/meta-data/,,,both,PL-WEB-SSRF-0010,ssrf-words.txt,1.0,PB-WEB-SSRF,3001003|100022
CWE-918,url,url,http://169.254.169.254/latest/api/token,,,payload,PL-WEB-SSRF-0011,ssrf-words.txt,0.6,PB-WEB-SSRF,100022
CWE-918,url,url,http://metadata.google.internal/computeMetadata/v1/,,,both,PL-WEB-SSRF-0012,ssrf-words.txt,1.0,PB-WEB-SSRF,3001003
CWE-918,url,url,http://169.254.169.254/metadata/instance,,,payload,PL-WEB-SSRF-0013,ssrf-words.txt,0.6,PB-WEB-SSRF,100022
CWE-918,url,url,file:///etc/passwd,,,both,PL-WEB-SSRF-0020,ssrf-words.txt,1.0,PB-WEB-SSRF,3001003
CWE-918,url,url,gopher://127.0.0.1:6379/,,,payload,PL-WEB-SSRF-0021,ssrf-words.txt,0.6,PB-WEB-SSRF,3001003
CWE-90,ldap,parameter,admin)(|(password=*,,,payload,PL-INFRA-0002,injection-words.txt,0.6,PB-WEB-SQLI,100020
CWE-90,ldap,parameter,*),,,both,PL-INFRA-0001,injection-words.txt,1.0,PB-WEB-SQLI,100020
CWE-20,nosql,body,"{""$ne"":null}",,,both,PL-INFRA-0010,injection-words.txt,1.0,PB-WEB-AUTHBYPASS,3001005
CWE-502,jndi,jndi,${jndi:ldap://,fuzz,PL-INFRA-0020,injection-words.txt,0.4,PB-WEB-SSRF,3001004
CWE-1336,template,parameter,{{config.items()}},,,payload,PL-WEB-SSTI-0002,ssti-words.txt,0.6,PB-WEB-XSS,3001006
CWE-1336,template,parameter,${{T(java.lang.Runtime),,,payload,PL-WEB-SSTI-0010,ssti-words.txt,0.6,PB-WEB-XSS,3001006
CWE-89,stack,parameter,xp_cmdshell,,,payload,PL-WEB-SQLI-0101,injection-words.txt,0.6,PB-WEB-SQLI,100020
CWE-89,query,parameter,1' AND 1=1,,,fuzz,,,,0.4,PB-WEB-SQLI,3001001
CWE-89,query,parameter,1 AND 1=2,,,fuzz,,,,0.4,PB-WEB-SQLI,3001001
CWE-89,query,parameter,benchmark(5000000,,,fuzz,,,,0.4,PB-WEB-SQLI,3001001
CWE-79,html-text,parameter,<body onload=alert(1)>,,,fuzz,,,,0.4,PB-WEB-XSS,3001006
CWE-79,url,parameter,JaVaScRiPt:alert(1),,,fuzz,,,,0.4,PB-WEB-XSS,3001006
CWE-918,url,url,http://localtest.me/,,,fuzz,,,,0.4,PB-WEB-SSRF,3001003
CWE-918,url,url,http://169.254.169.254.nip.io/,,,payload,PL-WEB-SSRF-0024,ssrf-words.txt,0.6,PB-WEB-SSRF,3001003
'''.lstrip()

FILES["10-crosswalk/wordlist-payload/README.md"] = r'''
# Wordlist to Payload Crosswalk

## 1. The problem this solves

SecLists gives you `UNION SELECT NULL,NULL` in `SQL-Injection.txt` with no
knowledge of whether it targets MySQL, MSSQL or a PHP parameter. PayloadsAllTheThings
gives you a rich record with `engine`, `context`, `surface` and `severity` but
you must know the id to find it. The archive needs one table where a
fuzzing tool and a payload library meet.

## 2. Join rule (normative)

Two records unify when **all** hold:

```
sha256(normalise(a.token)) == sha256(normalise(b.payload))
AND a.surface == b.surface
AND a.cwe_id == b.cwe_id
AND a.context == b.context
```

where

```python
def normalise(t: str) -> str:
    t = unicodedata.normalize("NFC", t)   # unicode canonical form
    t = t.strip()                          # leading/trailing whitespace
    t = re.sub(r"\s+", " ", t)             # collapse internal whitespace
    t = t.strip("'\"")                     # surrounding quotes
    return t
```

A wordlist entry that cannot be attributed to a CWE/context is recorded with
`origin=fuzz`, `payload_id` empty and `confidence=0.4`. It is still indexed,
so a consumer can distinguish "known injection token" from "blind guess".

## 3. Confidence model

| `origin` | Meaning | `confidence` |
|---|---|---|
| `both` | present in SecLists *and* PAT with matching normalisation | 1.0 |
| `payload` | PAT only, no wordlist equivalent | 0.6 |
| `fuzz` | SecLists only, unattributed | 0.4 |

## 4. Consumption examples

```bash
# export the highest-confidence SQLi tokens for a parameter surface
python - <<'PY'
import csv
rows = [r for r in csv.DictReader(open('10-crosswalk/wordlist-payload/crosswalk.csv'))
        if r['cwe_id'] == 'CWE-89' and r['surface'] == 'parameter']
for r in sorted(rows, key=lambda r: -float(r['confidence'] or 0)):
    print(r['confidence'], r['token'][:60])
PY
```

```bash
# feed ffuf directly
cut -d, -f4 10-crosswalk/wordlist-payload/crosswalk.csv | grep -v '^$' | \
  sort -u > /tmp/ssa-words.txt
ffuf -w /tmp/ssa-words.txt -u https://TARGET/FUZZ -mc all -ac
```

## 5. Maintenance

This file is **generated** by `11-automation/scripts/build_payload_index.py`
from the payload JSON files plus the wordlist exports. Edit the generators and
the payload corpus, never this file.
'''.lstrip()

FILES["10-crosswalk/evasion-detection/evasion-to-detection.csv"] = r'''
evasion_id,technique_id,sigma_rule,sigma_level,wazuh_rule,suricata_sid,audit_logsource,confidence,playbook,module,first_mapped
EV-LNX-0001,T1218.003,ssa_linux_find_exec.yml,high,101000,,auditd,high,PB-LINUX-PRIVESC,exploit/linux/sudo/local,2026-01-15
EV-LNX-0002,T1218.003,ssa_linux_editor_shell.yml,high,101001,,auditd,high,PB-LINUX-PRIVESC,exploit/multi/handler,2026-01-15
EV-LNX-0003,T1218.003,,,101003,,auditd,medium,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0004,T1218.003,ssa_linux_awk_shell.yml,medium,101002,,auditd,high,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0005,T1059.006,ssa_interpreter_shell.yml,medium,101002,,auditd,medium,PB-LINUX-PRIVESC,post/multi/reverse_ssh,2026-01-15
EV-LNX-0006,T1059.006,ssa_interpreter_shell.yml,medium,101002,,auditd,medium,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0007,T1548.003,ssa_linux_sudo_nonshell.yml,medium,101101,,auth.log,medium,PB-LINUX-PRIVESC,exploit/linux/sudo/local,2026-01-15
EV-LNX-0008,T1548.003,ssa_linux_suid_shell_copy.yml,critical,101003,,auditd,high,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0009,T1218.003,ssa_linux_env_shell.yml,medium,101100,,auditd,high,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0010,T1218.003,,,101102,,auditd,medium,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0011,T1218.003,,,101103,,auditd,medium,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0012,T1218.003,ssa_linux_editor_shell.yml,high,101001,,auditd,high,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0013,T1059.004,,,101104,,auditd,medium,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0014,T1218.003,,,101105,,auditd,medium,PB-LINUX-PRIVESC,,2026-01-15
EV-LNX-0015,T1218.003,ssa_ssh_pivot.yml,medium,101020,,auth.log,medium,PB-NET-PIVOT,auxiliary/scanner/ssh,2026-01-15
EV-LNX-0016,T1053.003,ssa_linux_cron_persistence.yml,high,101010,3001201,auditd,high,PB-LINUX-PERSIST,,2026-01-15
EV-LNX-0017,T1610,ssa_linux_nsenter.yml,critical,101004,,auditd,high,PB-CONTAINER-ESCAPE,exploit/linux/local/docker,2026-01-15
EV-WIN-0001,T1021.002,ssa_windows_psexec.yml,high,86710,3001301,sysmon,high,PB-AD-LATERAL,exploit/windows/smb/psexec,2026-01-15
EV-WIN-0002,T1218.003,ssa_windows_mmc_dll.yml,medium,86711,,sysmon,medium,PB-WINDOWS-PRIVESC,post/windows/escalate/bypassuac,2026-01-15
EV-WIN-0003,T1053.005,ssa_windows_schtasks.yml,high,86712,3001302,sysmon,high,PB-WINDOWS-PERSIST,exploit/windows/smb/smb_exec,2026-01-15
EV-WIN-0004,T1197,ssa_windows_bitsadmin.yml,high,86713,3001202,sysmon,high,PB-WINDOWS-EXEC,,2026-01-15
EV-WIN-0005,T1105,ssa_windows_certutil.yml,high,86714,3001202,sysmon,high,PB-WINDOWS-EXEC,auxiliary/downloader/HttpClient,2026-01-15
EV-WIN-0006,T1218.010,ssa_windows_regsvr32.yml,high,86715,3001202,sysmon,high,PB-WINDOWS-EXEC,exploit/windows/smb/smb_delivery,2026-01-15
EV-WIN-0007,T1218.005,ssa_windows_mshta.yml,high,86716,3001203,sysmon,high,PB-WINDOWS-EXEC,exploit/windows/smb/smb_delivery,2026-01-15
EV-WIN-0008,T1218.003,ssa_windows_installutil.yml,high,86717,3001202,sysmon,high,PB-WINDOWS-EXEC,exploit/windows/smb/smb_delivery,2026-01-15
EV-WIN-0009,T1059.001,ssa_windows_msbuild_inline.yml,high,86718,3001308,sysmon,high,PB-WINDOWS-EXEC,,2026-01-15
EV-WIN-0010,T1218.003,ssa_windows_clmxransom.yml,medium,86719,,sysmon,medium,PB-WINDOWS-PRIVESC,post/windows/escalate/printtoken,2026-01-15
EV-WIN-0011,T1218.003,,,86720,,sysmon,medium,PB-WINDOWS-EXEC,,2026-01-15
EV-WIN-0012,T1218.003,ssa_windows_cmstp.yml,high,86721,3001309,sysmon,high,PB-WINDOWS-EXEC,,2026-01-15
EV-WIN-0013,T1047,ssa_windows_wmi_exec.yml,high,86722,,sysmon,high,PB-AD-LATERAL,exploit/windows/smb/wmi_exec,2026-01-15
EV-WIN-0014,T1218.005,ssa_windows_msiexec.yml,high,86723,3001204,sysmon,high,PB-WINDOWS-PERSIST,exploit/windows/smb/smb_delivery,2026-01-15
EV-MAC-0001,T1059.002,ssa_macos_osascript_shell.yml,medium,86724,,unifiedlog,high,PB-MAC-EXEC,,2026-01-15
EV-MAC-0002,T1552.001,ssa_macos_keychain_read.yml,high,86725,,unifiedlog,high,PB-MAC-CREDS,,2026-01-15
EV-MAC-0003,T1543.004,,,86726,,unifiedlog,medium,PB-MAC-PERSIST,,2026-01-15
EV-MAC-0004,T1548.003,,,86727,,unifiedlog,medium,PB-MAC-PRIVESC,,2026-01-15
EV-MAC-0005,T1548.003,,,86728,,sudo.log,medium,PB-MAC-PRIVESC,exploit/multi/handler,2026-01-15
EV-CTR-0001,T1610,ssa_docker_privileged_run.yml,critical,86730,,docker,high,PB-CONTAINER-ESCAPE,exploit/linux/local/docker,2026-01-15
EV-CTR-0002,T1609,ssa_kubectl_exec_pod.yml,medium,86731,,k8s-audit,high,PB-CONTAINER-ESCAPE,,2026-01-15
EV-CTR-0003,T1609,,,86732,,k8s-audit,high,PB-CONTAINER-ESCAPE,,2026-01-15
EV-CTR-0004,T1610,,,86733,,k8s-audit,high,PB-CONTAINER-ESCAPE,,2026-01-15
EV-CTR-0005,T1610,ssa_linux_nsenter.yml,critical,101004,,auditd,high,PB-CONTAINER-ESCAPE,exploit/linux/local/docker,2026-01-15
EV-CI-0001,T1195.002,ssa_jenkins_groovy_console.yml,medium,86740,3001401,proxy,medium,PB-CICD-ABUSE,,2026-01-15
EV-CI-0002,T1195.002,ssa_gitlab_runner_shell.yml,medium,86741,3001402,gitlab-audit,medium,PB-CICD-ABUSE,,2026-01-15
EV-CI-0003,T1195.002,ssa_github_actions_checkout.yml,medium,86742,3001403,gh-audit,medium,PB-CICD-ABUSE,,2026-01-15
'''.lstrip()

FILES["10-crosswalk/control-detection/control-detection.csv"] = r'''
control_id,sheet,severity,cwe_id,anchor_layer,anchor_kind,suricata_sid,wazuh_rule,sigma_rule,suricata_file,wazuh_file,confidence,residual_gap,reviewed
CSRF-1,Cross_Site_Request_Forgery_Cheat_Sheet,critical,CWE-352,network,suricata,3001011,,,ssa-web-attacks.rules,,medium,TLS-terminated bodies invisible,2026-01-15
CSRF-2,Cross_Site_Request_Forgery_Cheat_Sheet,critical,CWE-352,host,wazuh,,100012,ssa_web_csrf_missing_token.yml,ssa-baseline.xml,medium,Only for apps writing structured logs,2026-01-15
AUTH-1,Authentication_Cheat_Sheet,critical,CWE-308,host,wazuh,,100010,ssa_auth_mfa_bypass_attempt.yml,ssa-baseline.xml,medium,Successful MFA-less access is hard to detect,2026-01-15
AUTH-2,Authentication_Cheat_Sheet,high,CWE-384,application,sigma,,,ssa_session_weak_identifier.yml,,medium,Needs application telemetry,2026-01-15
AUTH-3,Authentication_Cheat_Sheet,high,CWE-306,application,sigma,,,ssa_sensitive_action_no_reauth.yml,,medium,Needs application telemetry,2026-01-15
AUTH-4,Authentication_Cheat_Sheet,high,CWE-307,host,wazuh,,100011,,ssa-baseline.xml,high,,2026-01-15
AUTH-7,Authentication_Cheat_Sheet,high,CWE-209,audit,wazuh,,100012,ssa_auth_user_enumeration.yml,ssa-baseline.xml,medium,Successful enumeration without a follow-on logon is invisible,2026-01-15
AUTHZ-2,Authorization_Cheat_Sheet,critical,CWE-863,application,sigma,,,ssa_authz_deny_by_default.yml,,medium,Needs application telemetry,2026-01-15
AUTHZ-3,Authorization_Cheat_Sheet,high,CWE-862,audit,wazuh,,100013,ssa_authz_missing_check.yml,ssa-baseline.xml,medium,Silent IDOR leaves no host evidence,2026-01-15
SESSION-3,Session_Management_Cheat_Sheet,high,CWE-384,audit,wazuh,,100014,ssa_session_rotation_missing.yml,ssa-baseline.xml,medium,,2026-01-15
SESSION-4,Session_Management_Cheat_Sheet,high,CWE-1004,network,suricata,3001012,,,ssa-web-attacks.rules,,high,,2026-01-15
INPUT-4,Input_Validation_Cheat_Sheet,high,CWE-20,network,suricata,3001001,,,ssa-web-attacks.rules,,high,,2026-01-15
INPUT-8,Input_Validation_Cheat_Sheet,high,CWE-918,network,suricata,3001003,,,ssa-web-attacks.rules,,high,,2026-01-15
INJ-1,SQL_Injection_Cheat_Sheet,critical,CWE-89,network,suricata,3001005,,,ssa-web-attacks.rules,,high,Encrypted traffic,2026-01-15
INJ-1,SQL_Injection_Cheat_Sheet,critical,CWE-89,host,wazuh,,100020,,ssa-baseline.xml,ssa-baseline.xml,high,,2026-01-15
INJ-2,SQL_Injection_Cheat_Sheet,high,CWE-284,audit,wazuh,,100015,,ssa-baseline.xml,ssa-baseline.xml,medium,Needs database audit forwarding,2026-01-15
DOM-1,XSS_Prevention_Cheat_Sheet,high,CWE-79,network,suricata,3001006,,,ssa-web-attacks.rules,,high,,2026-01-15
DOM-1,XSS_Prevention_Cheat_Sheet,high,CWE-79,host,wazuh,,100021,,ssa-baseline.xml,ssa-baseline.xml,high,,2026-01-15
DOM-4,XSS_Prevention_Cheat_Sheet,high,CWE-1021,network,suricata,3001005,,,ssa-web-attacks.rules,,medium,CSP header presence needs TLS termination,2026-01-15
UPL-2,File_Upload_Cheat_Sheet,high,CWE-434,host,wazuh,,100030,,ssa-baseline.xml,ssa-baseline.xml,high,,2026-01-15
UPL-5,File_Upload_Cheat_Sheet,high,CWE-434,network,suricata,3001007,,,ssa-web-attacks.rules,,medium,,2026-01-15
LOG-4,Logging_Cheat_Sheet,medium,CWE-117,host,wazuh,,100032,,ssa-baseline.xml,ssa-baseline.xml,high,,2026-01-15
LOG-7,Logging_Cheat_Sheet,medium,CWE-778,network,suricata,3001007,,,ssa-web-attacks.rules,,medium,,2026-01-15
CRYPTO-1,Cryptographic_Storage_Cheat_Sheet,high,CWE-327,host,sigma,,,ssa_crypto_weak_algorithm.yml,,medium,Needs code or library telemetry,2026-01-15
CRYPTO-4,Cryptographic_Storage_Cheat_Sheet,high,CWE-327,host,sigma,,,ssa_crypto_ecb_static_iv.yml,,medium,Needs code or library telemetry,2026-01-15
SECRETS-3,Secrets_Management_Cheat_Sheet,high,CWE-798,audit,wazuh,,100016,ssa_secret_in_log.yml,ssa-baseline.xml,medium,,2026-01-15
REST-1,REST_Security_Cheat_Sheet,high,CWE-319,network,suricata,3001009,,,ssa-web-attacks.rules,,medium,Only cleartext traffic is visible,2026-01-15
REST-7,REST_Security_Cheat_Sheet,medium,CWE-436,network,suricata,3001010,,,ssa-web-attacks.rules,,high,,2026-01-15
GQL-2,GraphQL_Cheat_Sheet,medium,CWE-200,network,suricata,3001013,,,ssa-web-attacks.rules,,medium,Encrypted traffic,2026-01-15
GQL-4,GraphQL_Cheat_Sheet,high,CWE-400,application,sigma,,,ssa_graphql_complexity_abuse.yml,,medium,Needs gateway telemetry,2026-01-15
LLM-01,LLM_Prompt_Injection_Cheat_Sheet,critical,CWE-1427,application,sigma,,,ssa_llm_prompt_injection.yml,,medium,Semantic evasion,2026-01-15
LLM-02,LLM_Prompt_Injection_Cheat_Sheet,high,CWE-1426,application,sigma,,,ssa_llm_output_schema_violation.yml,,medium,Semantic evasion,2026-01-15
LLM-05,LLM_Prompt_Injection_Cheat_Sheet,high,CWE-250,audit,sigma,,,ssa_llm_tool_privilege_escalation.yml,,medium,Needs gateway audit,2026-01-15
DES-3,Deserialization_Cheat_Sheet,medium,CWE-502,audit,sigma,,,ssa_deserialization_integrity.yml,,medium,,2026-01-15
'''.lstrip()

FILES["10-crosswalk/control-detection/README.md"] = r'''
# Control to Detection Crosswalk

## 1. Normative statement

> Every OWASP control in `01-intel/cheat-sheets/owasp/owasp-controls.csv` has
> **at least one** defensive anchor in this repository. A control without an
> anchor is a build failure (`COV-001`), not a documentation debt.

A single control may have several anchors at different layers (see `INJ-1`:
Suricata `3001005` for the network, Wazuh `100020` for the application log).
This is intentional: defence in depth, and each layer sees a different failure
mode.

## 2. Columns

| Column | Meaning |
|---|---|
| `control_id` | `<SHEET>-<n>`, matches `owasp-controls.csv` |
| `anchor_layer` | `network` / `host` / `audit` / `application` |
| `anchor_kind` | `suricata` / `wazuh` / `sigma` |
| `suricata_sid` | SSA sid from the 3001xxx range |
| `wazuh_rule` | SSA rule id from the 1000xx/1010xx range |
| `sigma_rule` | portable detection file name |
| `confidence` | `high` / `medium` / `low` detection confidence |
| `residual_gap` | what remains undetectable - **must not be empty for high-severity controls without a note** |
| `reviewed` | last review date |

## 3. Verification

```bash
python tools/ssactl.py verify --root . --coverage
```

Implementation contract:

* For each distinct `control_id`, count rows. Zero rows -> `COV-001`.
* For each row, at least one of `suricata_sid`, `wazuh_rule`, `sigma_rule` must be
  set. Empty -> `COV-001`.
* Every `suricata_sid` must exist in `06-defense/suricata/rules/*.rules`.
* Every `wazuh_rule` must exist in `06-defense/wazuh/rules/*.xml`.
* Every `sigma_rule` must exist in `06-defense/sigma/*.yml`.

## 4. Generation

This file is generated by `11-automation/scripts/render_crosswalks.py` from the
control catalogue plus the rule inventories. Regenerate after adding a rule:

```bash
python 11-automation/scripts/render_crosswalks.py --root . --target control-detection
python tools/ssactl.py verify --root . --coverage --strict
```
'''.lstrip()

FILES["10-crosswalk/attack-coverage/attack-coverage.csv"] = r'''
technique_id,tactic,name,playbooks,payload_ids,wordlists,evasion_ids,modules,sigma_rules,wazuh_rules,suricata_sids,emulations,coverage_state,gap_note,last_reviewed
T1059.001,Execution,PowerShell,PB-WINDOWS-EXEC,,,EV-WIN-0009,post/multi/reverse_ssh,ssa_windows_lolbin_anomaly.yml,86718,3001308,,full,,2026-01-15
T1059.003,Execution,Windows Command Shell,PB-WINDOWS-EXEC,,,EV-WIN-0001,exploit/multi/handler,ssa_windows_psexec.yml,86710,3001301,EV-WIN-0001,full,,2026-01-15
T1059.004,Execution,Unix Shell,PB-LINUX-EXEC,PL-OS-LNX-0001,shell-words,EV-LNX-0002,post/multi/reverse_ssh,ssa_linux_editor_shell.yml,101001,,,full,,2026-01-15
T1059.006,Execution,Python,PB-LINUX-EXEC,PL-OS-LNX-0002,,EV-LNX-0005,,ssa_interpreter_shell.yml,101002,,,full,,2026-01-15
T1003.006,Credential Access,DCShadow,PB-AD-KERBEROS,,,EV-WIN-0001,post/windows/gather/enum_domains,ssa_ad_dcsync.yml,86750,,EV-AD-0001,full,,2026-01-15
T1021.002,Remote Services,SMB Admin Shares,PB-AD-LATERAL,,,EV-WIN-0001,exploit/windows/smb/psexec,ssa_windows_psexec.yml,86710,3001301,EV-WIN-0001,full,,2026-01-15
T1027,Defense Evasion,Obfuscation,PB-WINDOWS-EXEC,PL-OS-LNX-0002,,EV-WIN-0010,evasion/windows/defender/processhacker,,86719,,,offensive-only,No portable detection for generic obfuscation,2026-01-15
T1047,Execution,WMI,PB-AD-LATERAL,,,EV-WIN-0013,exploit/windows/smb/wmi_exec,ssa_windows_wmi_exec.yml,86722,,EV-WIN-0013,full,,2026-01-15
T1053.003,Persistence,Cron,PB-LINUX-PERSIST,PL-OS-LNX-0004,,EV-LNX-0016,,ssa_linux_cron_persistence.yml,101010,3001201,,full,,2026-01-15
T1053.005,Persistence,Scheduled Task,PB-WINDOWS-PERSIST,,,EV-WIN-0003,exploit/windows/smb/smb_exec,ssa_windows_schtasks.yml,86712,3001302,,full,,2026-01-15
T1068,Privilege Escalation,Exploitation for PrivEsc,PB-CONTAINER-ESCAPE,,,EV-CTR-0001,exploit/linux/local/docker,ssa_docker_privileged_run.yml,86730,,EV-CTR-0001,offensive-only,K8s audit not enabled by default,2026-01-15
T1078,Defense Evasion,Valid Accounts,PB-AD-KERBEROS,PL-API-0008,userpass-combinations.txt,EV-CI-0001,,ssa_cloud_iam_anomaly.yml,86751,,,full,,2026-01-15
T1083,Discovery,File and Directory Discovery,PB-NET-ENUM,,,,auxiliary/scanner/filesystem/dir_file_enum,,,,,gap,No host rule for brute-force filesystem enumeration,2026-01-15
T1090,Proxy,Proxy,PB-NET-PIVOT,,,EV-LNX-0015,post/multi/reverse_ssh,ssa_ssh_pivot.yml,101020,3001207,,full,,2026-01-15
T1098.004,Persistence,SSH Authorized Keys,PB-LINUX-PERSIST,PL-OS-LNX-0003,,EV-LNX-0003,,ssa_linux_authorized_keys.yml,101011,,,full,,2026-01-15
T1105,Ingress Tool Transfer,Ingress Tool Transfer,PB-WINDOWS-EXEC,,,EV-WIN-0005,auxiliary/downloader/HttpClient,ssa_windows_certutil.yml,86714,3001202,,full,,2026-01-15
T1110.003,Credential Access,Password Spraying,PB-WEB-AUTHBYPASS,PL-API-0008,common-passwords.txt,,,ssa_linux_ssh_bruteforce.yml,100011,3001404,,full,,2026-01-15
T1134.005,Privilege Escalation,Constrained Delegation,PB-AD-KERBEROS,,,,post/windows/escalate/constrained_delegation,ssa_ad_constrained_delegation.yml,86752,,,full,,2026-01-15
T1190,Initial Access,Exploit Public-Facing App,PB-WEB-SQLI|PB-WEB-XSS|PB-WEB-SSRF,PL-WEB-SQLI-0001|PL-WEB-XSS-0001|PL-WEB-SSRF-0010,injection-words.txt|xss-words.txt|ssrf-words.txt,EV-WIN-0007,exploit/multi/http/struts_code_exec,ssa_web_sqli_probe.yml,100020,3001001,CH-001,full,,2026-01-15
T1195.002,Initial Access,Supply Chain Compromise,PB-CICD-ABUSE,,,EV-CI-0001,,ssa_jenkins_groovy_console.yml,86740,3001401,,full,,2026-01-15
T1218.003,Defense Evasion,System Binary Proxy Execution,PB-WINDOWS-EXEC|PB-WINDOWS-PRIVESC,,,EV-WIN-0010|EV-WIN-0002,evasion/windows/defender/processhacker,ssa_windows_lolbin_anomaly.yml,86719,,EV-WIN-0001,full,,2026-01-15
T1218.005,Defense Evasion,Mshta,PB-WINDOWS-EXEC,,,EV-WIN-0007,exploit/windows/smb/smb_delivery,ssa_windows_mshta.yml,86716,3001203,,full,,2026-01-15
T1218.010,Defense Evasion,Regsvr32,PB-WINDOWS-EXEC,,,EV-WIN-0006,exploit/windows/smb/smb_delivery,ssa_windows_regsvr32.yml,86715,3001202,,full,,2026-01-15
T1486,Impact,Data Encrypted for Impact,PB-RANSOMWARE,PL-OS-LNX-0004,,EV-LNX-0016,evasion/linux/last_stage/encryptor,ssa_linux_mass_encryption.yml,86801,,,full,,2026-01-15
T1490,Impact,Inhibit System Recovery,PB-RANSOMWARE,,,,,ssa_windows_shadow_copy_delete.yml,86802,,,full,,2026-01-15
T1548.003,Privilege Escalation,Bypass UAC / sudo abuse,PB-LINUX-PRIVESC|PB-WINDOWS-PRIVESC,PL-OS-LNX-0007,binaries-linux.txt,EV-LNX-0007,exploit/linux/sudo/local,ssa_linux_sudo_nonshell.yml,101101,,,full,,2026-01-15
T1552.001,Credential Access,Credentials In Files,PB-MAC-CREDS,PL-OS-LNX-0003,jwt-secrets.txt,EV-MAC-0002,,ssa_macos_keychain_read.yml,86725,,,full,,2026-01-15
T1552.005,Credential Access,IMDS,PB-CLOUD-AWS-IAM,PL-CLOUD-0002,,,auxiliary/gather/cloud/cloud_metadata,ssa_cloud_metadata_access.yml,86753,3001003,,full,,2026-01-15
T1556.003,Credential Access,Shadow Credentials,PB-AD-KERBEROS,,,,post/windows/gather/enum_domains,ssa_ad_shadow_credentials.yml,86754,,EV-AD-0001,full,,2026-01-15
T1558.003,Credential Access,Kerberoasting,PB-AD-KERBEROS,,,EV-WIN-0003,,ssa_ad_kerberoast.yml,86751,,,full,,2026-01-15
T1558.004,Credential Access,AS-REP Roasting,PB-AD-KERBEROS,,,,,ssa_ad_asrep_roast.yml,86755,,,full,,2026-01-15
T1567,Exfiltration,Exfiltration Over Web Service,PB-EXFIL,,PL-CLOUD-0001,,,,ssa_cloud_metadata_access.yml,86753,3001205,,detective-only,No egress volume baseline rule,2026-01-15
T1570,Lateral Movement,File Transfer Tools,PB-NET-PIVOT,,,EV-LNX-0015,post/multi/reverse_ssh,ssa_ssh_pivot.yml,101020,3001207,,full,,2026-01-15
T1609,Execution,Container Admin Command,PB-CONTAINER-ESCAPE,,,EV-CTR-0002,,ssa_kubectl_exec_pod.yml,86731,,,full,,2026-01-15
T1610,Privilege Escalation,Deploy Container,PB-CONTAINER-ESCAPE,PL-OS-LNX-0008,,EV-CTR-0001|EV-CTR-0005,exploit/linux/local/docker,ssa_docker_privileged_run.yml,101004,,EV-CTR-0001,full,,2026-01-15
T1649,Privilege Escalation,ADCS Abuse,PB-AD-KERBEROS,,,,post/windows/gather/enum_domains,ssa_ad_adcs_abuse.yml,86756,,,offensive-only,ESC1 depends on template misconfiguration,2026-01-15
T1595,Active Scanning,Active Scanning,PB-NET-ENUM,,,EV-LNX-0001,auxiliary/scanner/tcp/portscan,ssa_network_scan.yml,86700,3001401,,full,,2026-01-15
'''.lstrip()

FILES["10-crosswalk/api-contracts/README.md"] = r'''
# API Contracts

The archive is consumed by tools. This directory defines the contracts those
tools may rely on. Anything not described here is an implementation detail and
may change without a major version bump.

## 1. Artefacts and their consumers

| Artefact | Format | Producer | Consumers |
|---|---|---|---|
| `02-payloads/**/payloads.json` | `12-schemas/payload.schema.json` | humans (reviewed) | `ssactl index`, `render_crosswalks` |
| `03-wordlists/**.txt` | one token per line | upstream ingestion | `ffuf`, `hydra`, `sqlmap` |
| `03-wordlists/index/wordlist.db` | SQLite 3.35+ | `ssactl index` | SQL clients, scripts |
| `04-evasion/index/evasion-index.csv` | CSV | humans | `render_crosswalks`, docs |
| `06-defense/suricata/rules/*.rules` | Suricata rule syntax | humans | Suricata |
| `06-defense/wazuh/rules/*.xml` | Wazuh `<group>` XML | humans | Wazuh manager |
| `06-defense/sigma/*.yml` | Sigma 2.0 | humans | SIEM converters |
| `10-crosswalk/*.csv` | CSV, header required | `render_crosswalks` | docs, audits |
| `08-threatintel/ioc/*.json` | `12-schemas/ioc.schema.json` | feeds + humans | SIEM, proxies |

## 2. CSV dialect (normative)

* Encoding UTF-8, LF endings, **no** BOM.
* First row is a header, snake_case.
* No trailing spaces in fields.
* A field may contain `|` as a multi-value separator (never `,`).
* Empty field = not applicable; the string `n/a` is only allowed where the
  schema says so.
* Line ordering is deterministic (sorted by the join key) so `git diff` stays
  readable and the manifest hash stays stable.

## 3. Schema compatibility

* Schemas declare `$id` and `$schema: https://json-schema.org/draft/2020-12/schema`.
* Adding an **optional** property is a minor change.
* Adding a **required** property or changing a pattern is a major change and
  requires a `CHANGELOG.md` entry plus a migration note in
  `14-docs/standards/knowledge-format.md`.
* Every schema has a `$comment` stating which validator features it needs.

## 4. The unified index contract

`03-wordlists/index/wordlist.db` promises:

| Promise | Guarantee |
|---|---|
| Stable schema | `index_meta.schema_version` |
| Deterministic build | same inputs -> byte-identical logical content |
| Idempotent | `ssactl index` twice == once |
| Transactional | a failed build leaves the previous DB intact (temp file + rename) |
| Recoverable | `wordlist.db` is git-ignored and rebuildable from committed sources |
'''.lstrip()

FILES["10-crosswalk/api-contracts/control-detection.schema.json"] = r'''
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ssa.local/schemas/control-detection.schema.json",
  "title": "SSA crosswalk row - control to detection",
  "type": "object",
  "additionalProperties": false,
  "required": ["control_id", "anchor_layer", "anchor_kind", "confidence"],
  "properties": {
    "control_id":  { "type": "string", "pattern": "^[A-Z][A-Z0-9_]*-[0-9]+$" },
    "sheet":       { "type": "string" },
    "severity":    { "enum": ["critical", "high", "medium", "low", "info"] },
    "cwe_id":      { "type": "string", "pattern": "^CWE-[0-9]+$" },
    "anchor_layer":{ "enum": ["network", "host", "audit", "application"] },
    "anchor_kind": { "enum": ["suricata", "wazuh", "sigma"] },
    "suricata_sid":{ "type": ["integer", "null"], "minimum": 3001000, "maximum": 3001999 },
    "wazuh_rule":  { "type": ["string", "null"], "pattern": "^[0-9]{5,7}$" },
    "sigma_rule":  { "type": ["string", "null"], "pattern": "^[a-z0-9_]+\\.yml$" },
    "suricata_file": { "type": ["string", "null"] },
    "wazuh_file":  { "type": ["string", "null"] },
    "confidence":  { "enum": ["high", "medium", "low"] },
    "residual_gap":{ "type": "string" },
    "reviewed":    { "type": "string", "format": "date" }
  },
  "allOf": [
    {
      "$comment": "Exactly one anchor identifier must be present.",
      "anyOf": [
        { "required": ["suricata_sid"], "properties": { "suricata_sid": { "type": "integer" } } },
        { "required": ["wazuh_rule"],  "properties": { "wazuh_rule":  { "type": "string" } } },
        { "required": ["sigma_rule"],  "properties": { "sigma_rule":  { "type": "string" } } }
      ]
    },
    {
      "$comment": "The anchor_kind must match the identifier that is present.",
      "allOf": [
        { "if": { "properties": { "anchor_kind": { "const": "suricata" } } },
          "then": { "required": ["suricata_sid"] } },
        { "if": { "properties": { "anchor_kind": { "const": "wazuh" } } },
          "then": { "required": ["wazuh_rule"] } },
        { "if": { "properties": { "anchor_kind": { "const": "sigma" } } },
          "then": { "required": ["sigma_rule"] } }
      ]
    }
  ]
}
'''.lstrip()

# ===========================================================================
# 12-schemas
# ===========================================================================

FILES["12-schemas/payload.schema.json"] = r'''
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ssa.local/schemas/payload.schema.json",
  "title": "SSA payload record",
  "description": "One offensive payload with enough metadata to be selected by context and to be mapped to detections.",
  "type": "object",
  "additionalProperties": false,
  "required": ["payload_id", "cwe_id", "context", "surface", "payload", "severity", "classification", "provenance"],
  "properties": {
    "payload_id": {
      "type": "string",
      "pattern": "^PL-[A-Z0-9-]+-[0-9]{4}$",
      "description": "Stable identifier, never reused."
    },
    "cwe_id":   { "type": "string", "pattern": "^CWE-[0-9]+$" },
    "context":  { "type": "string" },
    "surface":  { "type": "string" },
    "engine":  { "type": "string" },
    "payload": { "type": "string", "minLength": 1, "maxLength": 4096 },
    "severity": { "enum": ["critical", "high", "medium", "low", "info"] },
    "classification": { "enum": ["T0", "T1", "T2"] },
    "tags":    { "type": "array", "items": { "type": "string" }, "maxItems": 32, "uniqueItems": true },
    "notes":   { "type": "string", "maxLength": 2000 },
    "provenance": {
      "type": "object",
      "additionalProperties": false,
      "required": ["source", "ref"],
      "properties": {
        "source":   { "type": "string", "description": "key from the lock file, e.g. PAT" },
        "ref":      { "type": "string", "description": "pinned upstream ref, e.g. master@2026-01-15" },
        "secondary": { "type": "string" },
        "derived_from": { "type": "array", "items": { "type": "string" } }
      }
    },
    "crosswalk": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "fuzz_wordlist": { "type": "string" },
        "detections": { "type": "array", "items": { "type": "string" } },
        "playbook":     { "type": "string" },
        "module":       { "type": "string" }
      }
    }
  },
  "$comment": "The (cwe_id, context, surface, engine, normalised payload) tuple is the index join key. The unique index lives in 03-wordlists/index/schema.sql."
}
'''.lstrip()

FILES["12-schemas/wordlist-entry.schema.json"] = r'''
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ssa.local/schemas/wordlist-entry.schema.json",
  "title": "SSA wordlist entry (JSON representation of a .txt line)",
  "description": "Wordlists on disk are plain text; this schema governs the JSON form used by the index and the feed mechanism.",
  "type": "object",
  "additionalProperties": false,
  "required": ["token", "surface"],
  "properties": {
    "token": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[^\\u0000-\\u001f\\u007f]+$",
      "description": "No control characters. Prevents log injection and index poisoning (threat model S6)."
    },
    "surface": {
      "enum": ["parameter", "header", "cookie", "url", "path", "body",
               "username", "password", "host", "cidr"]
    },
    "cwe_id":    { "type": "string", "pattern": "^CWE-[0-9]+$" },
    "context":   { "type": "string" },
    "source":    { "type": "string", "description": "SECLISTS or internal" },
    "provenance": { "type": "string" },
    "weight":    { "type": "number", "minimum": 0, "maximum": 1 }
  },
  "$comment": "Control characters are forbidden on purpose - see 00-governance/threat-model.md S6."
}
'''.lstrip()

FILES["12-schemas/evasion.schema.json"] = r'''
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ssa.local/schemas/evasion.schema.json",
  "title": "SSA evasion primitive",
  "description": "A GTFOBins-style abuse of a trusted binary, promoted to a stable EV-* identifier and required to carry at least one detection anchor.",
  "type": "object",
  "additionalProperties": false,
  "required": ["evasion_id", "platform", "binary", "technique_id", "primitive", "provenance"],
  "properties": {
    "evasion_id":   { "type": "string", "pattern": "^EV-(LNX|WIN|MAC|CTR|CI)-[0-9]{4}$" },
    "platform":     { "enum": ["linux", "windows", "macos", "containers", "ci", "other"] },
    "binary":       { "type": "string", "minLength": 1, "maxLength": 128 },
    "technique_id": { "type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$" },
    "cwe_id":       { "type": "string", "pattern": "^CWE-[0-9]+$" },
    "primitive":    { "type": "string", "minLength": 1, "maxLength": 512 },
    "triage_cost":  { "enum": ["low", "medium", "high"] },
    "mitre":        { "type": "array", "items": { "type": "string" } },
    "runbook":      { "type": "string" },
    "module":       { "type": "string" },
    "host_rule":    { "type": "string" },
    "network_rule": { "type": "string" },
    "sigma":        { "type": "string" },
    "provenance":   { "type": "string" },
    "notes":        { "type": "string" }
  },
  "$comment": "host_rule, network_rule or sigma must be present - enforced by ssactl verify --coverage."
}
'''.lstrip()

FILES["12-schemas/detection.schema.json"] = r'''
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ssa.local/schemas/detection.schema.json",
  "title": "SSA detection record",
  "description": "Vendor-neutral description of one detection, used by the crosswalk validators and the coverage report.",
  "type": "object",
  "additionalProperties": false,
  "required": ["detection_id", "kind", "layer", "severity", "confidence", "maps_to"],
  "properties": {
    "detection_id": { "type": "string", "pattern": "^(ssa_[a-z0-9_]+|[0-9]{6,7})$" },
    "kind":   { "enum": ["suricata", "wazuh", "sigma", "cloudtrail", "kubernetes", "proxy", "edr"] },
    "layer":  { "enum": ["network", "host", "audit", "application", "cloud"] },
    "title":  { "type": "string" },
    "severity": { "enum": ["critical", "high", "medium", "low", "info"] },
    "confidence": { "enum": ["high", "medium", "low"] },
    "maps_to": {
      "type": "object",
      "additionalProperties": false,
      "description": "At least one crosswalk target is required.",
      "properties": {
        "control_id":   { "type": "array", "items": { "type": "string" } },
        "evasion_id":   { "type": "array", "items": { "type": "string" } },
        "technique_id": { "type": "array", "items": { "type": "string" } },
        "cwe_id":       { "type": "array", "items": { "type": "string" } },
        "payload_id":   { "type": "array", "items": { "type": "string" } }
      },
      "minProperties": 1
    },
    "falsepositives": { "type": "array", "items": { "type": "string" } },
    "emulation": { "type": "string" },
    "reviewed":  { "type": "string" },
    "residual_gap": { "type": "string" }
  }
}
'''.lstrip()

FILES["12-schemas/ioc.schema.json"] = r'''
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ssa.local/schemas/ioc.schema.json",
  "title": "SSA indicator of compromise",
  "type": "object",
  "additionalProperties": false,
  "required": ["id", "type", "value", "confidence", "severity", "source", "first_seen", "last_seen", "tlp", "expires"],
  "properties": {
    "id":       { "type": "string", "pattern": "^IOC-[0-9]{4}-[0-9]{6}$" },
    "type":     { "enum": ["ipv4", "ipv6", "domain", "url", "file", "email", "registry", "mutex", "user-agent", "certificate"] },
    "value":    { "type": "string", "minLength": 1, "maxLength": 2048 },
    "hash_alg": { "enum": ["md5", "sha1", "sha256", "imphash", "ssdeep"] },
    "confidence": { "type": "integer", "minimum": 0, "maximum": 100 },
    "severity":   { "enum": ["critical", "high", "medium", "low", "info"] },
    "source":     { "type": "string", "description": "FEED-* id from feed-registry.yaml" },
    "first_seen": { "type": "string", "format": "date-time" },
    "last_seen":  { "type": "string", "format": "date-time" },
    "tlp":      { "enum": ["white", "green", "amber", "amber+strict", "red"] },
    "tags":     { "type": "array", "items": { "type": "string" }, "uniqueItems": true },
    "mitre":    { "type": "array", "items": { "type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$" } },
    "expires":  { "type": "string", "format": "date-time" },
    "context":  { "type": "string", "maxLength": 1024 }
  },
  "allOf": [
    {
      "$comment": "File indicators must declare the hash algorithm.",
      "if": { "properties": { "type": { "const": "file" } } },
      "then": { "required": ["hash_alg"] }
    },
    {
      "$comment": "Blocking requires high confidence.",
      "if": { "properties": { "confidence": { "maximum": 70 } } },
      "then": { "properties": { "severity": { "enum": ["medium", "low", "info"] } } }
    }
  ]
}
'''.lstrip()

FILES["12-schemas/README.md"] = r'''
# Schema Registry

| Schema | Governs | Consumers |
|---|---|---|
| `payload.schema.json` | `02-payloads/**/payloads.json` | `ssactl index`, `validate` |
| `wordlist-entry.schema.json` | JSON wordlist feeds, index ingestion | `build_payload_index.py` |
| `evasion.schema.json` | `04-evasion/index/evasion-index.csv` | `render_crosswalks.py` |
| `detection.schema.json` | detection inventory rows | `verify --coverage` |
| `ioc.schema.json` | `08-threatintel/ioc/*.json` | SIEM ingestion |
| `crosswalk-row.schema.json` | `10-crosswalk/**.csv` | `verify` |

## Validation levels

```bash
# Level 1 - structural, no dependencies (default, always available)
python tools/ssactl.py validate --root .

# Level 2 - full JSON Schema draft 2020-12 (requires pip install jsonschema)
python tools/ssactl.py validate --root . --strict-json
```

Level 1 checks: parseable JSON, top-level `schema` or known filename, required
top-level keys, array lengths, and pattern checks on the identifier fields that
the crosswalk validator depends on. It is deliberately shallow so the archive
can be verified on an air-gapped host with only the Python standard library.

Level 2 is what CI runs on a connected runner.

## Change policy

See `10-crosswalk/api-contracts/README.md` §3. Any required-property addition is
a major version change and requires a migration note.

## Adding a schema

1. Create `12-schemas/<name>.schema.json` with `$id` and `$comment`.
2. Register the governed paths in `tools/ssactl/validate.py` (`TARGETS`).
3. Add a sample artifact that must pass.
4. Run `python tools/ssactl.py validate --root .`.
'''.lstrip()