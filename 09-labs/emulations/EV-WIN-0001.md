# Emulation EV-WIN-0001 - Windows remote execution over SMB

| Field | Value |
|---|---|
| `emulation_id` | EV-WIN-0001 |
| `technique_id` | T1021.002 |
| `binary` | `psexec.exe` (Sysinternals / Impacket `psexec.py`) |
| `target` | lab Windows domain-joined host |
| `expected_sigma` | `ssa_windows_psexec.yml` |
| `expected_wazuh` | 100012 (logon after failures), Sysmon 1 |
| `expected_suricata` | 3001301 |
| `classification` | T0 (lab only) |

## 1. Steps

```powershell
# attacker box, lab network only
& .\PsExec.exe \\LAB-WEB-01 -u 'LAB\devops' -p 'LabOnlyPassw0rd!' -s cmd.exe /c "whoami > \\LAB-SHARE\evidence.txt"

# or Impacket
python3 psexec.py 'LAB\devops:LabOnlyPassw0rd!'@LAB-WEB-01 'whoami'
```

## 2. Expected telemetry

| Source | Signal |
|---|---|
| Windows 4624 | Type 3 logon from attacker host, `LogonType: 3`, service account |
| Windows 7045 | Service installed (`PSEXESVC`) |
| Sysmon 1 | `psexec.exe` parent `services.exe` |
| Sysmon 3 | Network connection by psexec |
| Suricata | `3001301` SMB admin-share traffic burst |

## 3. Result template

| Signal | Fired? |
|---|---|
| 7045 service install | |
| Sysmon 1 psexec | |
| 4624 type 3 | |
| Sigma `ssa_windows_psexec.yml` | |

## 4. Notes

Rule 7045 is the highest-fidelity indicator here and is often missed because
System and Security logs are not forwarded. Confirm forwarding before running
the emulation, otherwise you will record a false "gap".
