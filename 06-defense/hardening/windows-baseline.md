# Windows and Active Directory Hardening Baseline

## 1. Authentication policy (local + domain)

```powershell
# require complex passwords
secedit /export /cfg $env:TEMP\sec.cfg
# then edit: PasswordComplexity = 1 ; PasswordLength = 14
secedit /configure /cfg $env:TEMP\sec.cfg /db secedit.sdb /quiet

# account lockout
net accounts
# lockout threshold 5, window 15, duration 30

# LAPS
Get-LapsPolicy | Format-List
```

## 2. SMB signing (AD-03, critical)

```powershell
# domain controllers
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
Set-SmbServerConfiguration -RequireSecurityMode $true -EnableSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecurityMode $true -EnableSecuritySignature $true -Force

# verify
Get-SmbServerConfiguration | Select EnableSMB2Protocol, EnableSecuritySignature, RequireSecurityMode
Get-SmbClientConfiguration | Select EnableSecuritySignature, RequireSecurityMode
```

## 3. SMB hardening registry

```text
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
  EnableSMB2Protocol            = 1
  SmbServerSignature            = 1     (require)
  SmbClientSignature            = 1     (require)
HKLM\SYSTEM\CurrentControlSet\Control\FileServer
  Smb2Protocols                 = 0x0311 (disable SMB1, enable 2.0.2 + 2.1)
  EnableSMBQUIC                 = 0     (disable QUIC transport)
```

## 4. Kerberos (AD-01, AD-02)

```powershell
# AES only on all DCs
Get-ADDomainController -Filter * |
  ForEach-Object {
    Set-ADObject -Identity $_ -Replace @{
      'msDS-SupportedEncryptionTypes' = 31   # AES128/AES256/RC4(allowed during migration)
      'msDS-NoKerberosPreAuthentication' = $false
    }
  }

# accounts that must NOT require preauth (should be empty)
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4096)' |
  Select SamAccountName
```

## 5. LAPS and privileged access

```powershell
# no domain admin on workstations (AD-05)
Get-ADGroupMember "Domain Admins" |
  Where-Object { $_.objectClass -eq 'user' } |
  Select SamAccountName

# just-in-time admin (AD-06)
Get-MsolServicePlan | Format-Table DisplayName,PreAuthentication
```

## 6. PowerShell logging

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
  EnableScriptBlockLogging = 1
  ScriptBlockLoggingPath   = %windir%\System32\WindowsPowerShell\v1.0\Scripts
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
  EnableModuleLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
  EnableTranscription = 1
  MaxLogFiles        = 10
```

## 7. Defender and LSA protection

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -EnableNetworkProtection AuditMode   # then BlockMode
Set-MpPreference -MAPSReporting 2

# LSA protection (run at next boot)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1
# Credential Guard
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LsaCfgFlags -Value 1

# block WDigest
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DigestEncryption -Value 0 -PropertyType DWORD -Force
```

## 8. Application control

```powershell
# Smart App Control / WDAC audit mode first
Set-AppCompatPolicy -Name 'WDAC-Baseline' -PolicyFilePath C:\Windows\System32\CodeIntegrity\Policies\Active\{GUID}.cip
# then enable enforcement after a validation window
```

## 9. Verification one-liner

```powershell
Get-SmbServerConfiguration | Select EnableSecuritySignature, RequireSecurityMode
Get-MpPreference | Select DisableRealtimeMonitoring, EnableControlledFolderAccess
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4096)' | Measure-Object
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select RunAsPPL, LsaCfgFlags
```
