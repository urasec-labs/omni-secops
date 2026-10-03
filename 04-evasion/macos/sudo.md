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
