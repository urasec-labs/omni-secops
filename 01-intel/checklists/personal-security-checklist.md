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
