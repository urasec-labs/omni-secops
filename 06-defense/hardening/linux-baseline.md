# Linux Hardening Baseline

Derived from `01-intel/checklists/personal-security-checklist.md`,
`OWASP Cheat Sheet Series` and CIS Linux benchmarks. Ordered by impact.

## 1. SSH (`/etc/ssh/sshd_config`)

```text
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers deploy@10.0.0.5 opsadmin      # allow-list, not DenyUsers
AllowGroups ssh-users
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 20
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
```

```bash
sshd -T | grep -Ei 'permitroot|passwordauth|maxauth|allowusers|allowgroups|permittunnel'
```

## 2. Kernel and sysctl

```text
# /etc/sysctl.d/99-hardening.conf
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.ip_forward = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
```

```bash
sysctl --system
# verify
sysctl net.ipv4.conf.all.accept_redirects net.ipv4.ip_forward
```

## 3. Mount options

```text
# /etc/fstab
/tmp     tmpfs   defaults,noexec,nosuid,nodev   0 0
/dev/shm tmpfs   defaults,noexec,nosuid,nodev   0 0
```

## 4. Services

```bash
systemctl list-unit-files --state=enabled
systemctl mask cups.service avahi-daemon.service bluetooth.service 2>/dev/null
# inventory before masking - never mask blindly on a production host
```

| Service | Action |
|---|---|
| `cups`, `avahi-daemon` | mask unless print/mDNS is required |
| `telnet`, `rsh`, `rlogin` | remove packages |
| `rpcbind`, `nfs` | disable unless required |
| `cockpit` | disable unless managed |

## 5. Packages and updates

```bash
apt-get update && apt-get -y upgrade
apt-get -y autoremove
# unattended security upgrades
dpkg-reconfigure -plow unattended-upgrades
# audit software
dpkg -l | grep -E '^ii' | awk '{print $2, $3}' > /tmp/pkg-inventory.txt
```

## 6. File permissions audit

```bash
# world-writable files outside of /tmp, /var/tmp, /dev/shm
find / -xdev -perm -0002 -type f 2>/dev/null | grep -vE '^/(tmp|var/tmp|dev/shm)/'
# SUID / SGID
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
# audit rules
auditd -w /etc/passwd -p wa -k passwd
auditd -w /etc/group  -p wa -k group
auditd -w /etc/sudoers -p wa -k sudoers
```

## 7. Mandatory access control

```bash
setenforce 1
grep -v '^#' /etc/selinux/config | grep -v '^$'
# AppArmor
aa-status
aa-enforce /usr/sbin/sshd
```

## 8. Verification one-liner

```bash
# run after every change and paste the output into the change ticket
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|maxauthtries' && \
sysctl -a 2>/dev/null | grep -E 'accept_redirects|ip_forward' && \
find / -xdev -perm -4000 -type f 2>/dev/null | wc -l
```
