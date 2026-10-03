"""Curated content for 06-defense, 07-tooling, 08-threatintel, 09-labs."""

from __future__ import annotations

FILES: dict[str, str] = {}

# ===========================================================================
# 06-defense - suricata
# ===========================================================================

FILES["06-defense/suricata/rules/ssa-web-attacks.rules"] = r'''
# Sovereign Security Archive - Suricata web attack rules
# sid range 3001000-3001199 reserved for SSA web/application detections
# mapping: 10-crosswalk/control-detection/control-detection.csv
#
# 3001001 INPUT-4  server-side validation allow-list (SQLi tautology probe)
# 3001002 INPUT-8  SSRF / metadata access
# 3001003 INJ-1    parameterised query bypass attempt (SQL keywords)
# 3001004 DOM-1    reflected XSS probe
# 3001005 DOM-4    CSP report ingestion
# 3001006 UPL-5    upload attempt with executable extension
# 3001007 LOG-7    log forging attempt
# 3001008 REST-1   cleartext credential POST
# 3001009 REST-7   unsupported content type on API
# 3001010 CSRF-1    missing/blank CSRF token on state-changing request
# 3001011 SESSION-4 session cookie without Secure attribute
# 3001012 GQL-2    GraphQL introspection in production

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA INPUT-4 SQL injection boolean tautology probe"; flow:established,to_server; http.uri; content:"%27%20OR%20%271%27%3D%271"; nocase; http.query; content:"%27%20OR%201%3D1"; nocase; classtype:web-application-attack; reference:url,ssa.local/controls/INPUT-4; sid:3001001; rev:1; metadata:attack_target Web_Server, deployment Perimeter;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA INPUT-4 SQLi time-based probe (SLEEP)"; flow:established,to_server; http.uri; content:"SLEEP("; nocase; http.uri; content:"pg_sleep("; nocase; http.uri; content:"WAITFOR%20DELAY"; nocase; classtype:web-application-attack; reference:url,ssa.local/controls/INPUT-4; sid:3001002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA INPUT-8 SSRF attempt to cloud metadata service"; flow:established,to_server; http.uri; content:"169.254.169.254"; nocase; http.uri; content:"metadata.google.internal"; nocase; http.host; content:"100.100.100.200"; nocase; classtype:attempted-recon; reference:url,ssa.local/controls/INPUT-8; sid:3001003; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA INJ-1 JNDI lookup probe (Log4Shell class)"; flow:established,to_server; http.uri; content:"${jndi:"; nocase; http.header; content:"${jndi:"; nocase; http.user_agent; content:"${jndi:"; nocase; classtype:web-application-attack; reference:url,ssa.local/controls/INJ-1; sid:3001004; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA INJ-1 UNION SELECT injection probe"; flow:established,to_server; http.uri; content:"UNION"; nocase; http.uri; content:"SELECT"; nocase; http.query; content:"UNION%20SELECT"; nocase; classtype:web-application-attack; reference:url,ssa.local/controls/INJ-1; sid:3001005; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA DOM-1 reflected XSS probe"; flow:established,to_server; http.uri; content:"<script"; nocase; http.uri; content:"onerror="; nocase; http.uri; content:"javascript:"; nocase; http.query; content:"%3Cscript"; nocase; classtype:web-application-attack; reference:url,ssa.local/controls/DOM-1; sid:3001006; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA UPL-5 executable file upload extension"; flow:established,to_server; http.uri; content:".php"; nocase; http.uri; content:".jsp"; nocase; http.uri; content:".aspx"; nocase; http.uri; content:".phtml"; nocase; http.uri; content:".exe"; nocase; http.content_type; content:"multipart/form-data"; classtype:web-application-attack; reference:url,ssa.local/controls/UPL-5; sid:3001007; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA LOG-7 log forging attempt via CRLF in request"; flow:established,to_server; http.uri; content:"%0d%0a"; http.uri; content:"%0a"; http.uri; content:"%0d"; classtype:web-application-attack; reference:url,ssa.local/controls/LOG-7; sid:3001008; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA REST-1 cleartext credentials submitted over HTTP"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"password"; nocase; http.request_body; content:"passwd"; nocase; classtype:policy-violation; reference:url,ssa.local/controls/REST-1; sid:3001009; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA REST-7 unsupported media type on API endpoint"; flow:established,to_server; http.uri; content:"/api/"; http.content_type; content:"text/xml"; http.content_type; content:"application/x-java-serialized-object"; classtype:web-application-attack; reference:url,ssa.local/controls/REST-7; sid:3001010; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA CSRF-1 state-changing request without CSRF token"; flow:established,to_server; http.method; content:"POST|DELETE|PUT|PATCH"; http.cookie; content:"session="; http.request_body; content:"csrf_token|__RequestVerificationToken|authenticity_token"; nocase; threshold:type limit, track by_src, count 1, seconds 300; classtype:web-application-attack; reference:url,ssa.local/controls/CSRF-1; sid:3001011; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SSA SESSION-4 session cookie issued without Secure attribute"; flow:established,to_server; http.set_cookie; content:"session="; http.set_cookie; content:"Secure"; http.set_cookie; content:"HttpOnly"; threshold:type limit, track by_src, count 5, seconds 60; classtype:policy-violation; reference:url,ssa.local/controls/SESSION-4; sid:3001012; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA GQL-2 GraphQL introspection query in production"; flow:established,to_server; http.uri; content:"graphql"; http.request_body; content:"__schema"; http.request_body; content:"__type("; nocase; classtype:web-application-attack; reference:url,ssa.local/controls/GQL-2; sid:3001013; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA GQL-4 GraphQL query depth/complexity abuse (alias batching)"; flow:established,to_server; http.uri; content:"graphql"; threshold:type limit, track by_src, count 1, seconds 60; http.request_body; content:"alias"; http.request_body; content:"__typename"; classtype:web-application-attack; reference:url,ssa.local/controls/GQL-4; sid:3001014; rev:1;)
'''.lstrip()

FILES["06-defense/suricata/rules/ssa-evasion.rules"] = r'''
# Sovereign Security Archive - Suricata rules for evasion / living-off-the-land
# sid range 3001200-3001399 reserved for SSA evasion detections
# mapping: 10-crosswalk/evasion-detection/evasion-to-detection.csv

# EV-LNX-0016 cron persistence outbound fetch
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA EV-LNX-0016 periodic outbound fetch from cron-like beacon"; flow:established,to_server; http.host; content:"CRONBEACON"; nocase; http.uri; content:"/x.sh"; threshold:type limit, track by_src, count 3, seconds 300; classtype:policy-violation; sid:3001201; rev:1;)

# EV-WIN-0005 certutil download
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA EV-WIN-0005 certutil/bitsadmin payload download"; flow:established,to_server; http.user_agent; content:"certutil"; nocase; http.user_agent; content:"bitsadmin"; nocase; http.uri; content:"-urlcache"; http.uri; content:"/transfer"; http.uri; content:".dll"; http.uri; content:".exe"; classtype:policy-violation; sid:3001202; rev:1;)

# EV-WIN-0006/0007/0012 LOLBin remote content
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA EV-WIN-0007 mshta remote script fetch"; flow:established,to_server; http.uri; content:".hta"; nocase; http.user_agent; content:"MSHTA"; nocase; classtype:policy-violation; sid:3001203; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA EV-WIN-0014 msiexec remote MSI fetch"; flow:established,to_server; http.uri; content:".msi"; nocase; http.user_agent; content:"msiexec"; nocase; classtype:policy-violation; sid:3001204; rev:1;)

# CH-002 DNS tunnelling exfiltration indicator
alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA CH-002 possible DNS tunnelling - excessive label length"; dns.query; pcre:"/^[a-z0-9+\/=]{40,}/i"; threshold:type limit, track by_src, count 5, seconds 60; classtype:policy-violation; sid:3001205; rev:1;)

# EV-LNX-0015 ssh reverse tunnel
alert ssh $EXTERNAL_NET any -> $HOME_NET any (msg:"SSA EV-LNX-0015 interactive SSH session without PTY on internet-facing host"; flow:established,to_server; ssh.proto; content:"2"; threshold:type limit, track by_src, count 1, seconds 300; classtype:policy-violation; sid:3001206; rev:1;)

# HTTP CONNECT tunnel
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA PB-NET-PIVOT HTTP CONNECT tunnel to non-TLS port"; flow:established,to_server; http.method; content:"CONNECT"; http.port; content:"|80|"; startswith; classtype:policy-violation; sid:3001207; rev:1;)
'''.lstrip()

FILES["06-defense/suricata/rules/ssa-scanning.rules"] = r'''
# Sovereign Security Archive - reconnaissance and scanning detections
# sid range 3001400-3001599

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SSA PB-NET-ENUM SYN sweep - more than 20 distinct destination ports in 60s"; flags:S; threshold:type both, track by_src, count 20, seconds 60; classtype:network-scan; sid:3001401; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SSA PB-NET-ENUM sequential port probe 1-1024"; flags:S; flow:stateless; tcp.window_size:1024; threshold:type limit, track by_src, count 1, seconds 60; classtype:network-scan; sid:3001402; rev:1;)

alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA 03-wordlists subdomain bruteforce burst"; dns.query; threshold:type limit, track by_src, count 500, seconds 60; classtype:network-scan; sid:3001403; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA PB-NET-ENUM directory brute force burst"; flow:established,to_server; threshold:type limit, track by_src, count 500, seconds 60; classtype:web-application-attack; sid:3001404; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SSA PB-NET-PIVOT unusual high port outbound connection"; flow:established,to_client; tcp.dest_port:>1024; classtype:bad-unknown; sid:3001405; rev:1;)
'''.lstrip()

FILES["06-defense/suricata/thresholds/ssa-threshold.config"] = r'''
# Sovereign Security Archive - global threshold and suppression tuning
# Suricata 7.x syntax. Apply with: suricata -c suricata.yaml --engine-analysis
#
# Design rules
#   1. Every suppression MUST reference either a control_id or an evasion_id.
#   2. No blanket port or IP suppressions without a rule sid.
#   3. Suppressions expire: add `expires` and re-evaluate quarterly.

defaults:
  # do not alert on TLS SNI from known CDN edges - reduces FP on SAAS backends
  suppress:
    track: src_ip
  suppression:
    - id: 3001009; track: src_ip; type: ip; ip: 10.0.0.0/8; expires: 2026-04-01
      comment: "REST-1 suppressed inside RFC1918 during migration window SSA-2026-004"

threshold gen_id 1, type limit, track by_src, count 5, seconds 60
threshold gen_id 1, type limit, track by_dst, count 50, seconds 60
threshold gen_id 1, type both, track by_rule, count 3, seconds 300

# Rate limiting per rule class
threshold gen_id 1, type limit, track by_rule, count 20, seconds 60
threshold gen_id 1, type limit, track by_rule, count 100, seconds 300
'''.lstrip()

FILES["06-defense/suricata/README.md"] = r'''
# Suricata Detection Layer

| Field | Value |
|---|---|
| `detection_layer` | network |
| `source` | OISF/suricata @ 7.0.10 |
| `rules_dir` | `06-defense/suricata/rules/` |
| `control_side` | `10-crosswalk/control-detection/control-detection.csv` |
| `evasion_side` | `10-crosswalk/evasion-detection/evasion-to-detection.csv` |

## 1. SID allocation (SSA owned ranges)

| Range | Purpose |
|---|---|
| 3001000-3001199 | Web application attacks (OWASP control anchored) |
| 3001200-3001399 | Evasion / living-off-the-land |
| 3001400-3001599 | Reconnaissance and scanning |
| 3001600-3001799 | Exfiltration and C2 |
| 3001800-3001999 | Cloud, CI/CD and container workloads |

Never reuse a retired sid. Retire by setting `rev:` and adding
`retired: <date>` to `10-crosswalk/control-detection/control-detection.csv`.

## 2. Rule anatomy in this archive

Every SSA rule carries, in the `metadata` and comment header:

* the `control_id` or `evasion_id` it implements,
* the CWE it maps to,
* the confidence rating,
* the archive provenance.

## 3. Validation loop

```bash
# syntax and semantics
suricata -T -c suricata.yaml -S 06-defense/suricata/rules/ssa-web-attacks.rules
suricata -T -c suricata.yaml -S 06-defense/suricata/rules/ssa-evasion.rules

# regression against the lab estate (09-labs/infrastructure)
suricata -c suricata.yaml -r 09-labs/pcaps/CH-001.pcap -l /tmp/ssa-out
evince /tmp/ssa-out/eve.json      # every replay must produce its expected sids
```

## 4. Expected sids per emulation

| Emulation | Expected sids |
|---|---|
| `CH-001.md` | 3001003, 3001201 |
| `CH-002.md` | 3001202, 3001203, 3001204 |
| `CH-003.md` | 3001003, 3001205 |
| `EV-LNX-0007.md` | 3001401 (if scanned) |
| `PB-WEB-AUTHBYPASS` | 3001404 |

A sid in this table that never fires in the lab is a defect. Record it in
`10-crosswalk/attack-coverage/attack-coverage.csv` with state `gap`.

## 5. Deployment modes

| Mode | Use | Caution |
|---|---|---|
| IDS | default | drop nothing |
| IPS (blocking) | perimeter, after validation | false positives become outages |
| EVE JSON only | high volume, tuning | no inline action |

Always run the archive ruleset in IDS mode for at least 14 days before enabling
any rule in blocking mode.
'''.lstrip()

# ===========================================================================
# 06-defense - wazuh
# ===========================================================================

FILES["06-defense/wazuh/rules/ssa-baseline.xml"] = r'''
<!--
  Sovereign Security Archive - Wazuh baseline ruleset
  Manager-side rules. Merge into ossec.conf <ossec_config><rules> section or
  deploy with: curl -sS $MANAGER/api/agent-groups/1/configuration/upload
  Target rule ids: 100000-100999 are SSA-owned.
  Mapping: 10-crosswalk/control-detection/control-detection.csv
-->
<group name="ssa,baseline,">

  <group name="ssa,auth,">
    <!-- 100010 - AUTH-4 / AUTH-7: authentication failures (generic, any host) -->
    <rule id="100010" level="5">
      <if_sid>5712,5713,5716</if_sid>
      <match>authentication failure</match>
      <description>SSA AUTH-4: authentication failure detected.</description>
      <mitigation>Enable rate limiting and lockout per OWASP AUTH-4.</mitigation>
    </rule>

    <!-- 100011 - AUTH-4: password spraying (many users, few failures each) -->
    <rule id="100011" level="12">
      <if_matched_sid>100010</if_matched_sid>
      <frequency>20</frequency>
      <timeframe>300</timeframe>
      <same_user>?</same_user>
      <same_src_ip>yes</same_src_ip>
      <description>SSA AUTH-4: password spraying from a single source.</description>
      <group>authentication_failures,</group>
      <mitigation>Apply OWASP AUTH-4 progressive backoff; verify MFA coverage.</mitigation>
    </rule>

    <!-- 100012 - AUTH-7: successful logon after a failure burst -->
    <rule id="100012" level="12">
      <if_matched_sid>5710,5716</if_matched_sid>
      <frequency>5</frequency>
      <timeframe>300</timeframe>
      <same_user>yes</same_user>
      <description>SSA AUTH-7: successful logon after repeated failures.</description>
      <group>authentication_failures,</group>
    </rule>
  </group>

  <group name="ssa,web,">
    <!-- 100020 - INJ-1: SQLi keyword in web access log -->
    <rule id="100020" level="10">
      <if_sid>31151</if_sid>
      <regex>(\bunion\b.{0,40}\bselect\b)|\b(or|and)\b.{0,10}=.{0,10}|\bsleep\s*\(|\bwaitfor\s+delay\b|\bxp_cmdshell\b)</regex>
      <nocase>true</nocase>
      <description>SSA INJ-1: SQL injection indicator in web request.</description>
      <mitigation>Parameterised queries (OWASP INJ-1).</mitigation>
    </rule>

    <!-- 100021 - DOM-1: XSS indicator in web access log -->
    <rule id="100021" level="8">
      <if_sid>31151</if_sid>
      <regex>(&lt;script|%3cscript|onerror\s*=|javascript:|\bonload\s*=|\bsvg/onload)</regex>
      <nocase>true</nocase>
      <description>SSA DOM-1: XSS indicator in web request.</description>
    </rule>

    <!-- 100022 - INPUT-8: SSRF / metadata access from application server -->
    <rule id="100022" level="12">
      <if_sid>31151</if_sid>
      <regex>(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|file:///etc/passwd)</regex>
      <description>SSA INPUT-8: outbound request to a link-local metadata endpoint.</description>
      <mitigation>Egress filtering and destination allow-list (OWASP INPUT-8).</mitigation>
    </rule>
  </group>

  <group name="ssa,integrity,">
    <!-- 100030 - UPL-2: executable file written into a served path -->
    <rule id="100030" level="12">
      <if_sid>550,554,5712</if_sid>
      <match>\.(php|phtml|jsp|asp|aspx|exe|scr|cgi)$</match>
      <description>SSA UPL-2: executable artefact created under a web-served path.</description>
      <group>webserver_log,</group>
    </rule>

    <!-- 100031 - CRYPTO-1: private key material written in world-readable path -->
    <rule id="100031" level="10">
      <if_sid>550</if_sid>
      <match>.pem|id_rsa|id_ed25519|.ppk</match>
      <description>SSA CRYPTO-1: private key material present on a monitored host.</description>
    </rule>

    <!-- 100032 - LOG-7: CRLF in a logged field (log injection) -->
    <rule id="100032" level="7">
      <if_sid>31151</if_sid>
      <regex>%0d%0a|%0a|%0d</regex>
      <nocase>true</nocase>
      <description>SSA LOG-7: CR/LF in a logged field - log injection attempt.</description>
    </rule>
  </group>

</group>
'''.lstrip()

FILES["06-defense/wazuh/rules/ssa-linux.rules"] = r'''
<!--
  Sovereign Security Archive - Wazuh Linux host rules
  rule ids 101000-101999 (SSA-owned, linux)
  mapping: 10-crosswalk/evasion-detection/evasion-to-detection.csv
-->
<group name="ssa,linux,">

  <group name="ssa,linux,privesc,">
    <!-- 101000 - EV-LNX-0001 find -exec shell -->
    <rule id="101000" level="12">
      <if_sid>81151</if_sid>
      <regex>find\s+.*-exec\s+/(bin|usr/bin)/(ba)?sh</regex>
      <description>SSA EV-LNX-0001: find executing a shell (GTFOBins pattern).</description>
      <mitigation>Remove NOPASSWD from find; see 04-evasion/linux/sudo-lpe.md</mitigation>
    </rule>

    <!-- 101001 - EV-LNX-0002 editor/pager escaping to a shell -->
    <rule id="101001" level="12">
      <if_sid>81151</if_sid>
      <regex>(vim?|vi|nano|less|more|view)\s+.*(\!sh|:[0-9]*!?/(bin|usr/bin)/(ba)?sh)</regex>
      <description>SSA EV-LNX-0002: editor or pager spawning an interactive shell.</description>
    </rule>

    <!-- 101002 - EV-LNX-0005/0006 interpreter one-liner -->
    <rule id="101002" level="10">
      <if_sid>81151</if_sid>
      <regex>(perl|python3?|ruby|php)\s+-[ec]\s+.*(exec|system|popen|os\.system|subprocess)</regex>
      <description>SSA EV-LNX-0005: interpreter one-liner with command execution primitive.</description>
    </rule>

    <!-- 101003 - EV-LNX-0008 SUID shell copy -->
    <rule id="101003" level="14">
      <if_sid>81151</if_sid>
      <regex>chmod\s+[0-7]*[4][0-7]{3}\s+.*/(ba)?sh</regex>
      <description>SSA EV-LNX-0008: setuid bit applied to a shell.</description>
    </rule>

    <!-- 101004 - EV-LNX-0017 / EV-CTR-0005 nsenter into PID 1 -->
    <rule id="101004" level="13">
      <if_sid>81151</if_sid>
      <match>nsenter -t 1</match>
      <description>SSA EV-CTR-0005: nsenter targeting PID 1 - container escape indicator.</description>
    </rule>
  </group>

  <group name="ssa,linux,persistence,">
    <!-- 101010 - EV-LNX-0016 cron persistence -->
    <rule id="101010" level="12">
      <if_sid>81151</if_sid>
      <match>crontab -</match>
      <description>SSA EV-LNX-0016: crontab modified.</description>
    </rule>

    <!-- 101011 - authorized_keys modification (T1098.004) -->
    <rule id="101011" level="13">
      <if_sid>87101,87102,550,554</if_sid>
      <match>.ssh/authorized_keys</match>
      <description>SSA: SSH authorized_keys file modified.</description>
      <mitigation>Review key fingerprints; enforce host key management.</mitigation>
    </rule>

    <!-- 101012 - ld.so.preload modification (rootkit indicator) -->
    <rule id="101012" level="14">
      <if_sid>550,554,87101</if_sid>
      <match>ld.so.preload</match>
      <description>SSA: dynamic linker preload list modified.</description>
    </rule>
  </group>

  <group name="ssa,linux,network,">
    <!-- 101020 - EV-LNX-0015 ssh reverse tunnel via ProxyCommand -->
    <rule id="101020" level="12">
      <if_sid>5716</if_sid>
      <regex>ProxyCommand\s+.*(sh|bash|nc|ncat|python|perl)\s+-c</regex>
      <description>SSA EV-LNX-0015: ssh ProxyCommand shell execution - possible tunnel.</description>
    </rule>

    <!-- 101021 - /dev/tcp reverse shell pattern -->
    <rule id="101021" level="14">
      <if_sid>81151</if_sid>
      <match>/dev/tcp/</match>
      <description>SSA: bash /dev/tcp reverse shell primitive.</description>
    </rule>
  </group>

</group>
'''.lstrip()

FILES["06-defense/wazuh/decoders/ssa-json-decoder.xml"] = r'''
<!--
  Sovereign Security Archive - Wazuh decoders
  Unpacks JSON audit events from the archive's own automation services and from
  kubernetes audit logs into flat key=value pairs so rules can match on them.
-->
<decoder name="SSA-K8S-AUDIT">
  <prematch>^.*"kind":"Event".*$</prematch>
</decoder>

<decoder name="SSA-SEC-AGENT">
  <prematch>^SSA-AGENT\s|^\{\"agent\":</prematch>
</decoder>
'''.lstrip()

FILES["06-defense/wazuh/agents/linux-server.xml"] = r'''
<!--
  Sovereign Security Archive - hardened Wazuh agent profile: Linux server
  Deploy to /var/ossec/etc/ossec.conf on the target. Merge, do not overwrite.
-->
<ossec_config>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>10000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <auth>
    <disabled>no</disabled>
    <port>1514</port>
    <use_source_ip>yes</use_source_ip>
    <force_insert>yes</force_insert>
    <purge>yes</purge>
  </auth>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/wtmp</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <location>/var/log/audit/audit.log</location>
    <command>cat</command>
  </localfile>

  <!-- execve audit rules required for 06-defense/wazuh/rules/ssa-linux.rules -->
  <localfile>
    <log_format>full_command</log_format>
    <location>/var/log/audit/audit.log</location>
    <command>cat</command>
  </localfile>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>

    <!-- persistence surfaces from 04-evasion/linux/persistence.md -->
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/usr/bin</directories>
    <directories check_all="yes" realtime="yes">/usr/sbin</directories>
    <directories check_all="no" realtime="yes">/root/.ssh</directories>
    <directories check_all="no" realtime="yes">/home</directories>

    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mnttab</ignore>
    <ignore>/etc/exports</ignore>
    <ignore>/etc/apt/sources.list</ignore>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
    <check_dev>yes</check_dev>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev_points>/etc/mtab</etc/dev/</check_dev_points>
    <check_files_points>/bin /sbin /usr/bin /usr/sbin</check_files_points>
  </rootcheck>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_all>yes</scan_all>
    <hardware>yes</hardware>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <process>yes</process>
  </wodle>

</ossec_config>
'''.lstrip()

# ===========================================================================
# 06-defense - blue team, sigma, hardening, IR
# ===========================================================================

FILES["06-defense/blue-team/controls/controls.csv"] = r'''
control_id,control_name,framework,severity,owner,evidence_required,review_cadence
INPUT-4,Server-side input validation allow-list,OWASP-CS,high,appsec,unit tests + fuzz run,quarterly
INPUT-8,URL validation for server-side requests,OWASP-CS,high,appsec,egress policy + test,quarterly
INJ-1,Parameterised queries,OWASP-CS,critical,appsec,code review + SAST,quarterly
INJ-2,Least privilege database accounts,OWASP-CS,high,dba,grant inventory,quarterly
DOM-1,Context-aware output encoding,OWASP-CS,high,appsec,SAST + DAST,quarterly
DOM-4,Content Security Policy,OWASP-CS,high,appsec,response header check,monthly
CSRF-1,Anti-CSRF tokens,OWASP-CS,critical,appsec,integration test,quarterly
CSRF-2,SameSite cookies,OWASP-CS,critical,appsec,response header check,monthly
AUTH-1,Multi-factor authentication,OWASP-CS,critical,iam,IdP config export,monthly
AUTH-4,Rate limiting and lockout,OWASP-CS,high,appsec,load test + alerts,quarterly
AUTH-7,Generic authentication errors,OWASP-CS,high,appsec,response comparison,quarterly
SESSION-3,Session rotation after privilege change,OWASP-CS,high,appsec,integration test,quarterly
SESSION-4,Secure HttpOnly SameSite cookies,OWASP-CS,high,appsec,response header check,monthly
AUTHZ-2,Deny by default,OWASP-CS,critical,appsec,policy test suite,quarterly
AUTHZ-3,Server-side authorization on data access,OWASP-CS,high,appsec,IDOR test suite,quarterly
UPL-2,Upload extension allow-list,OWASP-CS,high,appsec,upload test,quarterly
UPL-5,Uploads outside web root,OWASP-CS,high,platform,nginx/apache config,quarterly
LOG-4,Log data encoding,OWASP-CS,medium,appsec,log injection test,annual
LOG-7,Near real-time alerting on security events,OWASP-CS,medium,soc,SOC runbook + rule tests,monthly
CRYPTO-1,Modern authenticated encryption,OWASP-CS,high,appsec,code review,quarterly
CRYPTO-4,No ECB / static IV,OWASP-CS,high,appsec,code review,quarterly
SECRETS-3,Secret rotation,OWASP-CS,high,platform,rotation job logs,monthly
REST-1,HTTPS only,OWASP-CS,high,platform,listener inventory,monthly
REST-7,Content-Type validation,OWASP-CS,medium,appsec,negative tests,quarterly
GQL-2,GraphQL introspection disabled in production,OWASP-CS,medium,appsec,request to /graphql,quarterly
GQL-4,Query depth and complexity limits,OWASP-CS,high,appsec,complexity test,quarterly
LLM-01,Untrusted content segregated from instructions,OWASP-CS,critical,ai-platform,prompt injection suite,monthly
LLM-02,Model output validated before use,OWASP-CS,high,ai-platform,output schema enforcement,monthly
LLM-05,Least privilege for model tools,OWASP-CS,high,ai-platform,tool permission list,monthly
CLOUD-01,IMDSv2 required / metadata endpoint protected,OWASP-CS,critical,cloudops,instance metadata config,monthly
CLOUD-02,Egress default deny for application subnets,OWASP-CS,high,network,route tables,monthly
CLOUD-03,Workload identity instead of static keys,OWASP-CS,high,cloudops,kubernetes service accounts,quarterly
AD-01,AS-REP roast hardening (preauth required),MITRE,high,adops,Get-ADUser report,quarterly
AD-02,AES-only Kerberos encryption,MITRE,high,adops,domain controller policy,quarterly
AD-03,SMB signing mandatory,MITRE,critical,adops,smb signing policy,quarterly
AD-04,DCSync monitored off-domain,MITRE,critical,soc,4662 collection proof,monthly
AD-05,Tiered administration,MITRE,high,adops,admin group inventory,quarterly
AD-06,Privileged MFA / PAW,MITRE,high,adops,Conditional Access policy,quarterly
IR-01,Documented IR playbook with named roles,OWASP-CS,medium,soc,playbook + tabletop record,annual
IR-02,Evidence handling with chain of custody,OWASP-CS,medium,soc,evidence register,annual
IR-03,Quarterly tabletop exercise,OWASP-CS,medium,soc,after-action report,quarterly
'''.lstrip()

FILES["06-defense/blue-team/owasp-to-detection.md"] = r'''
# OWASP Cheat Sheet to Defensive Detection Mapping

Every OWASP control in `01-intel/cheat-sheets/owasp/owasp-controls.csv` must
have at least one anchor. This page explains the method; the machine readable
result is `10-crosswalk/control-detection/control-detection.csv`.

## 1. Detection layer selection

| Layer | Best suited for | Suricata | Wazuh | Sigma |
|---|---|---|---|---|
| network | requests an attacker sends | yes | no | limited |
| host | what the request caused | no | yes | yes |
| audit | identity and privilege activity | no | yes | yes |
| application | logic the network cannot see | no | via app log | yes |

## 2. Worked example - AUTH-7

| Step | Value |
|---|---|
| Control | AUTH-7 "authentication error messages must be generic" |
| Failure mode | username enumeration through distinct error text |
| Network layer | Cannot see response bodies without TLS termination |
| Host/audit layer | 4625 burst followed by 4624 (spray succeeded) |
| Application layer | Delta on `/login` responses by status/body hash |
| **Chosen anchor** | `audit` - Wazuh `100012` and `100011` |
| Sigma portability | `ssa_win_failed_logon_then_success.yml` |
| Residual gap | Enumeration on a system with no successful logon is invisible |

## 3. Worked example - LLM-01

| Step | Value |
|---|---|
| Control | LLM-01 "segregate untrusted content from instructions" |
| Failure mode | prompt injection from retrieved documents |
| Network layer | TLS-terminated bodies only; heuristics on instruction keywords |
| Host layer | LLM gateway logs: role markers appearing in user content |
| Application layer | Tool invocation without prior user confirmation |
| **Chosen anchor** | `application` - Sigma `ssa_llm_prompt_injection.yml` |
| Sigma portability | yes (LLM gateway logs) |
| Residual gap | Semantic attacks that mimic legitimate instructions |

## 4. Coverage verification

```bash
python tools/ssactl.py verify --root . --coverage
```

Output semantics:

```
COV-001 ok      30 controls, 30 anchored, 0 orphaned
COV-001 ERROR  control_id=LLM-05 has no anchor_id
```

Exit code `2` blocks CI.

## 5. Adding a control

1. Add the row to `owasp-controls.csv` with `anchor_layer` and `anchor_id`.
2. Implement the anchor in `06-defense/suricata/rules/` or
   `06-defense/wazuh/rules/` (allocate a sid or rule id from the SSA ranges).
3. Add the row to `10-crosswalk/control-detection/control-detection.csv`.
4. Run the verifier.
'''.lstrip()

FILES["06-defense/blue-team/mitre-coverage.csv"] = r'''
technique_id,tactic,name,offensive_artifacts,evasion_ids,detection_artifacts,coverage_state,gap_note,last_reviewed
T1059.001,Execution,PowerShell,05-engines/metasploit,EV-WIN-0009,ssa_windows_lolbin_anomaly.yml,full,,2026-01-15
T1059.003,Execution,Windows Command Shell,05-engines/metasploit,EV-WIN-0001,ssa_windows_lolbin_anomaly.yml,full,,2026-01-15
T1059.004,Execution,Unix Shell,05-engines/metasploit,EV-LNX-0002,ssa_interpreter_shell.yml,full,,2026-01-15
T1059.006,Execution,Python,05-engines/metasploit,EV-LNX-0005,ssa_interpreter_shell.yml,full,,2026-01-15
T1003.006,Credential Access,DCShadow,02-payloads/os/linux/payloads.json,,ssa_ad_dcsync.yml,full,,2026-01-15
T1021.002,Remote Services,SMB/Windows Admin Shares,05-engines/metasploit,EV-WIN-0001,ssa_windows_psexec.yml,full,,2026-01-15
T1027,Defense Evasion,Obfuscated Files or Information,04-evasion,EV-WIN-0010,ssa_windows_lolbin_anomaly.yml,offensive-only,,2026-01-15
T1047,Execution,Windows Management Instrumentation,05-engines/metasploit,EV-WIN-0013,ssa_windows_wmi_exec.yml,full,,2026-01-15
T1053.003,Persistence,Cron,04-evasion/linux/persistence.md,EV-LNX-0016,ssa_linux_cron_persistence.yml,full,,2026-01-15
T1053.005,Persistence,Scheduled Task/Job,04-evasion/windows/sushi.md,EV-WIN-0003,ssa_windows_schtasks.yml,full,,2026-01-15
T1068,Privilege Escalation,Exploitation for Privilege Escalation,02-payloads/os,EV-CTR-0001,ssa_kubectl_exec_pod.yml,offensive-only,Kubernetes audit not enabled by default,2026-01-15
T1078,Defense Evasion,Valid Accounts,05-engines,EV-CI-0001,ssa_cloud_iam_anomaly.yml,full,,2026-01-15
T1083,Discovery,File and Directory Discovery,05-engines/metasploit,,,gap,No host rule for brute-force filesystem enumeration,2026-01-15
T1090,Proxy,T1090 Proxy,01-intel/playbooks/network/pivoting.md,EV-LNX-0015,ssa_ssh_pivot.yml,full,,2026-01-15
T1098.004,Persistence,SSH Authorized Keys,02-payloads/os/linux/payloads.json,EV-LNX-0003,ssa_linux_authorized_keys.yml,full,,2026-01-15
T1105,Ingress Tool Transfer,Ingress Tool Transfer,04-evasion/windows/sushi.md,EV-WIN-0005,ssa_windows_certutil.yml,full,,2026-01-15
T1110.003,Credential Access,Password Spraying,03-wordlists/credentials,,ssa_linux_ssh_bruteforce.yml,full,,2026-01-15
T1134.005,Privilege Escalation,Additional Cloud Roles,01-intel/playbooks/active-directory/kerberos-attacks.md,,ssa_ad_constrained_delegation.yml,full,,2026-01-15
T1190,Initial Access,Exploit Public-Facing Application,02-payloads/web,EV-WIN-0007,ssa_web_sqli_probe.yml,full,,2026-01-15
T1195.002,Initial Access,Supply Chain Compromise,04-evasion/containers,EV-CI-0001,ssa_jenkins_groovy_console.yml,full,,2026-01-15
T1218.003,Defense Evasion,Windows Management Instrumentation,04-evasion/windows/sushi.md,EV-WIN-0010,ssa_windows_lolbin_anomaly.yml,full,,2026-01-15
T1218.005,Defense Evasion,Mshta,04-evasion/windows/sushi.md,EV-WIN-0007,ssa_windows_mshta.yml,full,,2026-01-15
T1218.010,Defense Evasion,Regsvr32,04-evasion/windows/sushi.md,EV-WIN-0006,ssa_windows_regsvr32.yml,full,,2026-01-15
T1486,Impact,Data Encrypted for Impact,09-labs/emulations,EV-LNX-0016,ssa_linux_mass_encryption.yml,full,,2026-01-15
T1490,Impact,Inhibit System Recovery,06-defense/ir,,ssa_windows_shadow_copy_delete.yml,full,,2026-01-15
T1548.003,Privilege Escalation,Bypass User Account Control,04-evasion/linux/sudo-lpe.md,EV-LNX-0007,ssa_linux_sudo_nonshell.yml,full,,2026-01-15
T1552.001,Credential Access,Credentials In Files,04-evasion/macos/sudo.md,EV-MAC-0002,ssa_macos_keychain_read.yml,full,,2026-01-15
T1552.005,Credential Access,Cloud Instance Metadata API,02-payloads/cloud/payloads.json,,ssa_cloud_metadata_access.yml,full,,2026-01-15
T1556.003,Credential Access,Create or Modify System Process,01-intel/playbooks/active-directory/kerberos-attacks.md,,ssa_ad_shadow_credentials.yml,full,,2026-01-15
T1558.003,Credential Access,Kerberoasting,01-intel/playbooks/active-directory/kerberos-attacks.md,,ssa_ad_kerberoast.yml,full,,2026-01-15
T1558.004,Credential Access,AS-REP Roasting,01-intel/playbooks/active-directory/kerberos-attacks.md,,ssa_ad_asrep_roast.yml,full,,2026-01-15
T1567,Exfiltration,Exfiltration Over Web Service,02-payloads,,ssa_cloud_metadata_access.yml,detective-only,,2026-01-15
T1570,Lateral Movement,File Transfer Tools,01-intel/playbooks/network/pivoting.md,,ssa_ssh_pivot.yml,full,,2026-01-15
T1609,Execution,Container Administration Command,04-evasion/containers,EV-CTR-0002,ssa_kubectl_exec_pod.yml,full,,2026-01-15
T1610,Privilege Escalation,Deploy Container,04-evasion/containers,EV-CTR-0005,ssa_docker_privileged_run.yml,full,,2026-01-15
T1649,Privilege Escalation,Steal or Forge Authentication Certificates,01-intel/playbooks/active-directory/kerberos-attacks.md,,ssa_ad_adcs_abuse.yml,offensive-only,ESC1 depends on template misconfiguration,2026-01-15
T1595,Active Scanning,Active Scanning,01-intel/playbooks/network,EV-LNX-0001,ssa_network_scan.yml,full,,2026-01-15
'''.lstrip()

FILES["06-defense/sigma/ssa_ad_kerberoast.yml"] = r'''
title: Kerberoasting - bulk service ticket requests with RC4 encryption
id: 8f2a1c44-1d21-4a1e-9a71-0b6d2f5c7e01
status: experimental
description: Detects a high volume of TGS requests using RC4-HMAC, characteristic of Kerberoasting.
author: Sovereign Security Archive
date: 2026-01-15
references:
  - https://attack.mitre.org/techniques/T1558/003/
  - 01-intel/playbooks/active-directory/kerberos-attacks.md
  - 10-crosswalk/evasion-detection/evasion-to-detection.csv
logsource:
  product: windows
  service: security
detection:
  selection_encryption_type:
    TicketEncryptionType|re: '0x17|0x18|0x12'
  selection_event:
    EventID: 4769
  filter_service:
    ServiceName: ''   # exclude machine account requests with no service name
  condition: selection_encryption_type and selection_event and not 1 of filter_service
  timeframe: 10m
  condition_count: 25
fields:
  - TargetUserName
  - ServiceName
  - TicketEncryptionType
  - IpAddress
  - WorkstationName
falsepositives:
  - Legitimate service accounts with pre-tickets disabled during password rotation
  - Monitoring tools that enumerate SPNs
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
'''.lstrip()

FILES["06-defense/sigma/ssa_ad_dcsync.yml"] = r'''
title: DCSync - directory replication request from a non-domain-controller host
id: 3c9b77aa-9d3d-4f0c-9c0f-2b5a1c3e77aa
status: test
description: 4662 with a directory replication GUID on any host that is not a DC is a high-fidelity indicator of DCSync.
author: Sovereign Security Archive
date: 2026-01-15
references:
  - https://attack.mitre.org/techniques/T1003/006/
  - 01-intel/playbooks/active-directory/kerberos-attacks.md
  - 00-governance/threat-model.md
logsource:
  product: windows
  service: security
detection:
  selection_replication_guid:
    ObjectType|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # GetNCChanges
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # GetDeltas
      - '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2'  # GetDeltasAddNC
      - '89e95b76-444d-4c62-991a-0facbeda640c'  # GetChanges
      - '89e95b77-444d-4c62-991a-0facbeda640c'  # GetAllChanges
  selection_event:
    EventID: 4662
  filter_dc:
    ObjectServer|contains: '\\DC'
  condition: selection_replication_guid and selection_event and not 1 of filter_dc
fields:
  - SubjectUserName
  - ObjectName
  - ObjectServer
  - IpAddress
  - Properties
falsepositives:
  - Legitimate third-party directory synchronisation products
  - Authorised backup appliances (must be allow-listed by host, not globally)
level: critical
tags:
  - attack.credential_access
  - attack.t1003.006
'''.lstrip()

FILES["06-defense/sigma/ssa_linux_authorized_keys.yml"] = r'''
title: SSH authorized_keys file modified
id: 6d4c1f77-3c22-4c53-9d61-3b6b0e0d4a02
status: test
description: Modification of authorized_keys creates durable SSH access.
author: Sovereign Security Archive
date: 2026-01-15
references:
  - https://attack.mitre.org/techniques/T1098/004/
  - 04-evasion/linux/persistence.md
logsource:
  product: linux
  service: sshd
detection:
  selection:
    TargetFilename|contains: '/.ssh/authorized_keys'
    EventType: write
  filter_automation:
    User|startswith: 'ansible.'
  condition: selection and not 1 of filter_automation
fields:
  - TargetFilename
  - User
  - Image
falsepositives:
  - Configuration management (must be scoped to the automation account)
  - Developer workstation key rotation
level: high
tags:
  - attack.persistence
  - attack.t1098.004
  - attack.t1552.001
'''.lstrip()

FILES["06-defense/sigma/ssa_windows_lolbin_anomaly.yml"] = r'''
title: Signed LOLBin spawned a shell or scripting host
id: 9a2f5c31-6e44-4f8a-bc02-3d5b7e9a1c05
status: test
description: Detects the parent/child pattern of trusted signed binaries used to execute attacker code.
author: Sovereign Security Archive
date: 2026-01-15
references:
  - 04-evasion/windows/sushi.md
  - 04-evasion/windows/binaries.csv
logsource:
  product: windows
  category: process_creation
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
      - '\odbcconf.exe'
      - '\control.exe'
      - '\eventvwr.exe'
      - '\mmc.exe'
      - '\pcalua.exe'
  child:
    ChildImage|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\curl.exe'
  filter_known_automation:
    User|startswith:
      - 'svc_'
      - 'SYSTEM'
  condition: parent and child and not 1 of filter_known_automation
fields:
  - ParentImage
  - ParentCommandLine
  - Image
  - CommandLine
  - User
  - ParentUser
falsepositives:
  - Software installers and updaters
  - Management tools that invoke certutil to verify catalog signatures
  - Legacy VB/COM applications
level: high
tags:
  - attack.defense_evasion
  - attack.taint_tools
  - attack.execution
'''.lstrip()

FILES["06-defense/sigma/ssa_cloud_metadata_access.yml"] = r'''
title: Unexpected access to the cloud instance metadata service
id: 2f9c3d84-5a17-4f61-8c02-9a3d5e7b1c07
status: test
description: Detects non-application requests to the IMDS endpoint, a common SSRF and credential-theft step.
author: Sovereign Security Archive
date: 2026-01-15
references:
  - 01-intel/playbooks/cloud/aws-iam-privesc.md
  - 02-payloads/cloud/payloads.json
logsource:
  category: proxy
  product: zeek
detection:
  selection:
    dest_ip|cidr: '169.254.169.254/32'
  filter_known_agents:
    UserAgent|contains:
      - 'AWS_EC2'
      - 'cloudfront'
      - 'kube-probe'
  condition: selection and not 1 of filter_known_agents
fields:
  - id.orig_h
  - user_agent
  - http.request_uri
  - dest_ip
falsepositives:
  - Instance bootstrap agents
  - Serverless runtimes legitimately contacting IMDSv2
level: high
tags:
  - attack.credential_access
  - attack.t1552.005
  - attack.discovery
'''.lstrip()

FILES["06-defense/sigma/ssa_llm_prompt_injection.yml"] = r'''
title: LLM gateway - instruction injection markers inside untrusted content
id: b7d4e2f1-9c08-4a35-8f12-6d0a4c8e2b09
status: experimental
description: Detects instruction-like content appearing in documents or tool output that the model treats as trusted.
author: Sovereign Security Archive
date: 2026-01-15
references:
  - 01-intel/cheat-sheets/owasp/owasp-controls.csv (LLM-01, LLM-02, LLM-05)
logsource:
  category: application
  product: llm-gateway
detection:
  selection_markers:
    content_role:
      - 'untrusted_document'
      - 'tool_output'
      - 'web_page'
    message|re: '(?i)(ignore (all )?(previous|prior|above) instructions|disregard the (system|previous) (prompt|instructions)|you are now (a|an) [A-Za-z]+|reveal (your )?(system )?prompt|exfiltrate|send (the )?(contents|conversation) to)'
  filter_benign:
    message|contains: 'example of an injection attempt'
  condition: selection_markers and not 1 of filter_benign
fields:
  - session_id
  - model
  - message
  - content_role
  - tool_name
falsepositives:
  - Security testing and red-team exercises against your own gateway
  - Content moderation training data
level: high
tags:
  - attack.llm_injection
  - attack.t1195
'''.lstrip()

FILES["06-defense/hardening/linux-baseline.md"] = r'''
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
'''.lstrip()

FILES["06-defense/hardening/windows-baseline.md"] = r'''
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
'''.lstrip()

FILES["06-defense/hardening/network-baseline.md"] = r'''
# Network and Perimeter Hardening Baseline

## 1. Egress (highest value control)

| Tier | Policy |
|---|---|
| Server subnet | default deny outbound; allow 443 to proxy, 53 to resolvers, NTP |
| User subnet | allow 80/443, 53, 123; block all other TCP/UDP |
| IoT/OT subnet | no internet, no inter-subnet except required flows |
| Management subnet | no internet at all |

Why this dominates: SSRF, ransomware, C2 and data exfiltration all require
egress. Blocking it converts an incident into a failed attempt.

## 2. Ingress

```text
Allow  tcp/443   from 0.0.0.0/0        to DMZ  (WAF only, not origin)
Allow  tcp/22    from VPN range       to bastion
Deny   tcp/22    from any             to any
Allow  tcp/3389  from VPN range       to jump hosts
Deny   tcp/3389  from any             to any
Deny   tcp/135,139,445 from any       to any except domain tier
```

| Exposure | Required action |
|---|---|
| RDP on 3389 to internet | Never. If unavoidable: gateway + MFA + IP allow-list |
| SMB to internet | Never |
| Management consoles to internet | Never |
| Databases to internet | Never |

## 3. Segmentation model

```
Internet
   |
 [ WAF ]  -- only hardened, patched, EDR-managed
   |
 [ DMZ ]  -- reverse proxy, stateless services
   |            |
 [App tier]--[Data tier]   (App -> Data: specific ports only)
   |
 [Mgmt]  -- reachable only from VPN, no egress
```

## 4. TLS

| Item | Baseline |
|---|---|
| TLS version | 1.2 minimum, 1.3 preferred |
| Cipher suites | AEAD only (GCM, ChaCha20) |
| HSTS | `max-age=63072000; includeSubDomains; preload` |
| Certificate expiry | alert at 30, 14, 7 days |
| Client certs | mTLS for partner and administrative APIs |

## 5. DNS

```text
# never expose recursion
allow-recursion { 10.0.0.0/8; };
allow-query { 10.0.0.0/8; };
# rate limit
dnssec-validation yes;
```

## 6. Load balancer

* Do not pass the client IP in `X-Forwarded-For` unless the edge is trusted -
  otherwise IP allow-lists are bypassable (see `PL-API-0006`).
* Do not use a real `Host` value to build backend URLs (see `PL-API-0005`).

## 7. Logging

| Log | Retention | Notes |
|---|---|---|
| Firewall (allowed + denied) | 400 days | denied flows matter most |
| DNS queries | 90 days | tunnelling and beaconing |
| Netflow / Zeek | 180 days | set `30012xx` rules apply |
| Load balancer | 400 days | include the raw request URI |
'''.lstrip()

FILES["06-defense/ir/incident-response-playbook.md"] = r'''
# Incident Response Playbook

| Field | Value |
|---|---|
| `playbook_id` | IR-001 |
| `framework` | NIST SP 800-61r2 |
| `controls` | IR-01, IR-02, IR-03 |
| `sources` | `meirwah/awesome-incident-response`, `SANS` |

## 1. Severity and response targets

| Sev | Definition | First response | Update cadence | Escalation |
|---|---|---|---|---|
| SEV1 | Confirmed exfiltration, encryption, or destructive action | 15 min | hourly | CISO + Legal + comms |
| SEV2 | Confirmed compromise, scope unknown | 30 min | every 2 h | SOC lead + IT |
| SEV3 | Suspicious activity, unconfirmed | 4 h | daily | Analyst |
| SEV4 | Policy violation without impact | 1 day | weekly | Team lead |

## 2. Roles (assign by name before an incident, not during)

| Role | Duty | Backup |
|---|---|---|
| Incident Commander | Owns decisions, severity, comms | SOC lead |
| Technical Lead | Directs investigation | Tier 3 analyst |
| Forensics Lead | Evidence, imaging, chain of custody | DFIR contractor |
| Communications | Internal and external messaging | Legal |
| Scribe | Timeline, decisions, evidence log | Automation (this archive) |

## 3. Phase 1 - Preparation

- [ ] Playbook reviewed quarterly (`IR-03`)
- [ ] Contact tree tested monthly
- [ ] Jump host ready with the tooling in `07-tooling/`
- [ ] Forensic disk / RAM acquisition capability verified
- [ ] Legal and insurer notification path known
- [ ] Log sources confirmed to be reaching the SIEM (see `06-defense/wazuh/`)

## 4. Phase 2 - Detection and analysis

```powershell
# Windows triage
Get-LocalUser | Where-Object { $_.LastLogon -gt (Get-Date).AddDays(-1) }
Get-NetTCPConnection -State Established,Listen | Group-Object OwningProcess
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddHours(-4)} |
  Select TimeCreated,Message
```

```bash
# Linux triage
last -ai | head -40
ss -tulpn
find /tmp /dev/shm -type f -perm -u+x -mtime -2 2>/dev/null
journalctl --since "-4 hours" -p warning
```

Analysis questions:
1. What is the initial access vector?
2. What is the earliest confirmed malicious timestamp?
3. Which identities and hosts are involved?
4. Is there evidence of exfiltration?
5. Which of our detections fired, and which should have?

## 5. Phase 3 - Containment, eradication, recovery

| Option | Impact | Use when |
|---|---|---|
| Network isolation (EAP) | High - user disruption | Active exfiltration or lateral movement |
| Account disable + session kill | Medium | Compromised identity, host still trustworthy |
| Host shutdown (do not power off) | High | Unknown rootkit; image memory first |
| Selective process kill | Low | Single known malicious process |
| Rate limiting / blocking at egress | Low | Ongoing command and control |

**Always capture volatile evidence before containment:** memory, network
connections, running processes, logged-on users.

## 6. Phase 4 - Post-incident

- [ ] After-action review within 5 business days
- [ ] Timeline finalised in `06-defense/ir/timeline.md`
- [ ] Detection gaps turned into Sigma rules (this is the archive's key loop)
- [ ] New ATT&CK techniques recorded in `06-defense/blue-team/mitre-coverage.csv`
- [ ] Playbook, runbooks and training updated
- [ ] Compliance notification obligations tracked (GDPR 72 h, PCI, contracts)

## 7. Communication template

```text
SEV:            <SEV1-4>
Detected:       <UTC timestamp, source>
Summary:        <one sentence, no speculation>
Affected:       <identity/asset count and type>
Data exposure:  <confirmed / suspected / none>
Containment:    <action taken, UTC>
Next update:    <UTC>
Owner:          <Incident Commander>
```
'''.lstrip()

FILES["06-defense/ir/evidence-handling.md"] = r'''
# Evidence Handling and Chain of Custody

| Field | Value |
|---|---|
| `playbook_id` | IR-002 |
| `controls` | IR-02 |

## 1. Rules

1. Work only on copies. Never modify the original image.
2. Hash on acquisition, hash on transfer, hash on analysis.
3. Log every person, time and action that touched the evidence.
4. Store under access control with write-once semantics where possible.
5. Record the tool and version used for each derived artefact.

## 2. Acquisition

```powershell
# Windows disk image (dd style, from WinPE or a live environment)
Get-Disk | Format-Table Number, Size, PartitionStyle
# memory (order matters: do this FIRST)
WinPmem.exe physmem.mem
Get-FileHash .\physmem.mem -Algorithm SHA256 | Format-List
# disk
Get-FileHash \\.\PhysicalDrive0 -Algorithm SHA256   # extremely slow; hash the image instead
```

```bash
# Linux memory first, then disk
sudo insmod /lib/modules/$(uname -r)/build/drivers/misc/isadump.ko isadump 2>/dev/null
dd if=/proc/kcore of=/mnt/evidence/mem.lime bs=1M status=progress   # alternative
# or
sudo su -c 'cat /proc/kcore' > /mnt/evidence/mem.lime
# disk
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT
sudo dd if=/dev/sda bs=4M status=progress of=/mnt/evidence/sda1.dd
sha256sum /mnt/evidence/sda1.dd
```

## 3. Chain of custody register

| Field | Example |
|---|---|
| Evidence ID | `SSA-2026-0007` |
| Description | `MEM-01 memory dump - WEB-03` |
| Acquired by | `<analyst>, <badge>` |
| Acquired at (UTC) | `2026-01-15T09:12:44Z` |
| SHA-256 on acquire | `<hash>` |
| Method | `WinPmem 3.3`, `dd bs=4M` |
| Storage location | `T1 vault, shelf 3, box 11` |
| Transfers | every handoff with person, time, hash |
| Disposal | date, method, authoriser |

## 4. Analysis sequence

```bash
# 1. triage with file/magic
file evidence/*
# 2. build a timeline
python 11-automation/scripts/build_timeline.py --input logs/ --output timeline.csv
# 3. memory forensics
vol.py -f mem.lime windows.info
vol.py -f mem.lime windows.pstree
vol.py -f mem.lime windows.netscan
# 4. binary inspection for packed/unknown content
#    -> 07-tooling/imhex/ patterns
```

## 5. Legal notes

* Preserve originals until the legal hold is lifted; do not delete "junk" data.
* Record tool provenance: a hash produced by an undocumented tool may not be
  admissible.
* Chain of custody gaps are the most common reason forensic findings are
  challenged.
'''.lstrip()

FILES["06-defense/ir/timeline.md"] = r'''
# Incident Timeline Template

Copy this table per incident. Times are UTC. Never edit a completed row -
append a correction row and reference the original.

| # | Timestamp (UTC) | Source | Actor | Action | Evidence ID | Analyst | Notes |
|---|---|---|---|---|---|---|---|
| 1 | 2026-01-15T08:41:02Z | `suricata` 3001006 | unknown | XSS probe on `/search` | SSA-2026-0001-LOG | analyst.a | first alert |
| 2 | 2026-01-15T08:41:15Z | `wazuh` 100020 | unknown | SQLi probe on `/product?id=` | SSA-2026-0001-LOG | analyst.a | |
| 3 | 2026-01-15T08:52:44Z | `proxy` | 10.20.3.44 | request to `169.254.169.254` | SSA-2026-0001-LOG | analyst.a | **SSRF confirmed** |
| 4 | 2026-01-15T08:52:51Z | `wazuh` 100022 | app-svc | SSRF rule fired | SSA-2026-0002-ALERT | auto | |
| 5 | 2026-01-15T08:53:10Z | `wazuh` 100011 | svc_deploy | 20 failed logons, 1 success | SSA-2026-0002-ALERT | auto | spray succeeded |
| 6 | 2026-01-15T09:03:33Z | `cloudtrail` | svc_deploy | `iam:CreatePolicyVersion` | SSA-2026-0003-CT | analyst.b | escalation |
| 7 | 2026-01-15T09:20:00Z | responder | - | EC2 isolated, key revoked | SSA-2026-0004-ACT | analyst.a | containment |

## Correlation queries

```bash
# all events for a host
grep 'WEB-03' 06-defense/ir/timeline.md

# gaps between consecutive steps (a >20 minute gap may mean evasion)
awk -F'|' 'NR>2 {if (prev) { gsub(/[TZ: -]/,"",$2); gsub(/[TZ: -]/,"",prev);
    d=$2-prev; if (d>1200) print "GAP", $2, d "s" } prev=$2 }' 06-defense/ir/timeline.md
```

## Required fields discipline

* Every row needs `Evidence ID` - a timeline without evidence is opinion.
* `Actor` uses an identity (`user@domain`, `IP`, `role-arn`), not "attacker".
* `Action` is what the system recorded, not what you assume it means.
'''.lstrip()