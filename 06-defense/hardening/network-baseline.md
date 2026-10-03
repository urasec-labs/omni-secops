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
