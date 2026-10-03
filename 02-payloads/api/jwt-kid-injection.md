# JWT `kid` / `jku` / `x5u` Injection

| Field | Value |
|---|---|
| `payload_id` | PL-API-JWT-002 |
| `cwe_id` | CWE-918, CWE-22 |

## Variants

| Header field | Payload | Effect |
|---|---|---|
| `kid` | `../../../../../../dev/null` | empty key -> signature check trivially bypassed in some libraries |
| `kid` | `/proc/self/environ` | read local file as key material |
| `kid` | `sqlmap_sqli.txt` | key pulled from a database column |
| `jku` | `https://COLLAB/keys.json` | attacker hosts the JWKS |
| `x5u` | `https://COLLAB/cert.pem` | attacker hosts the certificate chain |
| `x5c` | injected certificate | forged chain |

## Detection

* `kid` containing path separators, `..`, or a URL scheme.
* `jku`/`x5u` pointing outside the trusted issuer set.
* Wazuh rule `86692`: gateway sees a JWT with `jku` or `x5u` set.
* Suricata `3001101`: HTTP Authorization header containing `"jku"`.

## Remediation

* Allow-list key ids; reject anything not matching `^[A-Za-z0-9_-]{1,64}$`.
* Never fetch remote key URLs from the token.
* Pin `kid` to keys in the local keystore.
