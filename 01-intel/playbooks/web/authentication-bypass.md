# Playbook - Authentication & Session Bypass

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-AUTHBYPASS |
| `cwe_id` | CWE-287, CWE-303 |
| `owasp_top10` | A07:2021 |
| `owasp_controls` | AUTH-1, AUTH-2, AUTH-3, AUTH-4, AUTH-7, SESSION-1..5 |
| `payload_corpus` | `02-payloads/api/`, `02-payloads/web/sqli/` |
| `detections` | `06-defense/wazuh/rules/1005-web-app.rules` (4625, 4728, 4729) |

## 1. Password attack ladder

| Step | Action | Wordlist |
|---|---|---|
| 1 | Credential stuffing from breach corpora | `03-wordlists/credentials/userpass-combinations.txt` |
| 2 | Password spraying (1-3 passwords / user, low rate) | `03-wordlists/credentials/common-passwords.txt` |
| 3 | Targeted list per persona (CTO, dev, HR) | `03-wordlists/web/fuzzing/usernames.txt` |
| 4 | Default credentials on exposed appliances | `03-wordlists/credentials/defaults.txt` |
| 5 | Kerberos AS-REP roasting (no spray at all) | - |

Rate limit: stay under the client's lockout policy; prefer spraying (many users,
few attempts) over brute force (one user, many attempts).

## 2. Authentication logic flaws

```bash
# Parameter pollution: does the app trust the first or the last value?
curl -s "https://TARGET/login?username=admin&username=attacker"

# Case / unicode normalisation: admin, Admin, ADMIN, admın
# JSON type juggling
curl -s -X POST "https://TARGET/api/login" -d '{"user":"admin","pass":true}'
curl -s -X POST "https://TARGET/api/login" -d '{"user":"admin","pass":0}'

# Mass assignment on registration
curl -s -X POST "https://TARGET/api/register" -d '{"user":"a","role":"admin","isAdmin":true}'

# Password reset token handling
curl -s "https://TARGET/reset?token=<jwt>"        # no expiry / no user binding
curl -s -X POST "https://TARGET/reset" -d '{"email":"victim@x"}'  # user enumeration
```

## 3. JWT attack checklist

| Check | Payload / technique | Reference |
|---|---|---|
| `alg: none` | strip signature | `02-payloads/api/jwt-none.jwt` |
| Algorithm confusion | RS256 public key used as HMAC secret | `02-payloads/api/jwt-hs256-confusion.md` |
| Weak secret | `secret`, `password`, `key` | `03-wordlists/credentials/jwt-secrets.txt` |
| Missing claims | no `exp`, no `aud`, no `iss` | - |
| Key confusion | `kid` header → local file / URL injection | `02-payloads/api/jwt-kid-injection.md` |
| Token reuse | reuse across users/environments | - |

## 4. Session management

* Predictable session id (low entropy, timestamp-derived).
* Session id in URL, or leaking via `Referer`.
* No rotation after privilege change (OWASP SESSION-3).
* `Secure` missing on an HTTPS-only application.
* Long-lived sessions with no absolute timeout (OWASP SESSION-3).

## 5. Detection

| Signal | Source | Rule |
|---|---|---|
| 4625 burst across many users | Windows log | Wazuh 86630 (spray) |
| 4625 followed by 4624 same user | Windows log | Wazuh 86631 (success after failures) |
| Logon outside business hours / geolocation | Windows log | Wazuh 86632 |
| 4728 new member in privileged group | Windows log | Wazuh 86640 |
| Password reset requests for many accounts | App log | Wazuh 86650 |

## 6. Remediation

Prioritise OWASP AUTH-1..7 and SESSION-1..5: MFA on privileged paths, generic
error messages, rate limiting with progressive backoff, server-side session
store, rotate on auth, absolute + idle timeout, and `Secure; HttpOnly; SameSite`.
