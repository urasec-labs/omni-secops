# Playbook - Unrestricted File Upload

| Field | Value |
|---|---|
| `playbook_id` | PB-WEB-UPLOAD |
| `cwe_id` | CWE-434 |
| `owasp_controls` | INPUT-1, INPUT-5, DES-5 |
| `payload_corpus` | `02-payloads/web/` (`web-upload.md` entries) |
| `tooling` | `07-tooling/cyberchef/` for magic-byte normalisation |

## 1. Bypass ladder

```
report.php.jpg.php        -> double extension, Apache multi-extension risk
report.php%00.jpg         -> null byte (legacy engines)
report.pHp                -> case-insensitive handler match
report.php.               -> trailing dot (Windows)
report.php::$DATA         -> NTFS alternate data stream
report.pdf -> magic bytes -> upload .png with %PDF- header
polyglot .jpg + .php       -> EXIF injection, GIF89a polyglots
.zip with .php entry       -> if extraction is by name only
```

## 2. Content validation, done properly

```bash
# never trust the client MIME type - inspect the bytes
xxd -l 16 uploaded.bin
file --mime-type uploaded.bin
# compare declared type, client MIME, extension and actual magic bytes - all four
```

## 3. Execution vectors

| Vector | Condition |
|---|---|
| Direct execution | Uploaded file served by the app server in an executable location |
| PHP include | File lands where an include/require can reach it |
| Template | `.ftl`, `.tpl`, `.jsp`, `.shtml` extension execution |
| Image parser | ImageMagick `convert`, `identify`, PHP `getimagesize()` |
| Archive extraction | Zip-slip (`../`), symlink entries, tar traversal |

## 4. Remediation

1. Store uploads outside the web root, serve from a separate origin (OWASP DES-5).
2. Allow-list extensions and derive the stored name server-side; never trust
   the client filename (OWASP INPUT-5).
3. Validate content by magic bytes, re-encode images (re-serialize, do not just
   check the header).
4. Disable execution in the upload directory (`engine off`, no handler).
5. Size limits, per-user quotas, and quarantine scanning.

## 5. Detection

* Wazuh rule `86670`: web server writes a new file with an executable extension
  into a served path.
* Wazuh rule `86671`: `ImageMagick`/`ffmpeg` spawned by a web server process.
* Suricata `ssa-web-attacks.rules` sid `3001015`: upload with a double extension.
