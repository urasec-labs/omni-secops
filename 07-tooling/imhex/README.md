# ImHex Binary Forensics Patterns

| Field | Value |
|---|---|
| `tool_id` | TOOL-IMHEX |
| `source` | WerWolv/ImHex @ v3.1.0 |
| `license` | GPL-2.0 |
| `pattern_format` | ImPat / HexPat (`.hexpat`) |
| `pattern_dir` | `07-tooling/imhex/patterns/` |

## 1. Purpose

ImHex is the archive's binary inspection tool of record for:

* Verifying magic bytes during file-upload analysis (`01-intel/playbooks/web/file-upload.md`).
* Reading embedded secrets in firmware and disk images.
* Confirming polyglot files and container structures.
* Producing byte-offset citations for forensic reports.

## 2. Pattern library

| Pattern | Inspects | Used by |
|---|---|---|
| `elf-x86-64.hexpat` | ELF headers, section table | `04-evasion/linux/`, forensics |
| `pe-executable.hexpat` | PE/COFF headers, imports, sections | `04-evasion/windows/` |
| `png-chunks.hexpat` | PNG chunk structure (for exfil hiding) | IR |
| `jpeg-app1-hexpat.hexpat` | JPEG APP1/EXIF segments | `09-labs/`, exfil |
| `zip-central-directory.hexpat` | ZIP central directory, zip-slip entries | upload analysis |
| `pdf-objects.hexpat` | PDF object table and streams | `09-labs/apps/` |
| `sqlite-header.hexpat` | SQLite header and page layout | forensics |
| `gzip-tar.hexpat` | gzip + tar headers | `07-tooling/cyberchef/` |

## 3. Workflow

```bash
# open a file
imhex ./evidence.bin

# validate a suspected upload against the PNG pattern
imhex --pattern 07-tooling/imhex/patterns/png-chunks.hexpat ./upload.png
```

Byte-offset citing in a finding:

```markdown
Evidence:
  File:      evidence/upload.png   SHA-256: <hash>
  Offset:    0x0000021A - 0x0000024D
  Pattern:   png-chunks.hexpat -> tEXt keyword
  Content:   "id=..; pw=.." (ASCII)
```

## 4. Rules of engagement for uploads

* Analyse a **copy**, in an isolated environment.
* Do not open untrusted files on a machine with sensitive credentials.
* If a file is a polyglot, do **not** execute it to "prove" anything - the
  offset evidence is sufficient and execution is out of scope.
