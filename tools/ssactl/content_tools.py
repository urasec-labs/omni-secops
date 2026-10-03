"""Curated content for 07-tooling, 08-threatintel, 09-labs."""

from __future__ import annotations

FILES: dict[str, str] = {}

# ===========================================================================
# 07-tooling
# ===========================================================================

FILES["07-tooling/cyberchef/README.md"] = r'''
# CyberChef Data Transformation Recipes

| Field | Value |
|---|---|
| `tool_id` | TOOL-CYBERCHEF |
| `source` | gchq/CyberChef @ v10.42.0 |
| `license` | Apache-2.0 |
| `recipe_dir` | `07-tooling/cyberchef/recipes/` |
| `recipe_format` | CyberChef "Save recipe" JSON (see `recipes/*.recipe.json`) |

## 1. Why recipes are archived

Two reasons, both operational:

1. **Repeatability.** "Decode this blob the way we did last quarter" is a recipe,
   not a series of GUI clicks. Recipes are diffable, reviewable, and testable.
2. **Defensive utility.** Most recipes in the archive reverse-engineer attacker
   behaviour: decode a C2 config, unpack a layered encoding, identify an
   algorithm from ciphertext structure.

## 2. Recipe catalogue

| Recipe file | Use case | Operations |
|---|---|---|
| `url-decode-chain.recipe.json` | Multi-layer URL/hex encoding | URL Decode, Decode text (Base64), From Hex |
| `jwt-decode.recipe.json` | Read a JWT header/payload without a key | nothing - just eyeball |
| `pkcs7-asn1.parse.recipe.json` | Read certificate structure | Parse X.509 certificate, ASN.1 dump |
| `ransomware-note-extract.recipe.json` | Pull config from a ransom note | Find (Regex), Match offset, Drop bytes |
| `dns-exfil-extract.recipe.json` | Reassemble hex data from subdomains | Regex groups, Concat, From Hex |
| `cobalt-strike-config.recipe.json` | Decode an encoded beacon config | XOR, From Hex, Find |
| `powershell-obfuscation-unfold.recipe.json` | Normalise `-eNxx` encoded commands | Charcode, From Decimal |

## 3. Using a recipe

```bash
# open the CyberChef web app, Menu > Load recipe, paste the JSON
# or run headless against a file
node cyberchef_cli.js -r 07-tooling/cyberchef/recipes/url-decode-chain.recipe.json \
                      -i input.bin -o output.txt
```

## 4. Authoring rules

1. Every operation in a recipe must be from the CyberChef operation catalogue
   (check the operation count in the "Save recipe" dialog).
2. Recipes must be **idempotent or explicitly single-pass**; document which.
3. No operation that reaches the network (`Fetch URL`, `Scan for IP addresses`
   is fine - it is local).
4. Include `description`, `author`, `created` in the recipe JSON.
5. Test the recipe against a known input and store both under
   `07-tooling/cyberchef/recipes/` with the expected output in the commit
   message or the recipe `notes` field.

## 5. Cautions

* Decoding untrusted data can produce huge output - set an operation limit.
* `Detect magic numbers` and `Identify` are heuristic; confirm before reporting.
* A recipe that "works" in the GUI may fail headless if it depends on a
  randomly chosen key; pin the key in the recipe arguments.
'''.lstrip()

FILES["07-tooling/cyberchef/recipes/url-decode-chain.recipe.json"] = r'''
{
  "name": "SSA - layered URL / Base64 / Hex decode",
  "description": "Applies URL decode, Base64 decode and hex decode in sequence. Use for encoded command lines, obfuscated PowerShell, and Cookie/Authorization header payloads. Repeat the chain manually if the output still contains base64 markers.",
  "author": "Sovereign Security Archive",
  "created": "2026-01-15",
  "notes": "Input: a string or file. Output order matters - URL decode first, then hex, then Base64. Verify each stage manually before trusting the final output.",
  "operations": [
    { "op": "To Base64", "args": { "alphabet": "A-Za-z0-9+/=", "removeNonAlphChars": false } },
    { "op": "URL Decode", "args": {} },
    { "op": "Decode text (Base64)", "args": { "removeNonAlphChars": false } },
    { "op": "From Hex", "args": { "space": "none", "ignoreInvalidChar": false } },
    { "op": "Decode text (Base64)", "args": { "removeNonAlphChars": false } }
  ]
}
'''.lstrip()

FILES["07-tooling/cyberchef/recipes/dns-exfil-extract.recipe.json"] = r'''
{
  "name": "SSA - reassemble DNS exfiltration subdomains",
  "description": "Extracts hex-encoded data segments from queried subdomains, concatenates them in label order and decodes to raw bytes.",
  "author": "Sovereign Security Archive",
  "created": "2026-01-15",
  "notes": "Feed the list of queried hostnames from 08-threatintel or the proxy log. Manual step: sort segments by their leading sequence number before concatenating.",
  "operations": [
    { "op": "Find / Replace", "args": { "find": "^[a-z0-9]+\\.exfil\\.example\\.", "replace": "" } },
    { "op": "Split", "args": { "delimiter": "\\n", "join": "" } },
    { "op": "From Hex", "args": { "space": "none", "ignoreInvalidChar": true } },
    { "op": "Show on image", "args": { "stretch": 1, "scale": 10 } }
  ]
}
'''.lstrip()

FILES["07-tooling/cyberchef/recipes/powershell-obfuscation-unfold.recipe.json"] = r'''
{
  "name": "SSA - unfold PowerShell -EncodedCommand",
  "description": "Base64-decodes the argument of -EncodedCommand / -e and outputs UTF-16LE text for manual review.",
  "author": "Sovereign Security Archive",
  "created": "2026-01-15",
  "notes": "powershell.exe -EncodedCommand takes Base64 of UTF-16LE. CyberChef Base64 decodes to UTF-16 bytes; read the result as wide characters.",
  "operations": [
    { "op": "Find / Replace", "args": { "find": ".*-([Ee]|-[Ee]c|ncoded[Cc]ommand)\\s+", "replace": "" } },
    { "op": "From Base64", "args": { "removeNonAlphChars": false, "strictMode": false } },
    { "op": "To Hex", "args": { "delimiter": "", "lowerCase": false } }
  ]
}
'''.lstrip()

FILES["07-tooling/imhex/README.md"] = r'''
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
'''.lstrip()

FILES["07-tooling/imhex/patterns/png-chunks.hexpat"] = r'''
// Sovereign Security Archive - PNG chunk structure
// purpose: locate tEXt/iTXt/zTXt chunks used to hide exfiltrated data
// source:  PNG (Portable Network Graphics) Specification, section 5.6
// usage:   imhex --pattern png-chunks.hexpat <file>

#pragma endian little

struct ChunkHeader {
    u32 length;
    char type[4];
};

struct PngChunk {
    ChunkHeader header;
    u8         data[header.length];
    u32        crc;
};

struct PngImage {
    u8   signature[8];      // 89 50 4E 47 0D 0A 1A 0A
    PngChunk chunks[while(!feof())];
};

PngImage png @ 0x00;
'''.lstrip()

FILES["07-tooling/imhex/patterns/pe-executable.hexpat"] = r'''
// Sovereign Security Archive - PE/COFF executable headers
// purpose: triage a binary dropped by a living-off-the-land technique
// source:  Microsoft PE/COFF Specification
// usage:   imhex --pattern pe-executable.hexpat <file>

#pragma endian little

struct DosHeader {
    u16 e_magic;      // 0x5A4D "MZ"
    u16 e_cblp;
    u16 e_cp;
    u16 e_crlc;
    u16 e_cparhdr;
    u16 e_minalloc;
    u16 e_maxalloc;
    u16 e_ss;
    u16 e_sp;
    u16 e_csum;
    u16 e_ip;
    u16 e_cs;
    u16 e_lfarlc;
    u16 e_ovno;
    u16 e_res[4];
    u16 e_oemid;
    u16 e_oeminfo;
    u16 e_res2[10];
    u32 e_lfanew;     // offset to PE signature
};

struct FileHeader {
    u16 machine;
    u16 numberOfSections;
    u32 timeDateStamp;
    u32 pointerToSymbolTable;
    u32 numberOfSymbols;
    u16 sizeOfOptionalHeader;
    u16 characteristics;
};

struct OptionalHeader32 {
    u16 magic;        // 0x10B PE32 / 0x20B PE32+
    u8  majorLinkerVersion;
    u8  minorLinkerVersion;
    u32 sizeOfCode;
    u32 sizeOfInitializedData;
    u32 sizeOfUninitializedData;
    u32 addressOfEntryPoint;
    u32 baseOfCode;
    u32 baseOfData;
    u32 imageBase;
    u32 sectionAlignment;
    u32 fileAlignment;
    u16 majorOperatingSystemVersion;
    u16 minorOperatingSystemVersion;
    u16 majorImageVersion;
    u16 minorImageVersion;
    u16 majorSubsystemVersion;
    u16 minorSubsystemVersion;
    u32 win32VersionValue;
    u32 sizeOfImage;
    u32 sizeOfHeaders;
    u32 checkSum;
    u16 subsystem;
    u16 dllCharacteristics;
    u32 sizeOfStackReserve;
    u32 sizeOfStackCommit;
    u32 sizeOfHeapReserve;
    u32 sizeOfHeapCommit;
    u32 loaderFlags;
    u32 numberOfRvaAndSizes;
};

struct SectionHeader {
    char name[8];
    u32 virtualSize;
    u32 virtualAddress;
    u32 sizeOfRawData;
    u32 pointerToRawData;
    u32 pointerToRelocations;
    u32 pointerToLinenumbers;
    u16 numberOfRelocations;
    u16 numberOfLinenumbers;
    u32 characteristics;
};

struct CoffFile {
    DosHeader       dos       @ 0x00;
    char            pe_sig[4] @ dos.e_lfanew;   // "PE\0\0"
    FileHeader      file      @ $;
    OptionalHeader32 opt      @ $;
    SectionHeader   sections[file.numberOfSections] @ $;
};

CoffFile pe @ 0x00;

// Suspicion helpers (evaluate manually, never auto-report)
bool hasExecSections = false;
for (u32 i = 0, n = pe.file.numberOfSections; i < n; ++i) {
    u32 c = pe.sections[i].characteristics;
    if ((c & 0x20000000) && (c & 0x80000000)) hasExecSections = true; // CODE|EXEC
    if (c & 0x80000000) {}                                            // MEM_EXECUTE
}
'''.lstrip()

FILES["07-tooling/imhex/patterns/zip-central-directory.hexpat"] = r'''
// Sovereign Security Archive - ZIP central directory
// purpose: detect zip-slip and absolute-path entries during upload analysis
// source:  PKWARE APPNOTE.TXT, section 4.3.16 (central file header)
//
// flag bits (general purpose): 0x0001 encrypted, 0x0008 data descriptor,
// 0x0800 UTF-8 names. Report entries whose name contains "..", a drive letter,
// a leading "/", or a NUL byte.

#pragma endian little

struct Zip64EndOfCentralDirectory {
    u32 signature;       // 0x06064b50
    u64 sizeOfZip64EndOfCentralDirectoryRecord;
    u16 versionMadeBy;
    u16 versionNeededToExtract;
    u32 diskNumber;
    u32 diskWithStartOfCentralDirectory;
    u64 centralDirectoryDiskEntriesOnThisDisk;
    u64 centralDirectoryEntriesOnThisDisk;
    u64 sizeOfCentralDirectory;
    u64 offsetOfStartOfCentralDirectory;
};

struct ZipCentralFileHeader {
    u32 signature;                       // 0x02014b50
    u16 versionMadeBy;
    u16 versionNeeded;
    u16 generalPurposeBitFlag;
    u16 compressionMethod;
    u16 lastModFileTime;
    u16 lastModFileDate;
    u32 crc32;
    u32 compressedSize;
    u32 uncompressedSize;
    u16 fileNameLength;
    u16 extraFieldLength;
    u16 fileCommentLength;
    u16 diskNumberStart;
    u16 internalFileAttributes;
    u32 externalFileAttributes;
    u32 relativeOffsetOfLocalHeader;
    char fileName[fileNameLength];
    u8  extraField[extraFieldLength];
    u8  fileComment[fileCommentLength];
};

Zip64EndOfCentralDirectory eocd @ 0x00;
ZipCentralFileHeader     cdh[while(!feof())] @ eocd.offsetOfStartOfCentralDirectory;

// Tripwires a human reviewer must inspect
//   1. fileName containing "../"            -> zip-slip
//   2. fileName containing ":" or leading / -> absolute path
//   3. externalFileAttributes with unix mode 04755 -> setuid inside archive
//   4. fileName containing a NUL byte       -> truncation / parser confusion
'''.lstrip()

# ===========================================================================
# 08-threatintel
# ===========================================================================

FILES["08-threatintel/feeds/feed-registry.yaml"] = r'''
# Sovereign Security Archive - threat feed registry
# schema: 12-schemas/ioc.schema.json
# owner:  @cti-maintainer
# rule:   every feed must declare a reliability, an update cadence and a license.

feeds:
  - id: FEED-001
    name: MalwareBazaar
    kind: malware-hash
    url: https://bazaar.abuse.ch/export/txt/sha256/recent/
    format: plain
    reliability: A
    cadence: hourly
    license: public
    normalisation:
      observable_type: file
      hash: sha256
    notes: High fidelity; hash-only so no false positive risk.

  - id: FEED-002
    name: URLhaus
    kind: url
    url: https://urlhaus.abuse.ch/downloads/csv_recent/
    format: csv
    reliability: A
    cadence: hourly
    license: public
    normalisation:
      observable_type: url
      strip_utm: true
    notes: Trim the payload column; never fetch the payload.

  - id: FEED-003
    name: ThreatFox IOC
    kind: multi
    url: https://threatfox.abuse.ch/export/json/recent/
    format: json
    reliability: B
    cadence: 6-hourly
    license: public
    normalisation:
      observable_type: dynamic
    notes: Contains some low-confidence entries; keep the confidence field.

  - id: FEED-004
    name: Feodo Tracker (botnet C2)
    kind: ipv4
    url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    format: plain
    reliability: A
    cadence: 12-hourly
    license: public
    normalisation:
      observable_type: ipv4

  - id: FEED-005
    name: Emerging Threats Compromised IP
    kind: ipv4
    url: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
    format: plain
    reliability: C
    cadence: daily
    license: CC-BY-SA-3.0
    normalisation:
      observable_type: ipv4
    notes: Shared infrastructure causes false positives - score, do not block.

  - id: FEED-006
    name: OpenPhish
    kind: url
    url: https://openphish.com/feed.txt
    format: plain
    reliability: B
    cadence: daily
    licence_note: free feed, commercial use restricted
    normalisation:
      observable_type: url

  - id: FEED-007
    name: CERT Polska Feeds
    kind: multi
    url: https://cert.pl/hostname/white_list.txt
    format: plain
    reliability: B
    cadence: daily
    license: public
    normalisation:
      observable_type: hostname
    notes: Warnlist of malicious hostnames.

  - id: FEED-008
    name: Internal SOC enrichment
    kind: multi
    url: internal://cti/enriched
    format: stix
    reliability: A
    cadence: on-demand
    license: internal
    normalisation:
      observable_type: dynamic
    notes: Derived from internal detections; feeds 10-crosswalk/control-detection.
'''.lstrip()

FILES["08-threatintel/ioc/ioc-schema-notes.md"] = r'''
# IOC Normalisation Contract

Machine readable schema: `12-schemas/ioc.schema.json`.
This page explains the decisions; the schema is the authority.

## 1. Observable types

| `observable_type` | Meaning | Validation |
|---|---|---|
| `ipv4` | IPv4 address | dotted quad, no leading zeros |
| `ipv6` | IPv6 address | RFC 4291 compressed form |
| `domain` | FQDN | lowercase, IDNA punycode, <= 253 |
| `url` | full URL | scheme + host + optional path |
| `file` | hash | sha256/md5/sha1/imphash |
| `email` | mailbox | RFC 5322 minimal |
| `registry` | Windows registry key | `HKLM\...` form |
| `mutex` | named mutex | literal |
| `user-agent` | HTTP UA | literal |

## 2. Mandatory fields

```json
{
  "id": "IOC-2026-000001",
  "type": "domain",
  "value": "malicious.example",
  "confidence": 90,
  "severity": "high",
  "source": "FEED-002",
  "first_seen": "2026-01-14T00:00:00Z",
  "last_seen": "2026-01-15T00:00:00Z",
  "tlp": "amber",
  "tags": ["c2", "phishing"],
  "mitre": ["T1071.001"],
  "expires": "2026-04-15T00:00:00Z",
  "context": "observed in DNS exfiltration sample SSA-2026-0007"
}
```

## 3. Rules that prevent alert fatigue

1. **Never block on `confidence < 70` with reliability `C`.** Score it.
2. **Always set `expires`.** IOCs rot; an unbounded IOC list is a false-positive
   generator within a year.
3. **Prefer infrastructure indicators** (`ipv4`, `domain`) over file hashes for
   blocking: hashes do not survive a rebuild.
4. **Store the source feed id**, never only the name - feeds get replaced.
5. **TLP markings are respected end to end** (see `08-threatintel/README.md`).

## 4. Validation

```bash
python tools/ssactl.py validate --root .
# or, with the optional jsonschema dependency
pip install jsonschema
python tools/ssactl.py validate --root . --strict-json
```
'''.lstrip()

FILES["08-threatintel/ioc/sample-iocs.json"] = r'''
{
  "schema": "12-schemas/ioc.schema.json",
  "set_id": "IOCSET-SAMPLE",
  "classification": "T1",
  "provenance": { "source": "AWETI", "ref": "master@2026-01-05" },
  "iocs": [
    { "id": "IOC-2026-000001", "type": "domain",     "value": "c2.malicious.example",     "confidence": 95, "severity": "critical", "source": "FEED-002", "first_seen": "2026-01-10T00:00:00Z", "last_seen": "2026-01-15T00:00:00Z", "tlp": "amber", "tags": ["c2"], "mitre": ["T1071.001"], "expires": "2026-04-10T00:00:00Z", "context": "HTTP beaconing sample" },
    { "id": "IOC-2026-000002", "type": "ipv4",       "value": "203.0.113.42",              "confidence": 90, "severity": "high",     "source": "FEED-004", "first_seen": "2026-01-11T00:00:00Z", "last_seen": "2026-01-15T00:00:00Z", "tlp": "amber", "tags": ["c2", "botnet"], "mitre": ["T1071"], "expires": "2026-04-11T00:00:00Z", "context": "botnet C2 list" },
    { "id": "IOC-2026-000003", "type": "file",       "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "confidence": 100, "severity": "critical", "source": "FEED-001", "first_seen": "2026-01-12T00:00:00Z", "last_seen": "2026-01-12T00:00:00Z", "tlp": "amber", "tags": ["malware", "loader"], "mitre": ["T1105"], "expires": "2027-01-12T00:00:00Z", "context": "loader sample SHA-256" },
    { "id": "IOC-2026-000004", "type": "url",        "value": "http://malicious.example/login.php?cmd=", "confidence": 88, "severity": "high", "source": "FEED-002", "first_seen": "2026-01-12T00:00:00Z", "last_seen": "2026-01-14T00:00:00Z", "tlp": "amber", "tags": ["c2"], "mitre": ["T1071.001"], "expires": "2026-04-12T00:00:00Z", "context": "gate panel" },
    { "id": "IOC-2026-000005", "type": "domain",     "value": "phish-target.example",       "confidence": 72, "severity": "medium",   "source": "FEED-007", "first_seen": "2026-01-13T00:00:00Z", "last_seen": "2026-01-13T00:00:00Z", "tlp": "amber", "tags": ["phishing"], "mitre": ["T1566.002"], "expires": "2026-04-13T00:00:00Z", "context": "warnlist entry, score do not block" },
    { "id": "IOC-2026-000006", "type": "registry",   "value": "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command", "confidence": 99, "severity": "critical", "source": "FEED-008", "first_seen": "2026-01-14T00:00:00Z", "last_seen": "2026-01-15T00:00:00Z", "tlp": "green", "tags": ["persistence"], "mitre": ["T1547.001"], "expires": "2026-07-14T00:00:00Z", "context": "internal enrichment" },
    { "id": "IOC-2026-000007", "type": "user-agent", "value": "Mozilla/5.0 (compatible; BeaconScript/2.1)", "confidence": 65, "severity": "low", "source": "FEED-008", "first_seen": "2026-01-14T00:00:00Z", "last_seen": "2026-01-15T00:00:00Z", "tlp": "green", "tags": ["c2"], "mitre": ["T1071.001"], "expires": "2026-02-14T00:00:00Z", "context": "detection only, never block on UA alone" },
    { "id": "IOC-2026-000008", "type": "mutex",      "value": "Global\\SSA-Demo-4C1F",     "confidence": 97, "severity": "high",     "source": "FEED-008", "first_seen": "2026-01-15T00:00:00Z", "last_seen": "2026-01-15T00:00:00Z", "tlp": "green", "tags": ["malware"], "mitre": ["T1547.001"], "expires": "2026-04-15T00:00:00Z", "context": "lab emulation EV-WIN-0003" }
  ]
}
'''.lstrip()

FILES["08-threatintel/actors/actor-matrix.md"] = r'''
# Threat Actor Matrix

| Field | Value |
|---|---|
| `dossier_id` | ACT-* |
| `source` | `08-threatintel/feeds/feed-registry.yaml`, internal analysis |
| `classification` | T1 (contains assessment, not just facts) |

## 1. Tracked actor profiles

| Actor ID | Tracked name | Sector | Initial access | Primary objective | Archive techniques |
|---|---|---|---|---|---|
| ACT-001 | FIN-LEA / financially motivated intrusion cluster | Finance, retail | Phishing, valid accounts | Financial fraud | T1566.002, T1078, T1486 |
| ACT-002 | SUPPLY / CI supply-chain actor | Software, energy | CI/CD compromise | Long-term persistence | T1195.002, T1505.003, T1197 |
| ACT-003 | RANSOM-AGG / ransomware affiliate | Healthcare, manufacturing | RDP, VPN | Encryption + extortion | T1133, T1486, T1490, T1567 |
| ACT-004 | CLOUD-PIVOT / cloud-focused actor | SaaS, technology | Valid cloud sessions | Cloud takeover | T1078.004, T1552.005, T1548.005, T1550.001 |
| ACT-005 | EDGE-APT / espionage actor | Government, telecom | Spearphishing, edge devices | Persistent access | T1190, T1059.008, T1021.001 |
| ACT-006 | LLM-ABUSE / prompt-injection actor | SaaS | Web content | Model tool abuse | T1195, T1204.002, T1567 |

## 2. Profile template

```markdown
### ACT-00X - <tracked name>
- First observed: <YYYY-MM>
- Sector targets: <list>
- Initial vectors:    Txxxx ...
- Persistence:       Txxxx ...
- Evasion:           Txxxx ...
- Credential access: Txxxx ...
- Exfiltration:      Txxxx ...
- Archive coverage:  see 06-defense/blue-team/mitre-coverage.csv rows for <technique list>
- Detection gaps:    <technique ids in state "offensive-only" or "gap">
- Confidence:        high | medium | low  (with basis)
```

## 3. Discipline

* Track **techniques**, not names. Attribution changes; TTP persistence is the
  signal.
* Every "high confidence" attribution needs a stated basis (infrastructure
  overlap, code reuse with a published report, victimology).
* Each actor row must name the archive technique ids it uses so coverage gaps
  are visible immediately.
'''.lstrip()

FILES["08-threatintel/attack/technique-pages/T1190.md"] = r'''
# T1190 - Exploit Public-Facing Application

| Field | Value |
|---|---|
| `technique_id` | T1190 |
| `tactic` | Initial Access |
| `archive_coverage` | full |
| `offensive_artifacts` | `02-payloads/web/**`, `05-engines/metasploit/modules/**` |
| `evasion_ids` | EV-WIN-0007 |
| `detections` | Suricata 3001001-3001014, Wazuh 100020-100022, Sigma `ssa_web_*` |

## Offensive view

| Entry point | Playbook | Payload corpus |
|---|---|---|
| SQL injection | `01-intel/playbooks/web/sql-injection.md` | `02-payloads/web/sqli/` |
| XSS | `01-intel/playbooks/web/xss.md` | `02-payloads/web/xss/` |
| SSRF | `01-intel/playbooks/web/ssrf.md` | `02-payloads/web/ssrf/` |
| File upload | `01-intel/playbooks/web/file-upload.md` | `02-payloads/api/` |
| Deserialisation | `01-intel/playbooks/os/windows/execution.md` | `02-payloads/api/` |
| Known CVEs | `10-crosswalk/attack-coverage/attack-coverage.csv` | `05-engines/metasploit/` |

## Defensive view

| Layer | Anchor |
|---|---|
| Network | Suricata `3001001` (SQLi tautology), `3001006` (XSS probe), `3001007` (upload ext) |
| Web app log | Wazuh `100020`, `100021`, `100032` via `if_sid 31151` |
| WAF | managed rule engine, correlate with the Suricata sids above |
| Vulnerability management | `06-defense/blue-team/controls/controls.csv` INJ-1, DOM-1, UPL-5 |

## Attacker behaviour notes

* Scanning is automated and indiscriminate - expect probes within minutes of
  exposure; do not treat each probe as a targeted campaign.
* Successful exploitation is followed within 60 seconds by either
  `PL-WEB-SSRF-*` (lateral/pivot) or a web shell write (`Wazuh 100030`).
* Credential replay on the compromised account usually follows within 15
  minutes (`Wazuh 100011`).

## Coverage judgement

`full` - offensive artifacts, evasion primitives and layered detections exist,
and the emulations `CH-001` and `PB-WEB-SQLI` replay end to end in the lab.
'''.lstrip()

FILES["08-threatintel/README.md"] = r'''
# Threat Intelligence

| Field | Value |
|---|---|
| `domain` | CTI |
| `owner` | `@cti-maintainer` |
| `feeds` | `08-threatintel/feeds/feed-registry.yaml` |
| `iocs` | `08-threatintel/ioc/` (schema `12-schemas/ioc.schema.json`) |
| `actors` | `08-threatintel/actors/` |
| `attack` | `08-threatintel/attack/technique-pages/` |

## 1. Operating model

```
  feeds ──► normalise ──► enrich ──► score ──► distribute ──► measure
  (yaml)   (12-schemas)  (actor   (confid.  (Suricata /   (hit rate,
                      ioc.json)  mapping)  Wazuh /    false pos,
                                            SIEM)     time-to-detect)
```

## 2. TLP handling

| Mark | Storage | Distribution | Example |
|---|---|---|---|
| TLP:CLEAR | repo `08-threatintel/ioc/` | public | open-source feed IOCs |
| TLP:GREEN | repo | internal | internal enrichment |
| TLP:AMBER | repo with `classification: T1` | named recipients only | partner-shared IOCs |
| TLP:AMBER+STRICT | external secret store, **not** in git | case participants | breach-specific IOCs |
| TLP:RED | external secret store, **not** in git | named individuals only | pre-release actor intel |

Red and Amber+Strict material must never be committed. Use the case management
system.

## 3. Quality metrics tracked quarterly

| Metric | Target |
|---|---|
| Feed freshness (p95 `last_seen` lag) | < 6 h for reliability A feeds |
| IOC precision (confirmed true positives / alerts) | > 90 % |
| Median time to detect (MTTD) for new feed IOCs | < 30 min |
| Percentage of IOCs with `expires` set | 100 % |
| Coverage of the active actor list | every tracked actor mapped |

## 4. Relationship to the crosswalk

CTI feeds the archive in both directions:

* **In**: `10-crosswalk/attack-coverage/attack-coverage.csv` maps actor
  techniques to the offensive and defensive artifacts.
* **Out**: `06-defense/blue-team/mitre-coverage.csv` shows which techniques are
  `offensive-only` or `gap`, which is the CTI priority queue for detection
  engineering.
'''.lstrip()

# ===========================================================================
# 09-labs
# ===========================================================================

FILES["09-labs/README.md"] = r'''
# Lab Environments

| Field | Value |
|---|---|
| `domain` | Validation |
| `owner` | `@lab-maintainer` |
| `source` | `0xdea/awesome-hacking`, `meirwah/awesome-incident-response` |
| `estate` | `09-labs/infrastructure/` |
| `classification` | T0 (deliberately vulnerable, lab only) |

## 1. Rules

1. **Never deploy the lab estate on a routable network.** Use a host-only or
   isolated lab segment.
2. **Never store real credentials, real data, or real keys in a lab app.**
3. Lab machines carry no access to production identity providers.
4. Every emulation states the expected telemetry and expected rule ids.
5. Any deviation from the expected telemetry is a finding, recorded in
   `10-crosswalk/attack-coverage/attack-coverage.csv`.

## 2. Contents

| Path | What it is | Source |
|---|---|---|
| `apps/` | deliberately vulnerable applications | `09-labs/apps/docker-compose.dvwa.yml` |
| `infrastructure/` | Terraform/Docker estate | `09-labs/infrastructure/terraform-lab.md` |
| `emulations/` | atomic attack emulations per `EV-*` / `CH-*` | `09-labs/emulations/CH-001.md` |
| `ctf/` | categories and tooling | `09-labs/ctf/` |

## 3. Build

```bash
cd 09-labs/infrastructure
docker compose -f docker-compose.lab.yml up -d
# verify
python 11-automation/scripts/lab_healthcheck.py --root ../..
```

## 4. Teardown

```bash
docker compose -f docker-compose.lab.yml down -v
# verify nothing is left listening
ss -tulpn | grep -E ':(80|443|22|8080)\b' || echo "lab torn down"
```
'''.lstrip()

FILES["09-labs/apps/docker-compose.dvwa.yml"] = r'''
# Sovereign Security Archive - deliberately vulnerable lab estate
# WARNING: this stack is intentionally exploitable. Host-only networking only.
# provenance: 09-labs/apps (Awesome Hacking tool index) + OWASP-CS controls

name: ssa-lab

services:

  dvwa:
    image: vulnerables/web-dvwa:latest
    container_name: ssa-dvwa
    networks: [labnet]
    ports:
      - "127.0.0.1:8080:80"      # loopback bind only
    environment:
      DB_SERVER: dvwa-db
    labels:
      ssa.role: "web-target"
      ssa.playbook: "01-intel/playbooks/web/sql-injection.md"
      ssa.expected_rules: "3001001,3001003,3001006"

  dvwa-db:
    image: docker.io/library/mariadb:11
    container_name: ssa-dvwa-db
    networks: [labnet]
    environment:
      MARIADB_DATABASE: dvwa
      MARIADB_USER: dvwa
      MARIADB_PASSWORD: lab-only-not-a-secret
    labels:
      ssa.role: "data-tier"

  juice-shop:
    image: bkimminich/juice-shop:latest
    container_name: ssa-juice-shop
    networks: [labnet]
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      NODE_ENV: "production"
    labels:
      ssa.role: "web-target"
      ssa.playbook: "01-intel/playbooks/web/authentication-bypass.md"
      ssa.expected_rules: "3001404"

  log4j-demo:
    image: ghcr.io/christophetd/log4shell-vulnerable-app:latest
    container_name: ssa-log4j-demo
    networks: [labnet]
    ports:
      - "127.0.0.1:8081:8080"
    labels:
      ssa.role: "web-target"
      ssa.payload: "PL-INFRA-0020"
      ssa.expected_rules: "3001004"

  suricata-sensor:
    image: suricata/suricata:7.0.10
    container_name: ssa-suricata
    network_mode: host
    volumes:
      - ../../06-defense/suricata/rules:/etc/suricata/rules:ro
      - ../../06-defense/suricata/thresholds:/etc/suricata/thresholds:ro
      - suricata-logs:/var/log/suricata
    command: ["-c", "/etc/suricata/suricata.yaml", "--af-packet", "-l", "/var/log/suricata"]
    labels:
      ssa.role: "network-sensor"

  wazuh-manager:
    image: wazuh/wazuh-manager:4.9.0
    container_name: ssa-wazuh-manager
    network_mode: host
    volumes:
      - ../../06-defense/wazuh:/var/ossec/etc/shared:ro
      - wazuh-logs:/var/log/wazuh
    labels:
      ssa.role: "host-sensor"

  collector:
    image: python:3.12-slim
    container_name: ssa-collector
    network_mode: host
    volumes:
      - ../../10-crosswalk:/crosswalk:ro
      - ../../11-automation:/automation:ro
    command: ["python", "/automation/scripts/lab_healthcheck.py", "--root", "/crosswalk/../.."]
    labels:
      ssa.role: "validator"

networks:
  labnet:
    driver: bridge
    internal: true          # no route to the outside world from the lab

volumes:
  suricata-logs:
  wazuh-logs:
'''.lstrip()

FILES["09-labs/infrastructure/terraform-lab.md"] = r'''
# Lab Estate with Terraform

| Field | Value |
|---|---|
| `estate_id` | LAB-ESTATE-01 |
| `provider` | docker (default), libvirt (hypervisor) |
| `isolation` | internal bridge network, no default route |

## 1. Minimal estate

```hcl
terraform {
  required_version = ">= 1.6"
  required_providers {
    docker = { source = "kreuzwerker/docker", version = "~> 3.0" }
  }
}

provider "docker" {}

variable "lab_subnet" { default = "172.28.0.0/24" }

resource "docker_network" "lab" {
  name = "ssa-lab"
  # internal = true -> no external connectivity
  internal = true
  ipam_config {
    subnet = var.lab_subnet
  }
}

resource "docker_image" "target" {
  name = "vulnerables/web-dvwa:latest"
}

resource "docker_container" "target" {
  name  = "ssa-target"
  image = docker_image.target.image_id
  networks_advanced { name = docker_network.lab.name }
  ports {
    internal = 8080
    external = 0            # never publish to the host
  }
  labels = {
    ssa_role   = "web-target"
    ssa_lab    = "LAB-ESTATE-01"
    ssa_owner  = "lab-maintainer"
  }
}

resource "docker_image" "attacker" {
  name = "kalilinux/kali-rolling:latest"
}

resource "docker_container" "attacker" {
  name      = "ssa-attacker"
  image     = docker_image.attacker.image_id
  networks_advanced { name = docker_network.lab.name }
  tty = true
  stdin_open = true
  privileged = false         # privilege would invalidate the exercise
}

output "lab_network" { value = docker_network.lab.name }
```

## 2. Host firewall for the lab segment

```bash
# Linux host acting as the lab router
sudo iptables -A FORWARD -s 172.28.0.0/24 -d 0.0.0.0/0 -j DROP
sudo iptables -A FORWARD -s 172.28.0.0/24 -d 172.28.0.0/24 -j ACCEPT
sudo ip route add blackhole 0.0.0.0/1 dev lo
```

Windows equivalent (for PowerShell lab hosts):

```powershell
New-NetFirewallRule -DisplayName "SSA lab egress deny" -Direction Outbound `
  -RemoteAddress Internet -InterfaceAlias "vEthernet (ssa-lab)" -Action Block
```

## 3. Expected telemetry per estate

| Lab asset | Sensor | Expected |
|---|---|---|
| `ssa-target` | Suricata (host network mode) | sids from `06-defense/suricata/rules/` |
| `ssa-target` | Wazuh agent | rules 100010-100099, 101000-101099 |
| all containers | Docker daemon events | privileged / host-mount flags |
| lab host | OS audit | `auditd execve` for 101000-101004 |

## 4. Reset procedure

```bash
terraform destroy -auto-approve
docker network prune -f
# never: docker system prune -a --volumes  (destroys unrelated work)
```
'''.lstrip()

FILES["09-labs/emulations/CH-001.md"] = r'''
# Emulation CH-001 - Web to root on an internet-facing Linux host

| Field | Value |
|---|---|
| `emulation_id` | CH-001 |
| `target` | `ssa-target` (DVWA) in `09-labs/infrastructure/` |
| `chopra` | attacker -> initial access -> persistence -> privesc |
| `evasion_ids` | EV-LNX-0016, EV-LNX-0008 |
| `payload_ids` | PL-WEB-SSRF-0021 |
| `expected_sigma` | `ssa_linux_cron_persistence.yml`, `ssa_linux_suid_shell_copy.yml` |
| `expected_wazuh` | 101010, 101003, 100030 |
| `expected_suricata` | 3001003, 3001201 |
| `classification` | T0 (lab only) |

## 0. Pre-flight

```bash
python tools/ssactl.py verify --root . --strict
docker compose -f 09-labs/apps/docker-compose.dvwa.yml up -d
```

## 1. Hops

| Hop | Command (lab only) | Expected signal |
|---|---|---|
| 1 | Reach DVWA at `http://ssa-dvwa/` | baseline access log |
| 2 | SSRF vector: `gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/tmp` | Suricata `3001003`, Wazuh `100022` |
| 3 | Write a minimal web shell via Redis `SAVE` | Wazuh `100030` (`.php` created under web root) |
| 4 | `crontab -l; echo '* * * * * id > /tmp/probe' \| crontab -` | Sigma `ssa_linux_cron_persistence.yml`, Wazuh `101010` |
| 5 | `cp /bin/sh /tmp/.sh; chmod u+s /tmp/.sh` | Sigma `ssa_linux_suid_shell_copy.yml`, Wazuh `101003` |
| 6 | `/tmp/.sh -c id` | new session, uid 0 |

## 2. Verification

```bash
# Suricata
jq -r '.alert.signature' /var/log/suricata/eve.json | sort | uniq -c | grep -E 'SSA'

# Wazuh
grep -E 'rule:10(0030|1010|10100)' /var/log/wazuh/alerts/alerts.json | jq '.rule.description'

# auditd
ausearch -m EXECVE -i | grep -E 'find|chmod|crontab'
```

## 3. Results template

| Signal | Fired? | Rule | Notes |
|---|---|---|---|
| Suricata 3001003 | | | |
| Wazuh 100022 | | | |
| Wazuh 100030 | | | |
| Wazuh 101010 | | | |
| Wazuh 101003 | | | |

## 4. Defect handling

Any row left blank is a defect. Create a Sigma rule (or fix the existing one),
add the row to `10-crosswalk/evasion-detection/evasion-to-detection.csv`, and
note the outcome in `06-defense/blue-team/mitre-coverage.csv`.
'''.lstrip()

FILES["09-labs/emulations/EV-WIN-0001.md"] = r'''
# Emulation EV-WIN-0001 - Windows remote execution over SMB

| Field | Value |
|---|---|
| `emulation_id` | EV-WIN-0001 |
| `technique_id` | T1021.002 |
| `binary` | `psexec.exe` (Sysinternals / Impacket `psexec.py`) |
| `target` | lab Windows domain-joined host |
| `expected_sigma` | `ssa_windows_psexec.yml` |
| `expected_wazuh` | 100012 (logon after failures), Sysmon 1 |
| `expected_suricata` | 3001301 |
| `classification` | T0 (lab only) |

## 1. Steps

```powershell
# attacker box, lab network only
& .\PsExec.exe \\LAB-WEB-01 -u 'LAB\devops' -p 'LabOnlyPassw0rd!' -s cmd.exe /c "whoami > \\LAB-SHARE\evidence.txt"

# or Impacket
python3 psexec.py 'LAB\devops:LabOnlyPassw0rd!'@LAB-WEB-01 'whoami'
```

## 2. Expected telemetry

| Source | Signal |
|---|---|
| Windows 4624 | Type 3 logon from attacker host, `LogonType: 3`, service account |
| Windows 7045 | Service installed (`PSEXESVC`) |
| Sysmon 1 | `psexec.exe` parent `services.exe` |
| Sysmon 3 | Network connection by psexec |
| Suricata | `3001301` SMB admin-share traffic burst |

## 3. Result template

| Signal | Fired? |
|---|---|
| 7045 service install | |
| Sysmon 1 psexec | |
| 4624 type 3 | |
| Sigma `ssa_windows_psexec.yml` | |

## 4. Notes

Rule 7045 is the highest-fidelity indicator here and is often missed because
System and Security logs are not forwarded. Confirm forwarding before running
the emulation, otherwise you will record a false "gap".
'''.lstrip()

FILES["09-labs/ctf/README.md"] = r'''
# CTF Material

| Field | Value |
|---|---|
| `domain` | CTF / training |
| `owner` | `@lab-maintainer` |
| `use` | internal training, skill validation, interview practice |

## 1. Category map to the archive

| CTF category | Archive material | Skill measured |
|---|---|---|
| pwn | `02-payloads/os/`, `09-labs/emulations/` | memory corruption, ROP |
| web | `02-payloads/web/`, `01-intel/playbooks/web/` | injection, auth, logic |
| crypto | `01-intel/playbooks/crypto/` | classical/modern misuse |
| forensics | `07-tooling/imhex/`, `06-defense/ir/` | file carving, timeline |
| reversing | `07-tooling/imhex/` | static analysis |
| recon / osint | `05-engines/osint/`, `08-threatintel/` | information gathering |
| cloud | `01-intel/playbooks/cloud/` | IAM abuse, metadata |
| AD | `01-intel/playbooks/active-directory/` | Kerberos, ACL abuse |

## 2. Write-your-own rule

For each of the 10 windows in `13-training/assessments/quiz-bank.md`, the
practical is: write the payload, execute it in the lab, and record which
archive rule fired. A submission is accepted only when the detection fires and
the finding is written up in the format from
`01-intel/checklists/penetration-testing-checklist.md` §6.

## 3. Tenancy and legality

* Only infrastructure you own or are authorised to use.
* Keep CTF assets separate from the lab estate and from production identity
  providers.
* Do not reuse lab credentials anywhere else; `06-defense/ir/evidence-handling.md`
  applies if evidence must be produced.
'''.lstrip()