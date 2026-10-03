"""Canonical specification of the Sovereign Security Archive.

SOURCES : the 20 legendary upstream archives that feed this mega-repo.
TREE    : every directory, the upstream source(s) that feed it, and a blurb.
FEEDS   : reverse index, source -> directories (computed at import time).

Path separator is always POSIX so the spec is platform neutral.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 1. The 20 upstream sources
# ---------------------------------------------------------------------------

SOURCES: dict[str, dict[str, str]] = {
    "PAT": {
        "name": "PayloadsAllTheThings",
        "owner": "swisskyrepo",
        "license": "MIT",
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
        "role": "Offensive payload corpus",
        "primary": "02-payloads",
    },
    "SECLISTS": {
        "name": "SecLists",
        "owner": "danielmiessler",
        "license": "MIT",
        "url": "https://github.com/danielmiessler/SecLists",
        "role": "Discovery / fuzzing / credential wordlists",
        "primary": "03-wordlists",
    },
    "GTFOBINS": {
        "name": "GTFOBins",
        "owner": "GTFOBins",
        "license": "MIT",
        "url": "https://github.com/GTFOBins/GTFOBins",
        "role": "Abuse-case catalogue for legitimate signed binaries",
        "primary": "04-evasion",
    },
    "HACKTRICKS": {
        "name": "HackTricks",
        "owner": "carlospolop",
        "license": "GPL-3.0",
        "url": "https://github.com/carlospolop/HackTricks",
        "role": "Exploitation / privesc / methodology playbooks",
        "primary": "01-intel/playbooks",
    },
    "BOSK": {
        "name": "Book of Secret Knowledge",
        "owner": "dmknght",
        "license": "CC0-1.0",
        "url": "https://github.com/dmknght/BookOfSecretKnowledge",
        "role": "Operator toolbox: recon, tooling, hardening",
        "primary": "01-intel/cheat-sheets",
    },
    "H4CKER": {
        "name": "The Art of Hacking (h4cker)",
        "owner": "The-Art-of-Hacking",
        "license": "GPL-3.0",
        "url": "https://github.com/The-Art-of-Hacking/h4cker",
        "role": "Deep technical curriculum + self-hosted tooling",
        "primary": "01-intel/playbooks",
    },
    "90DAYS": {
        "name": "90 Days of Cyber Security",
        "owner": "0xDigit",
        "license": "MIT",
        "url": "https://github.com/0xDigit/90-Days-of-Cybersecurity",
        "role": "Structured 90-day onboarding curriculum",
        "primary": "13-training",
    },
    "AWEHACK": {
        "name": "Awesome Hacking",
        "owner": "0xdea",
        "license": "CC0-1.0",
        "url": "https://github.com/0xdea/awesome-hacking",
        "role": "Tool index for operators and lab builders",
        "primary": "09-labs",
    },
    "AWEPENTEST": {
        "name": "Awesome Pentest",
        "owner": "j0hnx3r",
        "license": "CC0-1.0",
        "url": "https://github.com/j0hnx3r/awesome-pentest",
        "role": "Engagement workflow: recon -> scan -> exploit -> report",
        "primary": "01-intel/methodologies",
    },
    "AWEIR": {
        "name": "Awesome Incident Response",
        "owner": "meirwah",
        "license": "CC0-1.0",
        "url": "https://github.com/meirwah/awesome-incident-response",
        "role": "IR playbooks, timeline, evidence handling",
        "primary": "06-defense/ir",
    },
    "AWETI": {
        "name": "Awesome Threat Intelligence",
        "owner": "amittmadan",
        "license": "CC0-1.0",
        "url": "https://github.com/stratascale/awesome-threat-intelligence",
        "role": "Feeds, IOC schema, CTI pipeline design",
        "primary": "08-threatintel",
    },
    "MSF": {
        "name": "Metasploit Framework",
        "owner": "rapid7",
        "license": "BSD-3-Clause",
        "url": "https://github.com/rapid7/metasploit-framework",
        "role": "Modular exploitation engine + post-exploitation",
        "primary": "05-engines/metasploit",
    },
    "SQLMAP": {
        "name": "sqlmap",
        "owner": "sqlmapproject",
        "license": "GPL-2.0",
        "url": "https://github.com/sqlmapproject/sqlmap",
        "role": "SQLi automation, tamper scripts, DB fingerprinting",
        "primary": "05-engines/sqlmap",
    },
    "SHERLOCK": {
        "name": "Sherlock",
        "owner": "sherlock-project",
        "license": "MIT",
        "url": "https://github.com/sherlock-project/sherlock",
        "role": "Username OSINT enumeration across platforms",
        "primary": "05-engines/osint",
    },
    "IMHEX": {
        "name": "ImHex",
        "owner": "WerWolv",
        "license": "GPL-2.0",
        "url": "https://github.com/WerWolv/ImHex",
        "role": "Hex editor / binary forensics patterns",
        "primary": "07-tooling/imhex",
    },
    "WAZUH": {
        "name": "Wazuh",
        "owner": "wazuh",
        "license": "GPL-2.0",
        "url": "https://github.com/wazuh/wazuh",
        "role": "XDR/SIEM rules, decoders, agent hardening",
        "primary": "06-defense/wazuh",
    },
    "SURICATA": {
        "name": "Suricata",
        "owner": "OISF",
        "license": "GPL-2.0",
        "url": "https://github.com/OISF/suricata",
        "role": "Network IDS/IPS rules and thresholds",
        "primary": "06-defense/suricata",
    },
    "CYBERCHEF": {
        "name": "CyberChef",
        "owner": "gchq",
        "license": "Apache-2.0",
        "url": "https://github.com/gchq/CyberChef",
        "role": "Data transform / encoding / decoding recipes",
        "primary": "07-tooling/cyberchef",
    },
    "OWASPCS": {
        "name": "OWASP Cheat Sheet Series",
        "owner": "OWASP",
        "license": "CC-BY-SA-4.0",
        "url": "https://github.com/OWASP/CheatSheetSeries",
        "role": "Authoritative secure-development controls",
        "primary": "01-intel/cheat-sheets/owasp",
    },
    "PSCL": {
        "name": "Personal Security Checklist",
        "owner": "0xNaN",
        "license": "MIT",
        "url": "https://github.com/0xNaN/personal-security-checklist",
        "role": "Individual / home-lab defensive baseline",
        "primary": "01-intel/checklists",
    },
}

# ---------------------------------------------------------------------------
# 2. The directory tree
#    (path, source_keys, blurb)
# ---------------------------------------------------------------------------

TREE: list[tuple[str, tuple[str, ...], str]] = [
    # -- 00 governance ------------------------------------------------------
    ("00-governance", (), "Charter, risk model, classification, release and compliance control plane."),
    ("00-governance/manifests", (), "Machine readable inventory: upstream lock file and generated archive manifest."),

    # -- 01 intel -----------------------------------------------------------
    ("01-intel", (), "Primary knowledge base: playbooks, methodologies, cheat sheets and checklists."),
    ("01-intel/playbooks", ("HACKTRICKS", "H4CKER"), "Offensive and defensive runbooks, one file per technique family."),
    ("01-intel/playbooks/web", ("HACKTRICKS", "OWASPCS"), "Web application attack and hardening runbooks."),
    ("01-intel/playbooks/network", ("HACKTRICKS", "AWEPENTEST"), "Network service enumeration, pivoting, relay and egress runbooks."),
    ("01-intel/playbooks/active-directory", ("HACKTRICKS", "BOSK"), "AD/Entra attack paths and corresponding detection anchors."),
    ("01-intel/playbooks/cloud", ("HACKTRICKS", "BOSK"), "AWS / Azure / GCP / Kubernetes abuse paths."),
    ("01-intel/playbooks/mobile", ("HACKTRICKS",), "Android / iOS application security runbooks."),
    ("01-intel/playbooks/crypto", ("HACKTRICKS",), "Applied cryptography misuse and break patterns."),
    ("01-intel/playbooks/hardening", ("PSCL", "OWASPCS"), "Defensive runbooks derived from the cheat sheet controls."),
    ("01-intel/methodologies", ("AWEPENTEST", "HACKTRICKS"), "OSSTMM / PTES / NIST SP 800-61 / MITRE ATT&CK mappings."),
    ("01-intel/cheat-sheets", ("BOSK", "H4CKER", "OWASPCS"), "Condensed operator reference cards."),
    ("01-intel/cheat-sheets/owasp", ("OWASPCS",), "OWASP cheat sheet ingestion, versioning and control identifiers."),
    ("01-intel/checklists", ("PSCL", "AWEPENTEST"), "Personal, workstation and engagement checklists."),

    # -- 02 payloads --------------------------------------------------------
    ("02-payloads", ("PAT",), "Normalized, schema-validated payload corpus (the offensive half of the archive)."),
    ("02-payloads/web", ("PAT",), "Browser-side and server-side web payloads."),
    ("02-payloads/web/sqli", ("PAT", "SQLMAP"), "SQL injection payloads aligned with sqlmap tamper scripts."),
    ("02-payloads/web/xss", ("PAT",), "Cross-site scripting contexts and breakouts."),
    ("02-payloads/web/ssrf", ("PAT",), "Server-side request forgery targets and bypasses."),
    ("02-payloads/web/xxe", ("PAT",), "XML external entity payloads and parameter entity variants."),
    ("02-payloads/web/ssti", ("PAT",), "Server-side template injection engines and probes."),
    ("02-payloads/api", ("PAT",), "REST, GraphQL, SOAP, JWT and header level payloads."),
    ("02-payloads/mobile", ("PAT",), "Android / iOS runtime payloads and intent abuse."),
    ("02-payloads/infrastructure", ("PAT", "GTFOBINS"), "Network services, LDAP, JNDI, template engines on infrastructure."),
    ("02-payloads/os", ("PAT", "GTFOBINS"), "Operating system level: shells, privesc, evasion primitives."),
    ("02-payloads/cloud", ("PAT",), "Cloud metadata and provider specific payloads."),
    ("02-payloads/templates", ("PAT",), "Payload record templates consumed by the payload schema."),

    # -- 03 wordlists -------------------------------------------------------
    ("03-wordlists", ("SECLISTS",), "Discovery, fuzzing and credential wordlists with a unified index."),
    ("03-wordlists/discovery", ("SECLISTS",), "Subdomain and host discovery wordlists."),
    ("03-wordlists/discovery/dns", ("SECLISTS",), "DNS bruteforce and zone-transfer wordlists."),
    ("03-wordlists/web", ("SECLISTS",), "Web content discovery and application wordlists."),
    ("03-wordlists/web/fuzzing", ("SECLISTS", "PAT"), "Fuzzing dictionaries, crosswalked against the payload corpus."),
    ("03-wordlists/credentials", ("SECLISTS",), "Password, username and default credential corpora."),
    ("03-wordlists/api", ("SECLISTS",), "API endpoint and parameter dictionaries."),
    ("03-wordlists/network", ("SECLISTS",), "Port, banner and protocol wordlists."),
    ("03-wordlists/tls", ("SECLISTS",), "TLS/SSL related wordlists."),
    ("03-wordlists/index", ("SECLISTS",), "Unified wordlist index (SQLite + CSV) used by every consumer."),

    # -- 04 evasion ---------------------------------------------------------
    ("04-evasion", ("GTFOBINS",), "Abuse cases for trusted binaries, ordered by triage triage-cost."),
    ("04-evasion/linux", ("GTFOBINS",), "SUID, sudo, editor, language interpreter and container escapes."),
    ("04-evasion/windows", ("GTFOBINS",), "Living-off-the-land on Windows: task schedulers, CLMXRANSOM, installers."),
    ("04-evasion/macos", ("GTFOBINS",), "macOS abuse of keychain, launchd, defaults and interpreters."),
    ("04-evasion/containers", ("GTFOBINS", "HACKTRICKS"), "Docker / Kubernetes / CI escape chains."),
    ("04-evasion/chains", ("GTFOBINS", "MSF"), "Multi-hop abuse chains with detection anchors per hop."),

    # -- 05 engines ---------------------------------------------------------
    ("05-engines", (), "Automation engines that consume the payload and wordlist corpora."),
    ("05-engines/metasploit", ("MSF",), "Metasploit module index, staging wrappers and hardening guidance."),
    ("05-engines/metasploit/modules", ("MSF", "PAT"), "Module index and payload binding table."),
    ("05-engines/metasploit/post-exploitation", ("MSF", "GTFOBINS"), "Post-exploitation modules crosswalked to evasion primitives."),
    ("05-engines/sqlmap", ("SQLMAP", "PAT"), "sqlmap configuration, tamper library and injection mapping."),
    ("05-engines/sqlmap/tamper", ("SQLMAP",), "Tamper script catalogue mapped onto payload entries."),
    ("05-engines/osint", ("SHERLOCK", "AWETI"), "Handle and identity OSINT collection."),
    ("05-engines/osint/sherlock", ("SHERLOCK",), "Username enumeration automation and false-positive handling."),

    # -- 06 defense ---------------------------------------------------------
    ("06-defense", ("WAZUH", "SURICATA", "OWASPCS"), "Defensive control plane: host telemetry, network rules, IR."),
    ("06-defense/wazuh", ("WAZUH",), "Wazuh manager configuration, rules and decoders."),
    ("06-defense/wazuh/rules", ("WAZUH", "OWASPCS"), "Host rules generated from the control crosswalk."),
    ("06-defense/wazuh/decoders", ("WAZUH",), "Custom decoders for structured log sources."),
    ("06-defense/wazuh/agents", ("WAZUH", "PSCL"), "Agent hardening profiles per workload class."),
    ("06-defense/suricata", ("SURICATA",), "Suricata IDS/IPS ruleset, thresholds and tuning."),
    ("06-defense/suricata/rules", ("SURICATA", "OWASPCS"), "Web, evasion and exfiltration rules."),
    ("06-defense/suricata/thresholds", ("SURICATA",), "Threshold and suppression tuning."),
    ("06-defense/blue-team", ("OWASPCS", "AWEPENTEST"), "Control-to-detection mapping and ATT&CK coverage."),
    ("06-defense/blue-team/controls", ("OWASPCS",), "Control catalogue with OWASP / NIST / CIS anchors."),
    ("06-defense/sigma", ("SURICATA", "WAZUH"), "Portable detections in Sigma format."),
    ("06-defense/hardening", ("PSCL", "OWASPCS"), "Linux, Windows, cloud and network hardening baselines."),
    ("06-defense/ir", ("AWEIR", "AWETI"), "Incident response playbooks, timeline and evidence handling."),

    # -- 07 tooling ---------------------------------------------------------
    ("07-tooling", (), "Analyst tooling playbooks: transformation recipes and binary inspection."),
    ("07-tooling/cyberchef", ("CYBERCHEF",), "Data transformation recipes for exfil and forensics work."),
    ("07-tooling/cyberchef/recipes", ("CYBERCHEF",), "Recipe library (.recipe.json) with SSA parameters."),
    ("07-tooling/imhex", ("IMHEX",), "ImHex pattern library for binary and file-format forensics."),

    # -- 08 threat intel ----------------------------------------------------
    ("08-threatintel", ("AWETI",), "Threat intelligence feeds, IOC handling and actor tracking."),
    ("08-threatintel/feeds", ("AWETI",), "Feed registry with reliability and update cadence."),
    ("08-threatintel/ioc", ("AWETI",), "Normalized IOC sets and validation rules."),
    ("08-threatintel/actors", ("AWETI", "MSF"), "Threat actor and campaign dossiers."),
    ("08-threatintel/attack", ("AWETI",), "MITRE ATT&CK technique pages enriched with archive data."),

    # -- 09 labs ------------------------------------------------------------
    ("09-labs", ("AWEHACK",), "Reproducible lab environments, emulation and capture-the-flag material."),
    ("09-labs/apps", ("AWEHACK",), "Deliberately vulnerable applications for validation."),
    ("09-labs/infrastructure", ("AWEHACK",), "Terraform / Docker lab estates."),
    ("09-labs/emulations", ("AWEHACK", "AWEIR"), "Atomic-style attack emulations with expected telemetry."),
    ("09-labs/ctf", ("AWEHACK",), "CTF material, categories and tooling."),

    # -- 10 crosswalk -------------------------------------------------------
    ("10-crosswalk", (), "The integration layer: every mapping between the 20 upstream domains."),
    ("10-crosswalk/wordlist-payload", ("SECLISTS", "PAT"), "Wordlist entry to payload record resolution rules."),
    ("10-crosswalk/evasion-detection", ("GTFOBINS", "SURICATA", "WAZUH"), "Evasion chain hop to defensive detection anchors."),
    ("10-crosswalk/control-detection", ("OWASPCS", "SURICATA", "WAZUH"), "Secure development control to network and host rule."),
    ("10-crosswalk/attack-coverage", ("MSF", "AWETI", "GTFOBINS"), "Module, technique and payload coverage matrices."),

    # -- 11 automation ------------------------------------------------------
    ("11-automation", (), "Pipelines, generators and CI that keep the archive consistent."),
    ("11-automation/scripts", (), "Python utilities: index build, normalization, crosswalk rendering."),
    ("11-automation/ci", (), "Continuous integration workflows and quality gates."),
    ("11-automation/hooks", (), "Local git hooks and pre-commit hygiene."),

    # -- 12 schemas ---------------------------------------------------------
    ("12-schemas", (), "JSON Schema definitions that every machine readable artifact validates against."),

    # -- 13 training --------------------------------------------------------
    ("13-training", ("90DAYS",), "90-day paths, role tracks and assessments."),
    ("13-training/90-days", ("90DAYS",), "Day-by-day curriculum in three 30-day phases."),
    ("13-training/tracks", ("90DAYS", "AWEHACK"), "Red team / blue team / SecOps role tracks."),
    ("13-training/assessments", ("90DAYS",), "Quizzes, practical assignments and sign-off criteria."),

    # -- 14 docs ------------------------------------------------------------
    ("14-docs", (), "Architecture, standards, FAQ and glossary."),
    ("14-docs/architecture", (), "System context, containers and component diagrams."),
    ("14-docs/standards", (), "Contribution and data format standards."),
    ("14-docs/decisions", (), "Architecture decision records (ADR)."),
]


def _index() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {k: [] for k in SOURCES}
    for path, keys, _ in TREE:
        for k in keys:
            out[k].append(path)
    return out


FEEDS: dict[str, list[str]] = _index()

TOP_LEVEL: list[str] = [p for p, _, _ in TREE if "/" not in p]

DIR_COUNT = len(TREE)