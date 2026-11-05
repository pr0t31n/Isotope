<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Isotope — Universal File Analysis Tool

Part of the pr0t31n penetration testing toolkit. Isotope performs comprehensive
file analysis across multiple dimensions: identification, entropy/encryption
detection, string extraction, code analysis, metadata extraction, binary/executable
analysis, embedded secrets scanning, cryptographic hashing with IOC lookup, and
recursive archive decomposition.


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/isotope)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Features

- **File Identification** — Extension, MIME type, magic bytes, content classification
- **Entropy Analysis** — Shannon entropy with block-level entropy map, encryption detection and method estimation
- **String Extraction** — ASCII and UTF-16 strings, URL/IP/email/path extraction
- **Code Analysis** — Language detection, line counts, import/framework identification
- **Metadata Extraction** — EXIF (images), PDF metadata, OLE properties, filesystem timestamps
- **Binary/Executable Analysis** — PE/ELF/Mach-O parsing, architecture detection, section enumeration, packer detection (UPX, Themida, ASPack, etc.)
- **Secrets Scanning** — API keys, tokens, private keys, connection strings, credentials (30+ patterns)
- **Hashing + IOC Lookup** — MD5, SHA1, SHA256, SHA512, ssdeep, TLSH; lookup against pr0t31n_threat_intel
- **Archive Extraction** — Recursive analysis of ZIP, TAR, GZ, BZ2, XZ, 7Z, RAR, JAR, APK, DOCX/XLSX/PPTX
- **Certificate Analysis** — PEM/DER certificate and private key inspection, key strength assessment

## Requirements

- Python 3.10+
- libmagic (optional, enhances MIME detection)
- See `requirements.txt` for Python packages

## Installation

```bash
cd /opt/pr0t31n/Isotope
python3 install.py
```

## Usage

### Standalone

```bash
# Analyse a single file
python3 isotope.py suspicious.exe

# Analyse multiple files
python3 isotope.py file1.pdf file2.zip file3.bin

# Custom output directory
python3 isotope.py -o /path/to/output malware.bin

# Limit archive recursion depth
python3 isotope.py --max-depth 3 nested_archive.zip

# Select specific modules
python3 isotope.py --modules identification,entropy,hashing sample.dat
```

### Crucible-Managed

When run via Crucible, Isotope reads a JSON settings file:

```bash
python3 isotope.py --settings /path/to/settings.json
```

## Analysis Modules

| Module | Flag | Description |
|--------|------|-------------|
| identification | Always on | Extension, MIME, magic bytes, classification |
| entropy | `--modules entropy` | Shannon entropy, encryption detection |
| strings | `--modules strings` | ASCII/UTF-16 string extraction |
| code | `--modules code` | Language detection, LOC, imports |
| metadata | `--modules metadata` | EXIF, PDF, OLE, timestamps |
| binary | `--modules binary` | PE/ELF/Mach-O, packer detection |
| secrets | `--modules secrets` | Credential/token/key scanning |
| hashing | `--modules hashing` | Hash computation + IOC lookup |
| archive | `--modules archive` | Recursive archive extraction |

## Output Files

| File | Content |
|------|---------|
| `findings.json` | Security findings (universal schema v1.1) |
| `findings.csv` | CSV mirror of findings |
| `summary.json` | Run statistics and file summaries |
| `scan.log` | Human-readable event log |
| `scan.log.json` | Machine-readable JSON log |
| `errors.log` | Error entries only |
| `meta.json` | Run metadata (when pr0t31n_schema available) |
| `analysis/<file>/` | Per-file analysis results (properties, entropy, strings, etc.) |

## Integration

- **Crucible** — Wizard card in Step 2, scope section with module checkboxes, 9 intelligence tabs
- **pr0t31n_schema** — Universal output structure (Section 13 compliant)
- **pr0t31n_threat_intel** — IOC hash lookup for known malicious files
