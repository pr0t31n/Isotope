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
