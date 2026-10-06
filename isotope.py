#!/usr/bin/env python3
"""Isotope — Universal File Analysis Tool.

Performs comprehensive file analysis: identification, entropy/encryption
detection, string extraction, code analysis, metadata extraction,
binary/executable analysis, secrets scanning, hashing with IOC lookup,
and recursive archive decomposition.
"""

import argparse
import hashlib
import json
import math
import mimetypes
import os
import re
import struct
import sys
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

_ISOTOPE_MANAGED = os.environ.get("ISOTOPE_MANAGED") == "1"
_CP_LOG    = "__CRUCIBLE_LOG__:"
_CP_ERR    = "__CRUCIBLE_ERR__:"
_CP_STATUS = "__CRUCIBLE_STATUS__:"

# ── Shared module imports (graceful fallback) ─────────────────
try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_schema as _us
except ImportError:
    _us = None

try:
    import pr0t31n_threat_intel as _ti
except ImportError:
    _ti = None

# ── Console (managed/standalone) ─────────────────────────────
class IsotopeConsole:
    def __init__(self):
        self._managed = _ISOTOPE_MANAGED

    def log(self, msg, level="INFO"):
        entry = {"ts": _now_iso(), "level": level, "message": msg}
        if self._managed:
            sys.stdout.write(_CP_LOG + json.dumps(entry) + "\n")
            sys.stdout.flush()
        else:
            print(f"[{entry['ts']}] {level}: {msg}")

    def error(self, msg, detail=""):
        entry = {"ts": _now_iso(), "level": "ERROR", "message": msg, "detail": detail}
        if self._managed:
            sys.stderr.write(_CP_ERR + json.dumps(entry) + "\n")
            sys.stderr.flush()
        else:
            print(f"[{entry['ts']}] ERROR: {msg}" + (f" — {detail}" if detail else ""), file=sys.stderr)

    def status(self, phase, label="", status="running", step="", pct=None):
        entry = {"ts": _now_iso(), "phase": phase, "label": label or phase,
                 "status": status, "step": step}
        if pct is not None:
            entry["pct"] = pct
        if self._managed:
            sys.stdout.write(_CP_STATUS + json.dumps(entry) + "\n")
            sys.stdout.flush()

_console = IsotopeConsole()

def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ═══════════════════════════════════════════════════════════════
# MAGIC BYTES DATABASE
# ═══════════════════════════════════════════════════════════════
MAGIC_SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n',       'image/png',       'PNG image'),
    (b'\xff\xd8\xff',             'image/jpeg',      'JPEG image'),
    (b'GIF87a',                   'image/gif',       'GIF87a image'),
    (b'GIF89a',                   'image/gif',       'GIF89a image'),
    (b'BM',                       'image/bmp',       'BMP image'),
    (b'RIFF',                     None,              'RIFF container'),
    (b'%PDF',                     'application/pdf', 'PDF document'),
    (b'PK\x03\x04',              'application/zip', 'ZIP archive'),
    (b'PK\x05\x06',              'application/zip', 'ZIP archive (empty)'),
    (b'\x1f\x8b',                 'application/gzip','Gzip compressed'),
    (b'BZh',                      'application/x-bzip2', 'Bzip2 compressed'),
    (b'\xfd7zXZ\x00',            'application/x-xz', 'XZ compressed'),
    (b'7z\xbc\xaf\x27\x1c',     'application/x-7z-compressed', '7-Zip archive'),
    (b'Rar!\x1a\x07',            'application/x-rar-compressed', 'RAR archive'),
    (b'\x7fELF',                  'application/x-elf', 'ELF executable'),
    (b'MZ',                       'application/x-dosexec', 'PE/DOS executable'),
    (b'\xfe\xed\xfa\xce',        'application/x-mach-binary', 'Mach-O 32-bit'),
    (b'\xfe\xed\xfa\xcf',        'application/x-mach-binary', 'Mach-O 64-bit'),
    (b'\xce\xfa\xed\xfe',        'application/x-mach-binary', 'Mach-O 32-bit (LE)'),
    (b'\xcf\xfa\xed\xfe',        'application/x-mach-binary', 'Mach-O 64-bit (LE)'),
    (b'\xca\xfe\xba\xbe',        'application/x-mach-binary', 'Mach-O universal'),
    (b'\xd0\xcf\x11\xe0',        'application/x-ole-storage', 'OLE2/MS Compound Document'),
    (b'SQLite format 3',         'application/x-sqlite3', 'SQLite 3 database'),
    (b'LZIP',                     'application/x-lzip', 'LZIP compressed'),
    (b'\x04\x22\x4d\x18',       'application/x-lz4', 'LZ4 compressed'),
    (b'\x28\xb5\x2f\xfd',       'application/zstd', 'Zstandard compressed'),
    (b'-----BEGIN ',              'application/x-pem-file', 'PEM encoded'),
    (b'\x30\x82',                 'application/x-x509-ca-cert', 'DER/ASN.1 encoded'),
    (b'REDIS',                    'application/x-redis-rdb', 'Redis RDB dump'),
]

ARCHIVE_EXTENSIONS = {
    '.zip', '.tar', '.gz', '.tgz', '.tar.gz', '.bz2', '.tbz2', '.tar.bz2',
    '.xz', '.tar.xz', '.7z', '.rar', '.jar', '.war', '.ear', '.apk', '.ipa',
    '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp',
}

CODE_EXTENSIONS = {
    '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.jsx': 'React JSX',
    '.tsx': 'React TSX', '.java': 'Java', '.c': 'C', '.cpp': 'C++', '.h': 'C/C++ Header',
    '.hpp': 'C++ Header', '.cs': 'C#', '.go': 'Go', '.rs': 'Rust', '.rb': 'Ruby',
    '.php': 'PHP', '.swift': 'Swift', '.kt': 'Kotlin', '.scala': 'Scala',
    '.r': 'R', '.pl': 'Perl', '.sh': 'Shell', '.bash': 'Bash', '.zsh': 'Zsh',
    '.ps1': 'PowerShell', '.bat': 'Batch', '.cmd': 'Batch', '.lua': 'Lua',
    '.sql': 'SQL', '.html': 'HTML', '.htm': 'HTML', '.css': 'CSS', '.scss': 'SCSS',
    '.less': 'LESS', '.xml': 'XML', '.json': 'JSON', '.yaml': 'YAML', '.yml': 'YAML',
    '.toml': 'TOML', '.ini': 'INI', '.cfg': 'Config', '.conf': 'Config',
    '.md': 'Markdown', '.rst': 'reStructuredText', '.tex': 'LaTeX',
    '.vue': 'Vue', '.svelte': 'Svelte', '.dart': 'Dart', '.ex': 'Elixir',
    '.exs': 'Elixir', '.erl': 'Erlang', '.hs': 'Haskell', '.ml': 'OCaml',
    '.fs': 'F#', '.clj': 'Clojure', '.lisp': 'Lisp', '.el': 'Emacs Lisp',
    '.m': 'Objective-C', '.mm': 'Objective-C++', '.asm': 'Assembly',
    '.s': 'Assembly', '.v': 'Verilog', '.vhd': 'VHDL',
    '.tf': 'Terraform', '.hcl': 'HCL', '.proto': 'Protocol Buffers',
    '.graphql': 'GraphQL', '.gql': 'GraphQL', '.sol': 'Solidity',
    '.zig': 'Zig', '.nim': 'Nim', '.cr': 'Crystal', '.jl': 'Julia',
    '.gd': 'GDScript', '.gdshader': 'Godot Shader',
}

# ── Secret patterns ──────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS Access Key",        r'(?:^|[^A-Za-z0-9])(?:AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)', "CRITICAL"),
    ("AWS Secret Key",        r'(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "CRITICAL"),
    ("Generic API Key",       r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "HIGH"),
    ("Generic Secret",        r'(?:secret|token|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})', "HIGH"),
    ("Private Key Header",    r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "CRITICAL"),
    ("GitHub Token",          r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "CRITICAL"),
    ("Slack Token",           r'xox[bpors]-[0-9]{10,}-[A-Za-z0-9]{10,}', "CRITICAL"),
    ("Google API Key",        r'AIza[0-9A-Za-z_-]{35}', "HIGH"),
    ("JWT Token",             r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+', "MEDIUM"),
    ("Connection String",     r'(?:mysql|postgres|mongodb|redis|mssql)://[^\s"\'<>]{10,}', "HIGH"),
    ("Bearer Token",          r'[Bb]earer\s+[A-Za-z0-9_\-.~+/]+=*', "MEDIUM"),
    ("Basic Auth Header",     r'[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}', "HIGH"),
    ("Azure Connection",      r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+', "CRITICAL"),
    ("Stripe Key",            r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}', "CRITICAL"),
    ("SendGrid Key",          r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', "CRITICAL"),
    ("Twilio Key",            r'SK[0-9a-fA-F]{32}', "HIGH"),
    ("Hex-encoded key/hash",  r'(?:key|secret|hash|token)\s*[=:]\s*["\']?([0-9a-fA-F]{32,})', "MEDIUM"),
]

# ── Packer signatures (PE) ──────────────────────────────────
PACKER_SIGNATURES = {
    b'UPX0': 'UPX', b'UPX1': 'UPX', b'UPX2': 'UPX', b'UPX!': 'UPX',
    b'.themida': 'Themida', b'Themida': 'Themida',
    b'.aspack': 'ASPack', b'.adata': 'ASPack',
    b'PECompact2': 'PECompact',
    b'.petite': 'Petite',
    b'.nsp0': 'NsPack', b'.nsp1': 'NsPack',
    b'MEW': 'MEW',
    b'.MPRESS1': 'MPRESS', b'.MPRESS2': 'MPRESS',
}


# ═══════════════════════════════════════════════════════════════
# OUTPUT MANAGER
# ═══════════════════════════════════════════════════════════════
class IsotopeOutput:
    def __init__(self, output_dir):
        self.root = Path(output_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.analysis_dir = self.root / "analysis"
        self.analysis_dir.mkdir(exist_ok=True)
        self.findings = []
        self.log_lines = []
        self.errors = []
        self._start = _now_iso()

    def log(self, msg):
        ts = _now_iso()
        self.log_lines.append(f"[{ts}] {msg}")
        _console.log(msg)

    def log_error(self, msg):
        ts = _now_iso()
        self.errors.append(f"[{ts}] ERROR: {msg}")
        _console.error(msg)

    def add_finding(self, title, risk, description, **kwargs):
        f = {
            "id": str(uuid.uuid4()),
            "tool": "isotope",
            "title": title,
            "datetime": _now_iso(),
            "risk": risk.upper(),
            "description": description,
            "ip": kwargs.get("ip", ""),
            "port": kwargs.get("port", 0),
            "hostname": kwargs.get("hostname", ""),
            "command": kwargs.get("command", "isotope"),
            "output": kwargs.get("output", "")[:4096],
            "output_file": kwargs.get("output_file", ""),
            "sources": kwargs.get("sources", "isotope"),
            "service": kwargs.get("service", "file"),
            "affected": kwargs.get("affected", ""),
            "remediation": kwargs.get("remediation", ""),
            "cves": kwargs.get("cves", ""),
            "exploitdb": False,
            "metasploit": False,
            "exploit_details": [],
            "cwe": kwargs.get("cwe", []),
            "confidence": kwargs.get("confidence", "Firm"),
        }
        self.findings.append(f)
        _console.log(f"FINDING [{risk}] {title}", "FINDING")

    def add_action_item(self, entry):
        self._action_items = getattr(self, "_action_items", [])
        self._ai_seen = getattr(self, "_ai_seen", set())
        key = (entry["recommended_tool"].lower(),
               entry["target"].lower(),
               entry["title"].strip().lower())
        if key in self._ai_seen:
            return
        self._ai_seen.add(key)
        entry.setdefault("id", str(uuid.uuid4()))
        entry.setdefault("status", "pending")
        entry.setdefault("datetime", _now_iso())
        entry.setdefault("metadata", {})
        self._action_items.append(entry)
        if _ISOTOPE_MANAGED:
            sys.stdout.write(_CP_LOG + json.dumps(
                {"ts": _now_iso(), "level": "ACTION_ITEM",
                 "message": f"Action Item: {entry['title']}"}) + "\n")
            sys.stdout.flush()

    def write_action_items(self):
        items = getattr(self, "_action_items", [])
        if not items:
            return
        ai_path = self.root / "action_items.json"
        ai_path.write_text(json.dumps(items, indent=2, default=str), encoding="utf-8")
        _console.log(f"{len(items)} cross-tool action item(s) written", "SUCCESS")

    def file_dir(self, filename):
        safe = re.sub(r'[^\w.\-]', '_', filename)
        d = self.analysis_dir / safe
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_results(self, file_results):
        findings_path = self.root / "findings.json"
        findings_path.write_text(json.dumps(self.findings, indent=2, ensure_ascii=False), encoding="utf-8")

        csv_path = self.root / "findings.csv"
        if self.findings:
            import csv
            fields = list(self.findings[0].keys())
            with open(csv_path, "w", newline="", encoding="utf-8") as cf:
                w = csv.DictWriter(cf, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                for f in self.findings:
                    w.writerow(f)

        summary = {
            "tool": "isotope",
            "version": VERSION,
            "started": self._start,
            "completed": _now_iso(),
            "files_analysed": len(file_results),
            "total_findings": len(self.findings),
            "risk_counts": _risk_counts(self.findings),
            "files": [_file_summary(r) for r in file_results],
        }
        (self.root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

        log_path = self.root / "scan.log"
        log_path.write_text("\n".join(self.log_lines) + "\n", encoding="utf-8")

        log_json_path = self.root / "scan.log.json"
        log_entries = []
        for line in self.log_lines:
            m = re.match(r'\[(.+?)\] (.+)', line)
            if m:
                log_entries.append({"ts": m.group(1), "message": m.group(2)})
        log_json_path.write_text(json.dumps(log_entries, indent=2), encoding="utf-8")

        err_path = self.root / "errors.log"
        err_path.write_text("\n".join(self.errors) + "\n" if self.errors else "", encoding="utf-8")

        if _us:
            try:
                meta = _us.make_meta(tool="isotope", version=VERSION,
                                     client_short="unknown", client_name="unknown",
                                     engagement_name="Isotope analysis",
                                     target="file analysis")
                _us.atomic_write_json(self.root / "meta.json", meta)
            except Exception:
                pass


def _risk_counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = f.get("risk", "INFO").upper()
        counts[r] = counts.get(r, 0) + 1
    return counts

def _file_summary(result):
    return {
        "filename": result.get("filename", ""),
        "size": result.get("size", 0),
        "mime": result.get("mime", ""),
        "classification": result.get("classification", ""),
        "entropy": result.get("entropy", 0),
        "findings_count": result.get("findings_count", 0),
    }


# ═══════════════════════════════════════════════════════════════
# ANALYSIS MODULES
# ═══════════════════════════════════════════════════════════════

def analyse_file(filepath, out, depth=0, max_depth=5, modules=None):
    """Run the full analysis pipeline on a single file."""
    filepath = Path(filepath)
    if not filepath.exists():
        out.log_error(f"File not found: {filepath}")
        return None

    result = {
        "filename": filepath.name,
        "path": str(filepath),
        "size": filepath.stat().st_size,
        "depth": depth,
        "findings_count": 0,
    }

    if modules is None:
        modules = {"identification", "entropy", "strings", "code", "metadata",
                    "binary", "secrets", "hashing", "archive"}

    file_dir = out.file_dir(filepath.name if depth == 0 else f"depth{depth}_{filepath.name}")

    try:
        data = filepath.read_bytes()
    except Exception as e:
        out.log_error(f"Cannot read {filepath}: {e}")
        return result

    out.log(f"Analysing: {filepath.name} ({_fmt_size(len(data))})")
    _console.status("analysis", label=filepath.name, status="running", step="identification")

    # ── 1. Identification ────────────────────────────────────
    ident = _identify(filepath, data)
    result.update(ident)
    _write_json(file_dir / "properties.json", ident)

    # ── 2. Hashing + IOC lookup ──────────────────────────────
    if "hashing" in modules:
        _console.status("analysis", label=filepath.name, step="hashing")
        hashes = _compute_hashes(data)
        result["hashes"] = hashes
        ioc_hits = _check_ioc(hashes)
        hashes["ioc_hits"] = ioc_hits
        _write_json(file_dir / "hashes.json", hashes)

        if ioc_hits:
            for hit in ioc_hits:
                out.add_finding(
                    title=f"Known malicious file hash ({hit.get('classification', 'SUSPECTED')})",
                    risk="CRITICAL" if hit.get("classification") == "KNOWN_MALICIOUS" else "HIGH",
                    description=f"File {filepath.name} matches a known threat indicator.\n"
                                f"Hash: {hashes.get('sha256', '')}\n"
                                f"Sources: {', '.join(hit.get('sources', []))}",
                    affected=filepath.name,
                    remediation="Quarantine this file immediately. Investigate its origin and any systems it has touched.",
                    cwe=["CWE-506"],
                    output=json.dumps(hit, indent=2),
                )
                result["findings_count"] += 1

    # ── 3. Entropy / encryption detection ────────────────────
    if "entropy" in modules:
        _console.status("analysis", label=filepath.name, step="entropy")
        entropy_result = _analyse_entropy(data)
        result["entropy"] = entropy_result["overall_entropy"]
        result["encryption_assessment"] = entropy_result["assessment"]
        _write_json(file_dir / "entropy.json", entropy_result)

        if entropy_result["assessment"] in ("likely_encrypted", "possibly_encrypted"):
            out.add_finding(
                title=f"{'Encrypted' if entropy_result['assessment'] == 'likely_encrypted' else 'Possibly encrypted'} file detected",
                risk="MEDIUM" if entropy_result["assessment"] == "likely_encrypted" else "LOW",
                description=f"File {filepath.name} has {'high' if entropy_result['assessment'] == 'likely_encrypted' else 'elevated'} "
                            f"entropy ({entropy_result['overall_entropy']:.4f}), suggesting encryption.\n"
                            f"Estimated method: {entropy_result.get('estimated_method', 'unknown')}",
                affected=filepath.name,
                remediation="Determine whether encryption is expected for this file. If not, investigate the file's origin.",
                output=f"Entropy: {entropy_result['overall_entropy']:.6f}\n"
                       f"Assessment: {entropy_result['assessment']}\n"
                       f"Estimated method: {entropy_result.get('estimated_method', 'unknown')}",
            )
            result["findings_count"] += 1

    # ── 4. String extraction ─────────────────────────────────
    if "strings" in modules:
        _console.status("analysis", label=filepath.name, step="strings")
        strings_result = _extract_strings(data)
        _write_json(file_dir / "strings.json", strings_result)
        result["string_count"] = strings_result["total"]

    # ── 5. Code analysis ─────────────────────────────────────
    if "code" in modules and ident.get("classification") == "code":
        _console.status("analysis", label=filepath.name, step="code")
        code_result = _analyse_code(filepath, data)
        _write_json(file_dir / "code.json", code_result)
        result["code"] = code_result

    # ── 6. Metadata extraction ───────────────────────────────
    if "metadata" in modules:
        _console.status("analysis", label=filepath.name, step="metadata")
        meta_result = _extract_metadata(filepath, data, ident)
        if meta_result:
            _write_json(file_dir / "metadata.json", meta_result)
            result["metadata"] = meta_result

            if meta_result.get("gps_coordinates"):
                out.add_finding(
                    title="GPS coordinates embedded in file metadata",
                    risk="LOW",
                    description=f"File {filepath.name} contains GPS coordinates in its EXIF metadata.\n"
                                f"Coordinates: {meta_result['gps_coordinates']}",
                    affected=filepath.name,
                    remediation="Strip EXIF metadata before sharing files externally. "
                                "Use tools like exiftool -all= to remove metadata.",
                    cwe=["CWE-200"],
                )
                result["findings_count"] += 1

    # ── 7. Binary / executable analysis ──────────────────────
    if "binary" in modules and ident.get("classification") == "executable":
        _console.status("analysis", label=filepath.name, step="binary")
        binary_result = _analyse_binary(data, ident)
        _write_json(file_dir / "binary.json", binary_result)
        result["binary"] = binary_result

        if binary_result.get("packers"):
            out.add_finding(
                title=f"Packed/obfuscated executable detected ({', '.join(binary_result['packers'])})",
                risk="MEDIUM",
                description=f"File {filepath.name} appears to be packed with: {', '.join(binary_result['packers'])}. "
                            f"Packed executables are commonly used by malware to evade detection.",
                affected=filepath.name,
                remediation="Unpack the executable and analyse the underlying binary. "
                            "Determine if packing is legitimate (software protection) or suspicious.",
                cwe=["CWE-506"],
            )
            result["findings_count"] += 1

    # ── 8. Secrets scanning ──────────────────────────────────
    if "secrets" in modules:
        _console.status("analysis", label=filepath.name, step="secrets")
        secrets_result = _scan_secrets(data, filepath.name)
        if secrets_result:
            _write_json(file_dir / "secrets.json", secrets_result)
            result["secrets_count"] = len(secrets_result)

            for secret in secrets_result:
                out.add_finding(
                    title="Information Disclosure: Secret in File",
                    risk=secret["risk"],
                    description=f"A {secret['type']} was detected in {filepath.name} at line {secret.get('line', '?')}.\n"
                                f"Match: {secret['match'][:80]}{'...' if len(secret['match']) > 80 else ''}",
                    affected=filepath.name,
                    remediation="Remove the secret from the file immediately. "
                                "Rotate the credential. Check git history for exposure.",
                    cwe=["CWE-798", "CWE-312"],
                    output=f"Type: {secret['type']}\nLine: {secret.get('line', '?')}\n"
                           f"Context: {secret.get('context', '')}",
                )
                result["findings_count"] += 1

    # ── 9. Archive extraction + recursive analysis ───────────
    if "archive" in modules and ident.get("is_archive") and depth < max_depth:
        _console.status("analysis", label=filepath.name, step="archive")
        contents = _extract_archive(filepath, data, ident, out, file_dir, depth, max_depth, modules)
        if contents:
            _write_json(file_dir / "contents.json", contents)
            result["archive_contents"] = contents

    # ── 10. Certificate analysis ─────────────────────────────
    if ident.get("classification") == "certificate":
        cert_result = _analyse_certificate(data, filepath.name)
        if cert_result:
            _write_json(file_dir / "certificate.json", cert_result)
            result["certificate"] = cert_result

            if cert_result.get("key_bits") and cert_result["key_bits"] < 2048:
                out.add_finding(
                    title=f"Weak cryptographic key ({cert_result['key_bits']} bits)",
                    risk="HIGH",
                    description=f"Certificate/key in {filepath.name} uses only {cert_result['key_bits']}-bit key. "
                                f"Keys under 2048 bits are considered weak.",
                    affected=filepath.name,
                    remediation="Regenerate the certificate with at least 2048-bit RSA or 256-bit EC key.",
                    cwe=["CWE-326"],
                )
                result["findings_count"] += 1

    result["classification"] = ident.get("classification", "unknown")
    result["mime"] = ident.get("mime", "")

    _console.status("analysis", label=filepath.name, status="complete")
    return result


# ═══════════════════════════════════════════════════════════════
# MODULE IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════

def _identify(filepath, data):
    ext = filepath.suffix.lower()
    mime_guess = mimetypes.guess_type(str(filepath))[0] or ""

    magic_mime = ""
    magic_desc = ""
    for sig, m, desc in MAGIC_SIGNATURES:
        if data[:len(sig)] == sig:
            magic_mime = m or ""
            magic_desc = desc
            break

    try:
        import magic as _magic
        m = _magic.Magic(mime=True)
        magic_mime = m.from_buffer(data[:8192]) or magic_mime
        m2 = _magic.Magic()
        magic_desc = m2.from_buffer(data[:8192]) or magic_desc
    except ImportError:
        pass

    mime = magic_mime or mime_guess or "application/octet-stream"

    is_text = _is_text(data[:8192])
    is_code = ext in CODE_EXTENSIONS
    is_archive = (ext in ARCHIVE_EXTENSIONS or
                  mime in ("application/zip", "application/gzip", "application/x-tar",
                           "application/x-bzip2", "application/x-xz",
                           "application/x-7z-compressed", "application/x-rar-compressed"))
    is_exec = mime in ("application/x-elf", "application/x-dosexec",
                        "application/x-mach-binary")
    is_cert = (ext in ('.pem', '.crt', '.cer', '.der', '.pfx', '.p12', '.key') or
               b'-----BEGIN ' in data[:100])

    if is_exec:
        classification = "executable"
    elif is_cert:
        classification = "certificate"
    elif is_archive:
        classification = "archive"
    elif is_code:
        classification = "code"
    elif is_text:
        classification = "plaintext"
    elif mime.startswith("image/"):
        classification = "image"
    elif mime.startswith("audio/") or mime.startswith("video/"):
        classification = "media"
    else:
        classification = "binary"

    return {
        "filename": filepath.name,
        "extension": ext,
        "size": len(data),
        "mime": mime,
        "mime_guessed": mime_guess,
        "magic_description": magic_desc,
        "is_text": is_text,
        "is_code": is_code,
        "is_archive": is_archive,
        "is_executable": is_exec,
        "is_certificate": is_cert,
        "classification": classification,
        "code_language": CODE_EXTENSIONS.get(ext, "") if is_code else "",
    }


def _is_text(data):
    if not data:
        return True
    text_chars = (set(range(32, 127)) | {9, 10, 13})
    non_text = sum(1 for b in data if b not in text_chars)
    return (non_text / len(data)) < 0.10


def _compute_hashes(data):
    result = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }
    try:
        import ssdeep
        result["ssdeep"] = ssdeep.hash(data)
    except ImportError:
        result["ssdeep"] = None
    try:
        import tlsh
        result["tlsh"] = tlsh.hash(data)
    except ImportError:
        result["tlsh"] = None
    return result


def _check_ioc(hashes):
    if not _ti:
        return []
    hits = []
    db = _ti.ThreatIntelDB()
    for algo in ("sha256", "md5", "sha1"):
        h = hashes.get(algo, "")
        if h:
            hit = db.lookup_url(h)
            if hit:
                hits.append({
                    "hash_type": algo,
                    "hash": h,
                    "classification": hit.classification,
                    "sources": list(hit.sources),
                    "confidence": hit.confidence,
                })
    return hits


def _analyse_entropy(data):
    if not data:
        return {"overall_entropy": 0, "assessment": "empty", "entropy_map": []}

    overall = _shannon_entropy(data)

    window_size = max(256, len(data) // 256)
    entropy_map = []
    for i in range(0, len(data), window_size):
        chunk = data[i:i + window_size]
        if len(chunk) < 16:
            continue
        e = _shannon_entropy(chunk)
        entropy_map.append({
            "offset": i,
            "length": len(chunk),
            "entropy": round(e, 6),
        })

    if overall > 7.99:
        assessment = "likely_encrypted"
        method = _guess_encryption_method(data)
    elif overall > 7.5:
        assessment = "possibly_encrypted"
        method = _guess_encryption_method(data)
    elif overall > 6.0:
        assessment = "compressed_or_binary"
        method = ""
    else:
        assessment = "not_encrypted"
        method = ""

    return {
        "overall_entropy": round(overall, 6),
        "assessment": assessment,
        "estimated_method": method,
        "entropy_map": entropy_map,
        "window_size": window_size,
        "file_size": len(data),
    }


def _shannon_entropy(data):
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _guess_encryption_method(data):
    if data[:8] == b'Salted__':
        return "OpenSSL (AES-CBC likely)"
    if data[:4] in (b'\x00\x00\x00\x01', b'\x00\x00\x00\x02'):
        return "Possibly AES-GCM or authenticated encryption"
    if len(data) % 16 == 0:
        return "Block cipher (128-bit blocks — likely AES)"
    if len(data) % 8 == 0:
        return "Block cipher (64-bit blocks — possibly 3DES/Blowfish)"
    return "Stream cipher or custom encryption"


def _extract_strings(data, min_length=6):
    ascii_pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    utf16_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_length)

    raw_strings = [s.decode("ascii", errors="replace") for s in ascii_pattern.findall(data)]
    utf16_strings = [s.decode("utf-16-le", errors="replace") for s in utf16_pattern.findall(data)]
    all_strings = raw_strings + utf16_strings

    urls = [s for s in all_strings if re.match(r'https?://', s)]
    ips = [s for s in all_strings if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)]
    emails = [s for s in all_strings if re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', s)]
    paths = [s for s in all_strings if re.match(r'(?:[A-Z]:\\|/(?:usr|etc|var|home|opt|tmp)/)', s)]

    return {
        "total": len(all_strings),
        "ascii_count": len(raw_strings),
        "utf16_count": len(utf16_strings),
        "urls": urls[:200],
        "ip_addresses": ips[:200],
        "email_addresses": emails[:200],
        "file_paths": paths[:200],
        "interesting": all_strings[:500],
    }


def _analyse_code(filepath, data):
    ext = filepath.suffix.lower()
    language = CODE_EXTENSIONS.get(ext, "Unknown")

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = data.decode("latin-1", errors="replace")

    lines = text.split("\n")
    loc = len(lines)
    blank = sum(1 for l in lines if not l.strip())
    comment = sum(1 for l in lines if l.strip().startswith(("#", "//", "/*", "*", "<!--")))

    imports = []
    frameworks = []
    if language == "Python":
        imports = re.findall(r'^\s*(?:import|from)\s+(\S+)', text, re.MULTILINE)[:50]
        if "flask" in text.lower(): frameworks.append("Flask")
        if "django" in text.lower(): frameworks.append("Django")
        if "fastapi" in text.lower(): frameworks.append("FastAPI")
    elif language in ("JavaScript", "TypeScript"):
        imports = re.findall(r"(?:import|require)\s*\(?['\"]([^'\"]+)", text)[:50]
        if "react" in text.lower(): frameworks.append("React")
        if "express" in text.lower(): frameworks.append("Express")
        if "vue" in text.lower(): frameworks.append("Vue")

    return {
        "language": language,
        "lines_of_code": loc,
        "blank_lines": blank,
        "comment_lines": comment,
        "code_lines": loc - blank - comment,
        "imports": imports,
        "frameworks": frameworks,
        "encoding": "utf-8",
    }


def _extract_metadata(filepath, data, ident):
    meta = {}
    mime = ident.get("mime", "")

    if mime.startswith("image/"):
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            img = Image.open(filepath)
            meta["dimensions"] = f"{img.width}x{img.height}"
            meta["mode"] = img.mode
            exif = img.getexif()
            if exif:
                meta["exif"] = {}
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    try:
                        meta["exif"][str(tag)] = str(value)
                    except Exception:
                        pass
                gps = exif.get(0x8825)
                if gps:
                    meta["gps_coordinates"] = str(gps)
        except ImportError:
            meta["note"] = "Pillow not installed; EXIF extraction skipped"
        except Exception as e:
            meta["error"] = str(e)

    elif mime == "application/pdf":
        try:
            import PyPDF2
            reader = PyPDF2.PdfReader(filepath)
            info = reader.metadata
            meta["pages"] = len(reader.pages)
            if info:
                meta["pdf_metadata"] = {k: str(v) for k, v in info.items() if v}
        except ImportError:
            meta["note"] = "PyPDF2 not installed; PDF metadata extraction skipped"
        except Exception as e:
            meta["error"] = str(e)

    elif mime in ("application/x-ole-storage",):
        try:
            import olefile
            ole = olefile.OleFileIO(data)
            meta["ole_metadata"] = ole.get_metadata().__dict__
            ole.close()
        except ImportError:
            pass
        except Exception:
            pass

    timestamps = {}
    try:
        st = filepath.stat()
        timestamps["created"] = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat()
        timestamps["modified"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        timestamps["accessed"] = datetime.fromtimestamp(st.st_atime, tz=timezone.utc).isoformat()
    except Exception:
        pass
    meta["timestamps"] = timestamps

    return meta if len(meta) > 1 else None


def _analyse_binary(data, ident):
    result = {
        "format": "unknown",
        "architecture": "",
        "bits": 0,
        "endianness": "",
        "sections": [],
        "imports": [],
        "packers": [],
    }

    if data[:4] == b'\x7fELF':
        result["format"] = "ELF"
        if len(data) > 18:
            bits = {1: 32, 2: 64}.get(data[4], 0)
            endian = {1: "little", 2: "big"}.get(data[5], "unknown")
            arch_map = {0x03: "x86", 0x3E: "x86_64", 0x28: "ARM", 0xB7: "AArch64",
                        0x08: "MIPS", 0x16: "S390", 0x2A: "SuperH"}
            arch_byte = struct.unpack_from("<H" if endian == "little" else ">H", data, 18)[0]
            result["architecture"] = arch_map.get(arch_byte, f"0x{arch_byte:x}")
            result["bits"] = bits
            result["endianness"] = endian

    elif data[:2] == b'MZ':
        result["format"] = "PE"
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
                arch_map = {0x14c: "x86", 0x8664: "x86_64", 0x1c0: "ARM",
                            0xAA64: "AArch64", 0x200: "IA64"}
                result["architecture"] = arch_map.get(machine, f"0x{machine:x}")
                result["bits"] = 64 if machine in (0x8664, 0xAA64, 0x200) else 32
                result["endianness"] = "little"

                num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
                opt_hdr_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
                section_offset = pe_offset + 24 + opt_hdr_size
                for i in range(min(num_sections, 50)):
                    off = section_offset + i * 40
                    if off + 40 > len(data):
                        break
                    name = data[off:off+8].rstrip(b'\x00').decode("ascii", errors="replace")
                    vsize = struct.unpack_from("<I", data, off + 8)[0]
                    rsize = struct.unpack_from("<I", data, off + 16)[0]
                    result["sections"].append({
                        "name": name, "virtual_size": vsize, "raw_size": rsize
                    })
        except Exception:
            pass

    elif data[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                       b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                       b'\xca\xfe\xba\xbe'):
        result["format"] = "Mach-O"
        if data[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf'):
            result["bits"] = 64
        elif data[:4] == b'\xca\xfe\xba\xbe':
            result["format"] = "Mach-O Universal"
        else:
            result["bits"] = 32

    for sig, name in PACKER_SIGNATURES.items():
        if sig in data:
            if name not in result["packers"]:
                result["packers"].append(name)

    return result


def _scan_secrets(data, filename):
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []

    lines = text.split("\n")
    secrets = []
    seen = set()

    for pattern_name, pattern, risk in SECRET_PATTERNS:
        for i, line in enumerate(lines, 1):
            for m in re.finditer(pattern, line):
                match_text = m.group(0).strip()
                key = (pattern_name, match_text[:40])
                if key in seen:
                    continue
                seen.add(key)

                context_start = max(0, i - 2)
                context_end = min(len(lines), i + 1)
                context = "\n".join(lines[context_start:context_end])

                secrets.append({
                    "type": pattern_name,
                    "risk": risk,
                    "match": match_text[:200],
                    "line": i,
                    "context": context[:500],
                    "file": filename,
                })

    return secrets


def _extract_archive(filepath, data, ident, out, file_dir, depth, max_depth, modules):
    contents = {"type": "", "entries": [], "recursive_results": []}
    mime = ident.get("mime", "")

    with tempfile.TemporaryDirectory(prefix="isotope_") as tmp:
        extracted_files = []

        if mime == "application/zip" or filepath.suffix.lower() in ('.zip', '.jar', '.apk', '.docx', '.xlsx', '.pptx'):
            import zipfile
            try:
                with zipfile.ZipFile(filepath) as zf:
                    contents["type"] = "zip"
                    for info in zf.infolist():
                        entry = {
                            "name": info.filename,
                            "size": info.file_size,
                            "compressed_size": info.compress_size,
                            "is_dir": info.is_dir(),
                        }
                        contents["entries"].append(entry)
                        if not info.is_dir() and info.file_size > 0:
                            safe_name = Path(info.filename).name
                            if safe_name and not info.filename.startswith(('/', '..')):
                                try:
                                    extracted = Path(tmp) / safe_name
                                    extracted.write_bytes(zf.read(info.filename))
                                    extracted_files.append(extracted)
                                except Exception:
                                    pass
            except Exception as e:
                contents["error"] = str(e)

        elif mime in ("application/gzip",) or filepath.suffix.lower() in ('.gz', '.tgz'):
            import gzip
            try:
                with gzip.open(filepath, 'rb') as gf:
                    decompressed = gf.read(50 * 1024 * 1024)
                inner_name = filepath.stem if filepath.suffix.lower() == '.gz' else filepath.name
                extracted = Path(tmp) / inner_name
                extracted.write_bytes(decompressed)
                extracted_files.append(extracted)
                contents["type"] = "gzip"
                contents["entries"].append({"name": inner_name, "size": len(decompressed)})
            except Exception as e:
                contents["error"] = str(e)

        elif filepath.suffix.lower() in ('.tar', '.tgz', '.tar.gz', '.tar.bz2', '.tar.xz'):
            import tarfile
            try:
                with tarfile.open(filepath) as tf:
                    contents["type"] = "tar"
                    for member in tf.getmembers():
                        entry = {
                            "name": member.name,
                            "size": member.size,
                            "is_dir": member.isdir(),
                            "mode": oct(member.mode) if member.mode else "",
                        }
                        contents["entries"].append(entry)
                        if member.isfile() and member.size > 0:
                            safe_name = Path(member.name).name
                            if safe_name and '..' not in member.name:
                                try:
                                    f = tf.extractfile(member)
                                    if f:
                                        extracted = Path(tmp) / safe_name
                                        extracted.write_bytes(f.read(50 * 1024 * 1024))
                                        extracted_files.append(extracted)
                                except Exception:
                                    pass
            except Exception as e:
                contents["error"] = str(e)

        elif mime == "application/x-bzip2":
            import bz2
            try:
                decompressed = bz2.decompress(data)
                inner_name = filepath.stem
                extracted = Path(tmp) / inner_name
                extracted.write_bytes(decompressed)
                extracted_files.append(extracted)
                contents["type"] = "bzip2"
                contents["entries"].append({"name": inner_name, "size": len(decompressed)})
            except Exception as e:
                contents["error"] = str(e)

        out.log(f"Archive {filepath.name}: {len(contents['entries'])} entries, "
                f"extracting {len(extracted_files)} files for deep analysis (depth {depth+1})")

        for ef in extracted_files[:100]:
            sub_result = analyse_file(ef, out, depth=depth + 1, max_depth=max_depth, modules=modules)
            if sub_result:
                contents["recursive_results"].append(sub_result)

    return contents


def _analyse_certificate(data, filename):
    result = {}
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    if "-----BEGIN CERTIFICATE-----" in text:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding
            cert_pem = text[text.index("-----BEGIN CERTIFICATE-----"):]
            cert_pem = cert_pem[:cert_pem.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")]
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            result["subject"] = str(cert.subject)
            result["issuer"] = str(cert.issuer)
            result["serial"] = str(cert.serial_number)
            result["not_before"] = cert.not_valid_before_utc.isoformat()
            result["not_after"] = cert.not_valid_after_utc.isoformat()
            result["key_type"] = cert.public_key().__class__.__name__
            result["key_bits"] = cert.public_key().key_size
            result["signature_algorithm"] = cert.signature_algorithm_oid._name
        except ImportError:
            result["note"] = "cryptography library not installed"
        except Exception as e:
            result["error"] = str(e)

    elif "-----BEGIN PRIVATE KEY-----" in text or "-----BEGIN RSA PRIVATE KEY-----" in text:
        result["type"] = "private_key"
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            key_start = re.search(r'-----BEGIN .*PRIVATE KEY-----', text)
            key_end = re.search(r'-----END .*PRIVATE KEY-----', text)
            if key_start and key_end:
                key_pem = text[key_start.start():key_end.end()]
                key = load_pem_private_key(key_pem.encode(), password=None)
                result["key_type"] = key.__class__.__name__
                result["key_bits"] = key.key_size
        except ImportError:
            result["note"] = "cryptography library not installed"
        except Exception as e:
            result["error"] = str(e)

    return result if result else None


# ═══════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════

def _write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

def _fmt_size(n):
    if n < 1024: return f"{n} B"
    if n < 1048576: return f"{n/1024:.1f} KB"
    return f"{n/1048576:.1f} MB"


# ═══════════════════════════════════════════════════════════════
# CLI + ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def _parse_args():
    p = argparse.ArgumentParser(
        prog="isotope",
        description="Isotope — Universal File Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("files", nargs="*", help="Files to analyse")
    p.add_argument("--settings", metavar="FILE", help="JSON settings file (Crucible mode)")
    p.add_argument("--output", "-o", metavar="DIR", default="isotope_output",
                   help="Output directory")
    p.add_argument("--max-depth", type=int, default=5,
                   help="Maximum archive recursion depth (default: 5)")
    p.add_argument("--modules", metavar="LIST", default="all",
                   help="Comma-separated analysis modules (default: all)")
    p.add_argument("--version", action="version", version=f"Isotope v{VERSION}")
    return p.parse_args()


def run_analysis(cfg):
    scan = cfg.get("scan", {})
    files = scan.get("files", [])
    output_dir = scan.get("output", "isotope_output")
    max_depth = int(scan.get("max_depth", 5))
    modules_str = scan.get("modules", "all")

    if modules_str == "all":
        modules = {"identification", "entropy", "strings", "code", "metadata",
                    "binary", "secrets", "hashing", "archive"}
    else:
        modules = set(modules_str.split(","))
    modules.add("identification")

    out = IsotopeOutput(output_dir)
    out.log(f"Isotope v{VERSION} started — {len(files)} file(s) queued")

    results = []
    for i, filepath in enumerate(files):
        fname = Path(filepath).name if isinstance(filepath, str) else filepath.name
        _console.status("overall", label=f"file {i+1}/{len(files)}",
                       step=fname, pct=int(i / len(files) * 100))
        result = analyse_file(filepath, out, depth=0, max_depth=max_depth, modules=modules)
        if result:
            results.append(result)

    out.write_results(results)
    _generate_action_items(out, results)
    _console.status("overall", label="Overall Progress", status="complete", pct=100)

    total_findings = sum(r.get("findings_count", 0) for r in results)
    out.log(f"Analysis complete: {len(results)} files, {total_findings} findings")
    _console.log(f"Results written to {output_dir}/", "SUCCESS")

    return 0


def _generate_action_items(out, results):
    """Generate cross-tool action items from Isotope analysis results."""
    _CONN_STRING_PROTOS = {"mysql", "postgres", "mongodb", "redis", "mssql",
                           "postgresql", "mariadb", "sqlserver"}

    for r in results:
        fname = r.get("file", "")
        fdir = out.analysis_dir / re.sub(r'[^\w.\-]', '_', Path(fname).name)
        strings_json = fdir / "strings.json"
        secrets_json = fdir / "secrets.json"

        # Load extracted strings
        urls = []
        ips = []
        if strings_json.exists():
            try:
                sdata = json.loads(strings_json.read_text(encoding="utf-8"))
                urls = sdata.get("urls", [])
                ips = sdata.get("ip_addresses", [])
            except Exception:
                pass

        # URLs → Fracture (web app testing) — deduplicate by domain
        _url_domains = set()
        for url in urls[:50]:
            try:
                from urllib.parse import urlparse
                host = urlparse(url).hostname or ""
            except Exception:
                continue
            if not host or host in _url_domains:
                continue
            if host.startswith("127.") or host == "localhost":
                continue
            _url_domains.add(host)
            out.add_action_item({
                "type": "web_app", "recommended_tool": "Fracture",
                "target": url, "ip": "", "port": 0, "hostname": host,
                "title": f"Web target from file analysis: {host}",
                "description": (
                    f"Isotope extracted URL {url} from {fname}. "
                    f"Fracture can test this web target for vulnerabilities."),
                "source_finding": f"URL in {fname}",
                "priority": "MEDIUM", "scope": "ext",
            })

        # IPs → SS3 (network scan) — deduplicate, skip private by default
        _seen_ips = set()
        for ip in ips[:30]:
            ip = ip.strip().split(":")[0]
            if ip in _seen_ips or ip.startswith("127.") or ip == "0.0.0.0":
                continue
            _seen_ips.add(ip)
            out.add_action_item({
                "type": "network_scan", "recommended_tool": "Scattershot3",
                "target": ip, "ip": ip, "port": 0, "hostname": "",
                "title": f"Network scan: IP from file analysis",
                "description": (
                    f"Isotope extracted IP {ip} from {fname}. "
                    f"Scattershot3 can perform comprehensive port/service "
                    f"scanning and vulnerability assessment."),
                "source_finding": f"IP in {fname}",
                "priority": "MEDIUM", "scope": "ext",
            })

        # Load secrets
        if secrets_json.exists():
            try:
                secrets = json.loads(secrets_json.read_text(encoding="utf-8"))
            except Exception:
                secrets = []
        else:
            secrets = []

        for secret in secrets:
            stype = secret.get("type", "").lower()
            match = secret.get("match", "")

            # Connection strings → Auger (database testing)
            if "connection string" in stype:
                try:
                    proto = match.split("://")[0].lower()
                except Exception:
                    proto = "database"
                if proto in _CONN_STRING_PROTOS:
                    out.add_action_item({
                        "type": "database_audit", "recommended_tool": "Auger",
                        "target": match[:100], "ip": "", "port": 0, "hostname": "",
                        "title": f"Database connection string: {proto}",
                        "description": (
                            f"Isotope found a {proto} connection string in {fname}. "
                            f"Auger can test this database endpoint for authentication "
                            f"weaknesses, default credentials, and misconfigurations."),
                        "source_finding": f"{secret.get('type', '')} in {fname}",
                        "priority": "CRITICAL", "scope": "ext",
                    })

            # AWS/Azure/cloud credentials → Forge (cloud audit)
            if any(kw in stype for kw in ("aws", "azure", "stripe", "google")):
                out.add_action_item({
                    "type": "cloud_audit", "recommended_tool": "Forge",
                    "target": fname, "ip": "", "port": 0, "hostname": "",
                    "title": f"Cloud credential: {secret.get('type', '')}",
                    "description": (
                        f"Isotope found {secret.get('type', 'a cloud credential')} "
                        f"in {fname}. Forge can use these credentials to audit "
                        f"cloud provider configuration, IAM policies, and "
                        f"identify exposed resources."),
                    "source_finding": f"{secret.get('type', '')} in {fname}",
                    "priority": "CRITICAL", "scope": "ext",
                })

            # API keys/tokens → Siphon (API testing)
            if any(kw in stype for kw in ("api key", "bearer", "jwt", "github token",
                                           "slack token", "generic secret")):
                out.add_action_item({
                    "type": "api", "recommended_tool": "Siphon",
                    "target": fname, "ip": "", "port": 0, "hostname": "",
                    "title": f"API credential for testing: {secret.get('type', '')}",
                    "description": (
                        f"Isotope found {secret.get('type', 'an API credential')} "
                        f"in {fname}. Siphon can use discovered API keys/tokens "
                        f"to test API endpoints for authorization flaws."),
                    "source_finding": f"{secret.get('type', '')} in {fname}",
                    "priority": "HIGH", "scope": "ext",
                })

    out.write_action_items()


def main():
    args = _parse_args()

    if args.settings:
        cfg_path = Path(args.settings)
        if not cfg_path.exists():
            _console.error(f"Settings file not found: {args.settings}")
            return 1
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    else:
        if not args.files:
            _console.error("No files specified. Use: isotope file1 [file2 ...]")
            return 1
        modules = args.modules
        cfg = {
            "scan": {
                "files": args.files,
                "output": args.output,
                "max_depth": args.max_depth,
                "modules": modules,
            }
        }

    return run_analysis(cfg)


if __name__ == "__main__":
    sys.exit(main())
