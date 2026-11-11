#!/usr/bin/env python3
"""Isotope installer — multi-platform."""
import subprocess
import sys
import os
import shutil
from pathlib import Path

TOOL_NAME = "Isotope"
MIN_PYTHON = (3, 10)

def _run(cmd, check=True):
    print(f"  → {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)

def _has(binary):
    return shutil.which(binary) is not None



    return shutil.which(binary) is not None


def _brew_safe(args):
    """Run brew with args, delegating to SUDO_USER when running as root."""
    brew_path = shutil.which("brew")
    if not brew_path:
        for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
            if os.path.isfile(p):
                brew_path = p
                break
    if not brew_path:
        print("  [!] brew not found — skipping")
        return
    cmd = [brew_path] + args
    if os.geteuid() == 0:
        user = os.environ.get("SUDO_USER", "").strip()
        if not user or user == "root":
            try:
                r = subprocess.run(["logname"], capture_output=True, text=True, timeout=3)
                user = r.stdout.strip() if r.returncode == 0 else ""
            except Exception:
                user = ""
        if not user or user == "root":
            print(f"  [!] Running as root with no real user — skipping: brew {' '.join(args)}")
            return
        cmd = ["sudo", "-u", user, "-H"] + cmd
    print(f"  → {' '.join(cmd)}")
    subprocess.run(cmd, check=False)




def _dpkg_installed(pkg):
    try:
        r = subprocess.run(["dpkg", "-s", pkg],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _rpm_installed(pkg):
    try:
        return subprocess.run(
            ["rpm", "-q", pkg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0
    except FileNotFoundError:
        return False


def _pip_installed(pkg_spec):
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "python-magic": "magic", "pyyaml": "yaml", "Pillow": "PIL",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None


def _brew_installed_set():
    brew_path = shutil.which("brew")
    if not brew_path:
        for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
            if os.path.isfile(p):
                brew_path = p
                break
    if not brew_path:
        return set()
    cmd = [brew_path, "list", "--formula", "-1"]
    if os.geteuid() == 0:
        user = os.environ.get("SUDO_USER", "").strip()
        if not user or user == "root":
            return set()
        cmd = ["sudo", "-u", user, "-H"] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return set(r.stdout.strip().splitlines())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set()


def install_system_deps():
    """Install system packages via apt/brew/choco."""
    deps_apt = ["libmagic1"]
    deps_brew = ["libmagic"]

    if sys.platform.startswith("linux") and _has("apt-get"):
        print("\nInstalling system dependencies (apt)...")
        for pkg in deps_apt:
            if _dpkg_installed(pkg):
                print(f"  ✓ {pkg} already installed")
            else:
                _run(["sudo", "apt-get", "install", "-y", pkg], check=False)
    elif sys.platform == "darwin" and _has("brew"):
        print("\nInstalling system dependencies (brew)...")
        installed = _brew_installed_set()
        for pkg in deps_brew:
            if pkg in installed:
                print(f"  ✓ {pkg} already installed")
                continue
            _brew_safe(["install", pkg])
    else:
        print("\nSkipping system deps — install libmagic manually if needed.")

def install_pip_deps():
    """Always last. Always --break-system-packages."""
    print("\nInstalling Python dependencies...")
    req = Path(__file__).parent / "requirements.txt"
    if not req.exists():
        print("  requirements.txt not found, skipping.")
        return
    missing = []
    for line in req.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if _pip_installed(line):
            print(f"  ✓ {line} already installed")
        else:
            missing.append(line)
    if not missing:
        print("  All Python packages already installed")
        return
    _run([sys.executable, "-m", "pip", "install",
          "--break-system-packages"] + missing)

def main():
    if sys.version_info < MIN_PYTHON:
        print(f"ERROR: Python {'.'.join(map(str, MIN_PYTHON))}+ required")
        sys.exit(1)

    print(f"{TOOL_NAME} — Installation\n")
    install_system_deps()
    install_pip_deps()

    print(f"\n{TOOL_NAME} installed. Run with: python3 isotope.py <file>")

if __name__ == "__main__":
    main()
