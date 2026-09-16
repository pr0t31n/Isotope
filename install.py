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

def install_system_deps():
    """Install system packages via apt/brew/choco."""
    deps_apt = ["libmagic1"]
    deps_brew = ["libmagic"]

    if sys.platform.startswith("linux") and _has("apt-get"):
        print("\nInstalling system dependencies (apt)...")
        for pkg in deps_apt:
            _run(["sudo", "apt-get", "install", "-y", pkg], check=False)
    elif sys.platform == "darwin" and _has("brew"):
        print("\nInstalling system dependencies (brew)...")
        for pkg in deps_brew:
            _run(["brew", "install", pkg], check=False)
    else:
        print("\nSkipping system deps — install libmagic manually if needed.")

def install_pip_deps():
    """Always last. Always --break-system-packages."""
    print("\nInstalling Python dependencies...")
    req = Path(__file__).parent / "requirements.txt"
    if req.exists():
        _run([sys.executable, "-m", "pip", "install",
              "--break-system-packages", "-r", str(req)])
    else:
        print("  requirements.txt not found, skipping.")

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
