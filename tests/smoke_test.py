#!/usr/bin/env python3
"""Minimal smoke tests for Phase 2: no third-party packages."""
import subprocess
from pathlib import Path

binary = Path(__file__).resolve().parents[1] / "build" / "tls-gateway"


def run(*args):
    return subprocess.run([str(binary), *args], capture_output=True, text=True, check=False)


def main():
    default = run()
    assert default.returncode == 0 and "[INFO]" in default.stderr
    help_result = run("--help")
    assert help_result.returncode == 0 and "Usage:" in help_result.stdout
    version = run("--version")
    assert version.returncode == 0 and "0.1.0" in version.stdout
    bad = run("--unexpected")
    assert bad.returncode == 2 and "[ERROR]" in bad.stderr
    print("PASS: default, help, version, invalid argument")


if __name__ == "__main__":
    main()
