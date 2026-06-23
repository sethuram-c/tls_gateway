#!/usr/bin/env python3
"""Phase 23: test the pure C bounded output queue using a compiled probe."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="tls-phase23-buffer-") as folder:
        executable = Path(folder) / "output-buffer-probe"
        subprocess.run([
            "gcc", "-std=c17", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-I", str(ROOT / "include"),
            str(ROOT / "tests" / "output_buffer_probe.c"),
            str(ROOT / "src" / "output_buffer.c"),
            "-o", str(executable),
        ], check=True, timeout=20)
        result = subprocess.run([str(executable)], check=True, capture_output=True,
                                text=True, timeout=10)
        assert result.stdout.startswith("PASS:"), result.stdout
        print(result.stdout.strip())


if __name__ == "__main__":
    main()
