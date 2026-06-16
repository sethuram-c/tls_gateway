"""Phase 16: non-blocking socketpair lab (no ports, no certificates)."""

import re
import subprocess
from pathlib import Path

BIN = Path(__file__).resolve().parents[1] / "build" / "tls-gateway"


def run(*args):
    return subprocess.run([str(BIN), *args], capture_output=True,
                          text=True, timeout=5, check=False)


def main():
    for _ in range(3):
        result = run("--nonblock-demo")
        assert result.returncode == 0, (result.stdout, result.stderr)
        lines = result.stdout
        assert "Empty recv: EAGAIN (not EOF)" in lines
        assert "First recv: 2 bytes (he)" in lines
        assert "Second recv: 3 bytes (llo)" in lines
        assert "After peer SHUT_WR: recv returned 0 (EOF)" in lines
        match = re.search(r"Full send buffer: EAGAIN after (\d+) bytes ", lines)
        assert match is not None and int(match.group(1)) > 0, lines
        assert "Demo complete" in lines
    help_result = run("--help")
    assert help_result.returncode == 0
    assert "--nonblock-demo" in help_result.stdout
    wrong = run("--nonblock-demo", "extra")
    assert wrong.returncode == 2
    print("PASS: EAGAIN vs EOF, partial reads, bounded sends, CLI validation")


if __name__ == "__main__":
    main()
