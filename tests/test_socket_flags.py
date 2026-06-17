"""Phase 17: Python-driven test of the reusable C socket flag helpers."""

import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "build" / "tls-gateway"


def main():
    # Compile a standalone C fixture to exercise the public helper API directly.
    with tempfile.TemporaryDirectory(prefix="gateway-flags-") as folder:
        probe = Path(folder) / "socket_flags_probe"
        compile_result = subprocess.run(
            ["gcc", "-Iinclude", "-std=c17", "-Wall", "-Wextra", "-Wpedantic",
             "-Werror", "-g", "tests/socket_flags_probe.c", "src/socket_flags.c",
             "-o", str(probe)],
            cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
        )
        assert compile_result.returncode == 0, compile_result.stderr
        result = subprocess.run(
            [str(probe)], capture_output=True, text=True, timeout=5, check=False,
        )
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert "PASS: toggle, idempotence" in result.stdout

    demo = subprocess.run(
        [str(GATEWAY), "--nonblock-demo"],
        capture_output=True, text=True, timeout=5, check=False,
    )
    assert demo.returncode == 0, demo.stderr
    assert "Flag helper: endpoint 0 non-blocking; endpoint 1 blocking" in demo.stdout
    assert "Flag helper: restored endpoint 0 to blocking" in demo.stdout
    print("PASS: reusable fcntl helpers, flag semantics and integrated C demo")


if __name__ == "__main__":
    main()
