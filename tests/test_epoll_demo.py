#!/usr/bin/env python3
"""Phase 18: epoll level-trigger, MOD, RDHUP and DEL smoke tests."""
import subprocess
from pathlib import Path

BIN = Path(__file__).resolve().parents[1] / "build" / "tls-gateway"


def main():
    required = [
        "EPOLL_CTL_ADD / EPOLLIN",
        "Initially: no readable data",
        "After send: EPOLLIN ready",
        "Partial read: he (2 bytes)",
        "EPOLLIN is still ready (3 bytes remain)",
        "After drain: no EPOLLIN",
        "EPOLL_CTL_MOD / EPOLLIN | EPOLLRDHUP",
        "Peer half-close: EPOLLRDHUP ready",
        "At EOF: recv returned 0",
        "After DEL: no more events",
        "Demo complete:",
    ]
    for _ in range(3):
        result = subprocess.run([str(BIN), "--epoll-demo"], capture_output=True,
                                text=True, timeout=5, check=False)
        assert result.returncode == 0, result.stderr
        assert all(needle in result.stdout for needle in required), result.stdout
        positions = [result.stdout.index(needle) for needle in required]
        assert positions == sorted(positions), "steps are out of order"

    invalid = subprocess.run([str(BIN), "--epoll-demo", "extra"],
                             capture_output=True, text=True, timeout=5, check=False)
    assert invalid.returncode == 2 and "Usage:" in invalid.stderr
    print("PASS: epoll readiness, LT re-notification, drain, MOD, RDHUP, DEL, CLI")


if __name__ == "__main__":
    main()
