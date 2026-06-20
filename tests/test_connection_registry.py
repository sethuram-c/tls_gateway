#!/usr/bin/env python3
"""Compile a small C unit-test driver and check the live epoll lifecycle."""
import re
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build" / "tls-gateway"


def test_c_registry():
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "connection_probe"
        subprocess.run([
            "gcc", "-Iinclude", "-std=c17", "-Wall", "-Wextra", "-Werror",
            "-g", "tests/connection_probe.c", "src/connection.c", "-o", str(probe),
        ], cwd=ROOT, check=True, timeout=15)
        result = subprocess.run([str(probe)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "PASS: registry" in result.stdout


def output(log):
    return os.pread(log.fileno(), 1_000_000, 0).decode(errors="replace")


def wait_for(log, proc, predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = output(log)
        if predicate(text):
            return text
        assert proc.poll() is None, text
        time.sleep(0.02)
    raise AssertionError(output(log))


def test_concurrent_tracking():
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+t") as log:
        proc = subprocess.Popen([str(BINARY), "--epoll-server", str(port)],
                                stdout=log, stderr=subprocess.STDOUT)
        clients = []
        try:
            wait_for(log, proc, lambda s: "listening on" in s)
            for _ in range(3):
                clients.append(socket.create_connection(("127.0.0.1", port), timeout=2))
            text = wait_for(log, proc, lambda s: s.count("Connection token=") >= 3)
            tokens = [int(s) for s in re.findall(r"Connection token=(\d+)", text)]
            assert len(set(tokens)) >= 3
            for size, c in zip([2, 5, 7], clients):
                c.sendall(b"x" * size)
            wait_for(log, proc, lambda s: s.count(" received ") >= 3)
            for c in clients:
                c.shutdown(socket.SHUT_WR)
            text = wait_for(log, proc, lambda s: s.count(" total received=") >= 3)
            totals = [int(s) for s in re.findall(r"total received=(\d+) bytes", text)]
            assert sorted(totals[:3]) == [2, 5, 7], totals
            assert "active=0" in text
            with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
                c.sendall(b"hi")
            text = wait_for(log, proc, lambda s: s.count("Connection token=") >= 4)
            newest = int(re.findall(r"Connection token=(\d+)", text)[-1])
            assert newest not in tokens
            proc.send_signal(signal.SIGTERM)
            assert proc.wait(timeout=3) == 0
        finally:
            for c in clients:
                c.close()
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)


if __name__ == "__main__":
    test_c_registry()
    test_concurrent_tracking()
    print("PASS: connection lifecycle, capacity, stale epoll tokens, per-client counters")
