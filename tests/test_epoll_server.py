#!/usr/bin/env python3
"""Phase 19: integration test for the loopback non-blocking epoll receiver."""
import signal
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

BINARY = Path(__file__).resolve().parents[1] / "build" / "tls-gateway"
HOST = "127.0.0.1"


def free_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def output(log):
    # pread() uses its own offset. seek()+read() would alter the offset
    # shared with the child process and can overwrite or lose log lines.
    return os.pread(log.fileno(), 1_000_000, 0).decode(errors="replace")


def wait_for(log, predicate, process, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = output(log)
        if predicate(text):
            return text
        assert process.poll() is None, f"server exited early:\n{text}"
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for event:\n{output(log)}")


def test_concurrent_clients():
    port = free_port()
    with tempfile.TemporaryFile(mode="w+t") as log:
        proc = subprocess.Popen([str(BINARY), "--epoll-server", str(port)],
                                stdout=log, stderr=subprocess.STDOUT)
        clients = []
        try:
            wait_for(log, lambda s: f"listening on {HOST}:{port}" in s, proc)
            # Keep the first socket idle while the listener accepts many more.
            for _ in range(20):
                conn = socket.create_connection((HOST, port), timeout=2)
                conn.settimeout(2)
                clients.append(conn)
            wait_for(log, lambda s: s.count("Client accepted:") >= len(clients), proc)
            assert proc.poll() is None

            # Interleave payloads; no client has to close to unblock others.
            for i, conn in enumerate(clients):
                conn.sendall(bytes([65 + i]) * (20 + i))
            wait_for(log, lambda s: s.count(" received ") >= len(clients), proc)

            # EOF for every client, while the server stays alive.
            for conn in clients:
                conn.shutdown(socket.SHUT_WR)
            wait_for(log, lambda s: s.count(" closed\n") >= len(clients), proc)
            assert proc.poll() is None, output(log)

            # Accept a new client after cleaning up the first batch.
            with socket.create_connection((HOST, port), timeout=2) as extra:
                extra.sendall(b"still alive")
            wait_for(log, lambda s: s.count("Client accepted:") >= 21
                     and s.count(" closed\n") >= 21, proc)

            proc.send_signal(signal.SIGTERM)
            assert proc.wait(timeout=3) == 0
            assert "epoll TCP server stopped" in output(log)
        finally:
            for client in clients:
                client.close()
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)


def test_busy_port_and_arguments():
    with socket.socket() as holder:
        holder.bind((HOST, 0))
        holder.listen()
        port = holder.getsockname()[1]
        busy = subprocess.run([str(BINARY), "--epoll-server", str(port)],
                              capture_output=True, text=True, timeout=3)
        assert busy.returncode != 0, busy.stdout
        assert "prepare listener" in busy.stderr, busy.stderr

    for bad in ("0", "65536", "-1", "garbage", "42more"):
        result = subprocess.run([str(BINARY), "--epoll-server", bad],
                                capture_output=True, text=True, timeout=3)
        assert result.returncode == 2, (bad, result)
        assert "invalid epoll listener port" in result.stderr

    result = subprocess.run([str(BINARY), "--epoll-server"],
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 2 and "Usage:" in result.stderr


if __name__ == "__main__":
    test_concurrent_clients()
    test_busy_port_and_arguments()
    print("PASS: epoll concurrent TCP accept, read, EOF, reuse, stop, port validation")
