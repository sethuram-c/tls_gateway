#!/usr/bin/env python3
"""Phase 24: finite state machine unit + end-to-end TLS transition tests."""
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"


def output(log):
    return os.pread(log.fileno(), 1_000_000, 0).decode(errors="replace")


def until(log, process, expected, seconds=6):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        contents = output(log)
        if all(text in contents for text in expected):
            return contents
        assert process.poll() is None, contents
        time.sleep(.02)
    raise AssertionError(output(log))


def main():
    with tempfile.TemporaryDirectory(prefix="tls-phase24-") as folder:
        tmp = Path(folder)
        exe = tmp / "tls-state-probe"
        subprocess.run(["gcc", "-std=c17", "-Wall", "-Wextra", "-Wpedantic",
                        "-Werror", "-fsanitize=undefined", "-I", str(ROOT / "include"),
                        str(ROOT / "src/tls_state.c"), str(ROOT / "tests/tls_state_probe.c"),
                        "-o", str(exe)], check=True, timeout=20)
        proc = subprocess.run([str(exe)], capture_output=True, text=True,
                              check=True, timeout=10)
        print(proc.stdout.strip())
        certs = tmp / "certs"
        subprocess.run(["bash", str(ROOT / "scripts/generate_dev_certs.sh"),
                        str(certs)], check=True, capture_output=True, timeout=25)
        ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with socket.socket() as sock:
            sock.bind((HOST, 0))
            port = sock.getsockname()[1]
        with tempfile.TemporaryFile(mode="w+t") as log:
            gateway = subprocess.Popen([
                str(ROOT / "build/tls-gateway"), "--epoll-tls",
                str(certs / "server.crt"), str(certs / "server.key"), str(port)],
                stdout=log, stderr=subprocess.STDOUT)
            stalled = None
            try:
                until(log, gateway, ["epoll TLS listener ready"])
                stalled = socket.create_connection((HOST, port), timeout=3)
                stalled.sendall(b"\x16\x03")
                with socket.create_connection((HOST, port), timeout=3) as raw:
                    with ctx.wrap_socket(raw, server_hostname="localhost") as client:
                        client.settimeout(3)
                        payload = b"state-machine\x00test"
                        client.sendall(payload)
                        received = bytearray()
                        while len(received) < len(payload):
                            chunk = client.recv(len(payload) - len(received))
                            assert chunk
                            received += chunk
                        assert bytes(received) == payload
                        raw = client.unwrap()
                        raw.close()
                traces = until(log, gateway, [
                    "UNUSED -> HANDSHAKING", "HANDSHAKING -> READING",
                    "READING -> WRITING", "WRITING -> READING",
                    "READING -> CLOSING", "CLOSING -> UNUSED",
                    "TLS close_notify received:"])
                assert "Invalid TLS state transition" not in traces
                print("PASS: handshake, echo, orderly closure follow legal transitions")
                with socket.create_connection((HOST, port), timeout=3) as raw:
                    with ctx.wrap_socket(raw, server_hostname="localhost") as client:
                        client.sendall(b"again")
                        assert client.recv(5) == b"again"
                assert gateway.poll() is None
                print("PASS: incomplete handshake cannot block another live client")
                stalled.close()
                stalled = None
                gateway.send_signal(signal.SIGTERM)
                assert gateway.wait(timeout=5) == 0, output(log)
                assert "epoll TLS listener stopped" in output(log)
                print("PASS: SIGTERM releases TLS sessions")
            finally:
                if stalled is not None:
                    stalled.close()
                if gateway.poll() is None:
                    gateway.kill()
                    gateway.wait(timeout=3)


if __name__ == "__main__":
    main()
