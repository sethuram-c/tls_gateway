#!/usr/bin/env python3
"""Phase 23: end-to-end non-blocking TLS echo and concurrent connection tests."""
import concurrent.futures
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "build" / "tls-gateway"
GENERATOR = ROOT / "scripts" / "generate_dev_certs.sh"
HOST = "127.0.0.1"


def free_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def logs(file):
    return os.pread(file.fileno(), 3_000_000, 0).decode(errors="replace")


def await_start(file, process):
    end = time.monotonic() + 6
    while time.monotonic() < end:
        if "epoll TLS listener ready" in logs(file):
            return
        assert process.poll() is None, logs(file)
        time.sleep(.02)
    raise AssertionError(logs(file))


def read_exact(sock, size):
    received = bytearray()
    while len(received) < size:
        chunk = sock.recv(min(4096, size - len(received)))
        assert chunk, f"EOF after {len(received)} of {size} bytes"
        received.extend(chunk)
    return bytes(received)


def main():
    with tempfile.TemporaryDirectory(prefix="tls-phase23-") as folder:
        certdir = Path(folder) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(certdir)],
                       check=True, capture_output=True, timeout=25)
        ctx = ssl.create_default_context(cafile=str(certdir / "ca.crt"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        port = free_port()
        with tempfile.TemporaryFile(mode="w+t") as log:
            server = subprocess.Popen(
                [str(PROGRAM), "--epoll-tls", str(certdir / "server.crt"),
                 str(certdir / "server.key"), str(port)],
                stdout=log, stderr=subprocess.STDOUT,
            )
            stalled = None
            try:
                await_start(log, server)

                def open_client():
                    raw = socket.create_connection((HOST, port), timeout=5)
                    raw.settimeout(5)
                    try:
                        return ctx.wrap_socket(raw, server_hostname="localhost")
                    except BaseException:
                        raw.close()
                        raise

                with open_client() as secure:
                    message = b"\x00\xffbinary\x00\n"
                    secure.sendall(message)
                    assert read_exact(secure, len(message)) == message
                    for part in (b"fragment-", b"one", b"\x00\x01"):
                        secure.sendall(part)
                        assert read_exact(secure, len(part)) == part
                    raw = secure.unwrap()
                    raw.close()
                print("PASS: binary-safe TLS echo and fragmented application records")

                def worker(index):
                    with open_client() as secure:
                        payload = f"worker-{index:02d}".encode()
                        secure.sendall(payload)
                        assert read_exact(secure, len(payload)) == payload
                    return index

                stalled = socket.create_connection((HOST, port), timeout=5)
                stalled.sendall(b"\x16\x03")  # incomplete handshake
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    assert list(executor.map(worker, range(20))) == list(range(20))
                print("PASS: 20 concurrent TLS echo clients despite incomplete handshake")

                with open_client() as secure:
                    payload = bytes(range(256)) * 192  # 48 KiB, larger than queue
                    secure.sendall(payload)
                    # Wait before reading to model a slower client; output is
                    # always buffered in at most one 4-KiB chunk per session.
                    time.sleep(.08)
                    assert read_exact(secure, len(payload)) == payload
                print("PASS: 48 KiB roundtrip with 4 KiB output buffer and slow reader")

                with open_client() as secure:
                    secure.sendall(b"last-message")
                    assert read_exact(secure, 12) == b"last-message"
                assert "TLS echoed:" in logs(log)
                assert server.poll() is None
                print("PASS: subsequent clients remain healthy")

                stalled.close()
                stalled = None
                server.send_signal(signal.SIGTERM)
                assert server.wait(timeout=5) == 0, logs(log)
                assert "epoll TLS listener stopped" in logs(log)
                print("PASS: clean SIGTERM shutdown")
            finally:
                if stalled is not None:
                    stalled.close()
                if server.poll() is None:
                    server.kill()
                    server.wait(timeout=3)


if __name__ == "__main__":
    main()
