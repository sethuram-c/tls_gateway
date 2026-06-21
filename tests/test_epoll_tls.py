#!/usr/bin/env python3
"""Phase 21: real non-blocking TLS handshakes via epoll (stdlib only)."""
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
BINARY = ROOT / "build" / "tls-gateway"
GENERATOR = ROOT / "scripts" / "generate_dev_certs.sh"
HOST = "127.0.0.1"


def unused_port():
    with socket.socket() as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def logs(file):
    return os.pread(file.fileno(), 1_000_000, 0).decode(errors="replace")


def wait_for(file, process, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        content = logs(file)
        if predicate(content):
            return content
        assert process.poll() is None, content
        time.sleep(0.02)
    raise AssertionError(f"Timed out: {logs(file)}")


def tls_client(port, ctx, hostname="localhost"):
    with socket.create_connection((HOST, port), timeout=3) as sock:
        sock.settimeout(3)
        with ctx.wrap_socket(sock, server_hostname=hostname) as secured:
            assert secured.version() == "TLSv1.3", secured.version()
            assert secured.cipher()[0].startswith("TLS_")
            # This diagnostic intentionally does not return HTTP; it closes
            # after the handshake, before any application-data read.
            return secured.version()


def test_handshakes(cert_dir):
    port = unused_port()
    cert = cert_dir / "server.crt"
    key = cert_dir / "server.key"
    with tempfile.TemporaryFile(mode="w+t") as logfile:
        process = subprocess.Popen(
            [str(BINARY), "--epoll-tls", str(cert), str(key), str(port)],
            stdout=logfile, stderr=subprocess.STDOUT,
        )
        idle = None
        try:
            wait_for(logfile, process, lambda s: "epoll TLS listener ready" in s)
            ctx = ssl.create_default_context(cafile=str(cert_dir / "ca.crt"))
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            assert tls_client(port, ctx) == "TLSv1.3"
            print("PASS: verified TLS 1.3 handshake through non-blocking listener")

            # A deliberately incomplete ClientHello cannot block other clients.
            idle = socket.create_connection((HOST, port), timeout=3)
            idle.sendall(b"\x16\x03")
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                results = list(pool.map(lambda _: tls_client(port, ctx), range(20)))
            assert results == ["TLSv1.3"] * 20
            wait_for(logfile, process, lambda s: s.count("TLS 1.3 handshake complete:") >= 21)
            assert process.poll() is None
            print("PASS: 20 TLS handshakes proceed while another client stalls")

            # Certificate verification occurs on the client, not in the server.
            try:
                tls_client(port, ctx, "mismatch.local")
                raise AssertionError("unexpected accepted hostname mismatch")
            except ssl.SSLCertVerificationError:
                pass

            tls12 = ssl.create_default_context(cafile=str(cert_dir / "ca.crt"))
            tls12.maximum_version = ssl.TLSVersion.TLSv1_2
            try:
                tls_client(port, tls12)
                raise AssertionError("TLS 1.2 negotiated unexpectedly")
            except ssl.SSLError:
                pass

            with socket.create_connection((HOST, port), timeout=3) as plain:
                plain.sendall(b"GET / HTTP/1.0\r\n\r\n")
            assert tls_client(port, ctx) == "TLSv1.3"
            print("PASS: hostname mismatch, TLS 1.2 and plaintext rejected")

            idle.close()
            idle = None
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=4) == 0, logs(logfile)
            assert "epoll TLS listener stopped" in logs(logfile)
            print("PASS: SIGTERM cleanup with concurrent SSL objects")
        finally:
            if idle is not None:
                idle.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)


def test_invalid_configuration(cert_dir):
    cert, key = cert_dir / "server.crt", cert_dir / "server.key"
    for bad in ("0", "65536", "not-a-port"):
        result = subprocess.run(
            [str(BINARY), "--epoll-tls", str(cert), str(key), bad],
            capture_output=True, text=True, timeout=3,
        )
        assert result.returncode == 2, result
    wrong = subprocess.run(
        [str(BINARY), "--epoll-tls", str(cert), str(cert_dir / "ca.key"), "18443"],
        capture_output=True, text=True, timeout=3,
    )
    assert wrong.returncode != 0 and "invalid TLS configuration" in wrong.stderr
    with socket.socket() as owned:
        owned.bind((HOST, 0))
        owned.listen()
        busy = owned.getsockname()[1]
        result = subprocess.run(
            [str(BINARY), "--epoll-tls", str(cert), str(key), str(busy)],
            capture_output=True, text=True, timeout=3,
        )
        assert result.returncode != 0, result
    print("PASS: invalid port, wrong key, and occupied listener rejected")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="tls-gateway-phase21-") as directory:
        certs = Path(directory) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(certs)],
                       check=True, capture_output=True, timeout=25)
        test_handshakes(certs)
        test_invalid_configuration(certs)
    print("PASS: epoll TLS phase 21")
