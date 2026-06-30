#!/usr/bin/env python3
"""Phase 30: mTLS certificate purpose and required client auth with OpenSSL.

All certificates are temporary. The real C TLS gateway is unchanged this phase.
"""
from pathlib import Path
import hashlib
import os
import socket
import ssl
import stat
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CA_SCRIPT = ROOT / "scripts" / "generate_dev_certs.sh"
CLIENT_SCRIPT = ROOT / "scripts" / "generate_client_cert.sh"


def cmd(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tls_request(port, ca, client_cert=None, client_key=None):
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    if client_cert is not None:
        context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as tcp:
        tcp.settimeout(5)
        with context.wrap_socket(tcp, server_hostname="localhost") as tls:
            assert tls.version() == "TLSv1.3"
            tls.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            result = bytearray()
            while True:
                block = tls.recv(4096)
                if not block:
                    break
                result.extend(block)
            return bytes(result)


def start_server(port, certs, log):
    argv = ["openssl", "s_server", "-accept", f"127.0.0.1:{port}",
            "-cert", str(certs / "server.crt"),
            "-key", str(certs / "server.key"),
            "-CAfile", str(certs / "ca.crt"),
            "-Verify", "1", "-verify_return_error", "-tls1_3", "-www"]
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                            stderr=subprocess.STDOUT)
    # Never spin forever: readiness is bounded and failures show the server log.
    for _ in range(80):
        if proc.poll() is not None:
            raise AssertionError(f"OpenSSL server exited unexpectedly: {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return proc
        except OSError:
            time.sleep(0.05)
    proc.terminate()
    proc.wait(timeout=5)
    raise AssertionError("OpenSSL mTLS server did not become ready")


def run():
    with tempfile.TemporaryDirectory(prefix="tls-phase30-") as tmp:
        root = Path(tmp)
        certs = root / "certs"
        cmd("bash", str(CA_SCRIPT), str(certs))
        cmd("bash", str(CLIENT_SCRIPT), str(certs))
        for name in ("client.key", "client.crt"):
            assert (certs / name).is_file(), name
        assert stat.S_IMODE((certs / "client.key").stat().st_mode) == 0o600
        assert cmd("openssl", "verify", "-CAfile", str(certs / "ca.crt"),
                   "-purpose", "sslclient", str(certs / "client.crt")).returncode == 0
        text = cmd("openssl", "x509", "-in", str(certs / "client.crt"),
                   "-noout", "-text").stdout
        assert "TLS Web Client Authentication" in text, text
        assert "TLS Web Server Authentication" not in text, text
        print("PASS: CA-signed client certificate and restricted private key")

        # Test server-only cert rejected for client authentication and vice versa.
        as_client = cmd("openssl", "verify", "-CAfile", str(certs / "ca.crt"),
                        "-purpose", "sslclient", str(certs / "server.crt"), check=False)
        as_server = cmd("openssl", "verify", "-CAfile", str(certs / "ca.crt"),
                        "-purpose", "sslserver", str(certs / "client.crt"), check=False)
        assert as_client.returncode != 0 and as_server.returncode != 0
        print("PASS: clientAuth and serverAuth purposes are not interchangeable")

        before = hashlib.sha256((certs / "client.key").read_bytes()).digest()
        repeated = cmd("bash", str(CLIENT_SCRIPT), str(certs), check=False)
        assert repeated.returncode != 0
        assert hashlib.sha256((certs / "client.key").read_bytes()).digest() == before
        print("PASS: client identity issuance refuses to overwrite existing keys")

        port = free_port()
        with tempfile.TemporaryFile() as log:
            proc = start_server(port, certs, log)
            try:
                ok = tls_request(port, certs / "ca.crt", certs / "client.crt",
                                 certs / "client.key")
                assert b"HTTP/1.0 200 ok" in ok or b"HTTP/1.0 200" in ok, ok[:150]
                print("PASS: verified TLS 1.3 server accepts trusted client certificate")

                try:
                    response = tls_request(port, certs / "ca.crt")
                except (ssl.SSLError, ConnectionResetError, BrokenPipeError, EOFError):
                    pass
                else:
                    assert b"HTTP/1.0 200" not in response, "missing client cert accepted"
                print("PASS: server requiring mTLS rejects a client without a certificate")

                # A CA-valid serverAuth-only certificate is not an acceptable client identity.
                try:
                    response = tls_request(port, certs / "ca.crt", certs / "server.crt",
                                           certs / "server.key")
                except (ssl.SSLError, ConnectionResetError, BrokenPipeError, EOFError):
                    pass
                else:
                    assert b"HTTP/1.0 200" not in response, "serverAuth certificate accepted for client"
                print("PASS: server requiring mTLS rejects wrong-purpose certificate")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    run()
