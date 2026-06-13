#!/usr/bin/env python3
"""Phase 13: TLS 1.3 listener regression tests (standard library)."""
import select
import signal
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "build" / "tls-gateway"
GENERATOR = ROOT / "scripts" / "generate_dev_certs.sh"
HOST = "127.0.0.1"


def call(*args):
    return subprocess.run([str(PROGRAM), *map(str, args)], capture_output=True,
                          text=True, timeout=10)


def available_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def start_listener(cert, key, port):
    process = subprocess.Popen([str(PROGRAM), "--tls-listen", str(cert),
                                str(key), str(port)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    ready, _, _ = select.select([process.stdout], [], [], 7)
    if not ready:
        process.kill()
        process.communicate(timeout=5)
        raise AssertionError("Timed out waiting for TLS listener startup")
    line = process.stdout.readline()
    assert "TLS listener ready" in line, line
    return process


def tls_connect(port, context, hostname="localhost"):
    with socket.create_connection((HOST, port), timeout=4) as transport:
        transport.settimeout(4)
        with context.wrap_socket(transport, server_hostname=hostname) as secured:
            assert secured.version() == "TLSv1.3", secured.version()
            assert secured.cipher()[0].startswith("TLS_"), secured.cipher()
            secured.sendall(b"GET /listener HTTP/1.0\r\n\r\n")
            assert secured.recv(1) == b""  # Phase 13 reads but does not reply.


def main():
    with tempfile.TemporaryDirectory(prefix="tls-gateway-phase13-") as tmp:
        certs = Path(tmp) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(certs)], check=True,
                       capture_output=True, text=True, timeout=25)
        cert, key = certs / "server.crt", certs / "server.key"
        port = available_port()
        server = start_listener(cert, key, port)
        try:
            trusted = ssl.create_default_context(cafile=str(certs / "ca.crt"))
            trusted.minimum_version = ssl.TLSVersion.TLSv1_3
            trusted.maximum_version = ssl.TLSVersion.TLSv1_3
            tls_connect(port, trusted)
            tls_connect(port, trusted)
            print("PASS: trusted TLS 1.3 handshakes on repeated connections")

            # Certificate is valid for localhost, not the supplied wrong name.
            try:
                tls_connect(port, trusted, hostname="wrong.local")
                raise AssertionError("Mismatched hostname was accepted")
            except ssl.SSLCertVerificationError:
                pass
            print("PASS: wrong server hostname rejected by client")

            untrusted = ssl.create_default_context()
            try:
                tls_connect(port, untrusted)
                raise AssertionError("Development CA was trusted unexpectedly")
            except ssl.SSLCertVerificationError:
                pass
            print("PASS: untrusted development CA rejected by client")

            with socket.create_connection((HOST, port), timeout=4) as plain:
                plain.settimeout(4)
                plain.sendall(b"GET / HTTP/1.0\r\n\r\n")
                try:
                    assert plain.recv(1024) == b""  # Not a TLS ClientHello.
                except ConnectionResetError:
                    pass  # TCP reset is also a valid plaintext rejection.
            tls_connect(port, trusted)
            print("PASS: plaintext rejected; server continues accepting TLS")

            tls12 = ssl.create_default_context(cafile=str(certs / "ca.crt"))
            tls12.maximum_version = ssl.TLSVersion.TLSv1_2
            try:
                tls_connect(port, tls12)
                raise AssertionError("TLS 1.2 was accepted")
            except ssl.SSLError:
                pass
            tls_connect(port, trusted)
            print("PASS: TLS 1.2 rejected; TLS 1.3 remains available")

            server.send_signal(signal.SIGTERM)
            stdout, stderr = server.communicate(timeout=7)
            assert server.returncode == 0, (stdout, stderr)
            assert "TLS handshake complete" in stdout and "TLS listener stopped" in stdout
            print("PASS: clean SIGTERM shutdown and socket cleanup")
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate(timeout=5)

        mismatch = call("--tls-listen", cert, certs / "ca.key", port)
        assert mismatch.returncode != 0 and "invalid TLS configuration" in mismatch.stderr
        absent = call("--tls-listen", certs / "absent.crt", key, port)
        assert absent.returncode != 0
        bad_port = call("--tls-listen", cert, key, 70000)
        assert bad_port.returncode == 2 and "invalid TLS listener port" in bad_port.stderr
        print("PASS: mismatched key, absent certificate and invalid port rejected")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            held.bind((HOST, 0))
            held.listen(1)
            busy = held.getsockname()[1]
            collision = call("--tls-listen", cert, key, busy)
            assert collision.returncode != 0
            assert "TLS listener socket setup" in collision.stderr
        print("PASS: occupied listener port rejected")


if __name__ == "__main__":
    main()
