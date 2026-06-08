"""Phase 8: inspect a real TLS 1.3 handshake, without altering the C proxy.

Requires openssl executable and Python standard library only. The certificate is
created in a TemporaryDirectory and never added to the Git repository.
"""
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run():
    with tempfile.TemporaryDirectory(prefix="tls-gateway-phase8-") as tmp:
        certificate = Path(tmp) / "server.pem"
        private_key = Path(tmp) / "server.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-sha256", "-nodes", "-days", "1",
            "-keyout", str(private_key), "-out", str(certificate),
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        port = free_port()
        server = subprocess.Popen([
            "openssl", "s_server", "-quiet", "-tls1_3",
            "-accept", f"127.0.0.1:{port}",
            "-cert", str(certificate), "-key", str(private_key),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            # Wait until the OpenSSL process opens its listening socket.
            for _ in range(60):
                if server.poll() is not None:
                    raise RuntimeError("openssl s_server exited unexpectedly")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("TLS test server did not start")

            verified = ssl.create_default_context(cafile=str(certificate))
            verified.minimum_version = ssl.TLSVersion.TLSv1_3
            verified.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with verified.wrap_socket(raw, server_hostname="localhost") as tls:
                    assert tls.version() == "TLSv1.3", tls.version()
                    assert tls.cipher() is not None
                    print(f"PASS: trusted TLS 1.3 handshake; cipher={tls.cipher()[0]}")

            # Self-signed certificates are NOT trusted by default.
            default = ssl.create_default_context()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                    with default.wrap_socket(raw, server_hostname="localhost"):
                        raise AssertionError("untrusted certificate unexpectedly accepted")
            except ssl.SSLCertVerificationError:
                print("PASS: untrusted self-signed certificate rejected")

            # A trusted certificate still must match the requested hostname.
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                    with verified.wrap_socket(raw, server_hostname="wrong.local"):
                        raise AssertionError("hostname mismatch unexpectedly accepted")
            except ssl.SSLCertVerificationError:
                print("PASS: mismatching hostname rejected")
        finally:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=3)


if __name__ == "__main__":
    run()
