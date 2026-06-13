#!/usr/bin/env python3
"""Phase 13: verify a bounded SSL_read and safe binary logging."""
import signal
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

from test_tls_listener import HOST, ROOT, GENERATOR, available_port, start_listener


def send_application_data(port, context, payload):
    with socket.create_connection((HOST, port), timeout=5) as transport:
        transport.settimeout(5)
        with context.wrap_socket(transport, server_hostname="localhost") as secured:
            secured.sendall(payload)
            assert secured.recv(1) == b"", "Phase 13 must not send app data"


def main():
    with tempfile.TemporaryDirectory(prefix="tls-gateway-read-") as folder:
        certs = Path(folder) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(certs)], check=True,
                       capture_output=True, text=True, timeout=25)
        ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        port = available_port()
        server = start_listener(certs / "server.crt", certs / "server.key", port)
        try:
            request = b"GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n"
            send_application_data(port, ctx, request)
            print("PASS: C server decrypts TLS application request")

            binary = b"\x00\xff\n\x1bEND"
            send_application_data(port, ctx, binary)
            print("PASS: C server accepts binary data safely")

            oversized = b"Z" * 8192
            send_application_data(port, ctx, oversized)
            print("PASS: reading a bounded block does not require full stream")

            with socket.create_connection((HOST, port), timeout=5) as sock:
                sock.settimeout(5)
                with ctx.wrap_socket(sock, server_hostname="localhost") as secure:
                    # An empty application stream can end with TLS close_notify.
                    raw = secure.unwrap()
                    raw.close()
            print("PASS: TLS close_notify before data handled")

            # A silent peer cannot monopolize this blocking listener forever.
            with socket.create_connection((HOST, port), timeout=5) as sock:
                sock.settimeout(6)
                with ctx.wrap_socket(sock, server_hostname="localhost") as secure:
                    assert secure.recv(1) == b""
            print("PASS: silent TLS client bounded by receive timeout")

            server.send_signal(signal.SIGTERM)
            stdout, stderr = server.communicate(timeout=7)
            assert server.returncode == 0, (stdout, stderr)
            assert f"TLS application data read: {len(request)} bytes" in stdout, stdout
            assert "47 45 54 20" in stdout, stdout  # GET in hexadecimal
            assert f"TLS application data read: {len(binary)} bytes" in stdout, stdout
            assert "00 ff 0a 1b 45 4e 44" in stdout, stdout
            assert "TLS application data read: 4096 bytes" in stdout, stdout
            assert "TLS peer closed cleanly before sending" in stdout, stdout
            assert "TLS listener stopped" in stdout, stdout
            assert "\x1b" not in stdout, "Raw ANSI escape bytes reached log"
            print("PASS: exact read sizes, safe hex preview and clean SIGTERM")
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate(timeout=5)


if __name__ == "__main__":
    main()
