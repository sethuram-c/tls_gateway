#!/usr/bin/env python3
"""Phase 14: verify actual HTTP application bytes returned over TLS 1.3."""
import signal
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

from test_tls_listener import HOST, GENERATOR, available_port, start_listener

BODY = b"hello from tls gateway\n"


def read_http(secure):
    """The listener closes after sending its fixed, short HTTP response."""
    reply = bytearray()
    while True:
        block = secure.recv(4096)
        if not block:
            break
        reply.extend(block)
    head, separator, body = bytes(reply).partition(b"\r\n\r\n")
    assert separator == b"\r\n\r\n", reply
    lines = head.split(b"\r\n")
    assert lines[0] == b"HTTP/1.1 200 OK", lines
    headers = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        headers[name.lower()] = value.strip()
    assert headers[b"content-type"] == b"text/plain; charset=utf-8"
    assert headers[b"connection"] == b"close"
    assert int(headers[b"content-length"]) == len(BODY), headers
    assert body == BODY, body
    return bytes(reply)


def main():
    with tempfile.TemporaryDirectory(prefix="tls-gateway-phase14-") as folder:
        certs = Path(folder) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(certs)], check=True,
                       capture_output=True, text=True, timeout=25)
        context = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        port = available_port()
        server = start_listener(certs / "server.crt", certs / "server.key", port)
        try:
            for path in ("/", "/health", "/not-a-real-route"):
                with socket.create_connection((HOST, port), timeout=5) as transport:
                    transport.settimeout(5)
                    with context.wrap_socket(transport, server_hostname="localhost") as tls:
                        assert tls.version() == "TLSv1.3"
                        tls.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                                     "Connection: close\r\n\r\n").encode("ascii"))
                        read_http(tls)
            print("PASS: valid HTTPS response, content length, repeated clients")

            # The server must only write after its first SSL_read succeeds.
            with socket.create_connection((HOST, port), timeout=5) as transport:
                transport.settimeout(5)
                with context.wrap_socket(transport, server_hostname="localhost") as tls:
                    tls.settimeout(0.35)
                    try:
                        tls.recv(1)
                        raise AssertionError("Server responded without application data")
                    except socket.timeout:
                        pass
                    tls.settimeout(5)
                    tls.sendall(b"GET /later HTTP/1.0\r\n\r\n")
                    read_http(tls)
            print("PASS: HTTPS reply only after decrypted application input")

            weak = ssl.create_default_context(cafile=str(certs / "ca.crt"))
            weak.maximum_version = ssl.TLSVersion.TLSv1_2
            try:
                with socket.create_connection((HOST, port), timeout=5) as transport:
                    transport.settimeout(5)
                    with weak.wrap_socket(transport, server_hostname="localhost"):
                        raise AssertionError("TLS 1.2 connection unexpectedly succeeded")
            except ssl.SSLError:
                pass
            print("PASS: TLS 1.2 clients rejected")

            server.send_signal(signal.SIGTERM)
            stdout, stderr = server.communicate(timeout=8)
            assert server.returncode == 0, (stdout, stderr)
            assert stdout.count("TLS HTTP response sent:") >= 4, stdout
            assert "TLS listener stopped" in stdout
            print("PASS: server logs writes and shuts down cleanly")
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate(timeout=5)


if __name__ == "__main__":
    main()
