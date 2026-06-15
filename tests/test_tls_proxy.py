#!/usr/bin/env python3
"""Phase 15: end-to-end HTTPS -> C TLS gateway -> Python HTTP backend."""
import select
import signal
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

from test_tls_listener import GENERATOR, HOST, PROGRAM, available_port

ROOT = Path(__file__).resolve().parents[1]


def wait_ready(process, marker):
    ready, _, _ = select.select([process.stdout], [], [], 8)
    if not ready:
        raise AssertionError(f"startup timeout: {marker}")
    line = process.stdout.readline()
    assert marker in line, (line, process.poll())


def start_backend(port):
    process = subprocess.Popen(
        ["python3", str(ROOT / "tests" / "http_backend.py"), "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    wait_ready(process, "Python HTTP backend listening")
    return process


def start_proxy(cert, key, port, backend_port):
    process = subprocess.Popen(
        [str(PROGRAM), "--tls-proxy", str(cert), str(key), str(port), str(backend_port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    wait_ready(process, "TLS proxy ready")
    return process


def request(port, context, path="/", chunks=None):
    with socket.create_connection((HOST, port), timeout=5) as sock:
        sock.settimeout(5)
        with context.wrap_socket(sock, server_hostname="localhost") as tls:
            assert tls.version() == "TLSv1.3"
            if chunks is None:
                chunks = [f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()]
            for block in chunks:
                tls.sendall(block)
                if len(chunks) > 1:
                    time.sleep(.03)
            output = bytearray()
            while True:
                data = tls.recv(4096)
                if not data:
                    break
                output.extend(data)
            head, marker, body = bytes(output).partition(b"\r\n\r\n")
            assert marker, output
            headers = {}
            for field in head.split(b"\r\n")[1:]:
                name, value = field.split(b":", 1)
                headers[name.lower()] = value.strip()
            assert len(body) == int(headers[b"content-length"]), bytes(output)
            return head.split(b"\r\n")[0], body


def main():
    with tempfile.TemporaryDirectory(prefix="tls-gateway-phase15-") as folder:
        certs = Path(folder) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(certs)],
                       check=True, capture_output=True, text=True, timeout=25)
        cert, key = certs / "server.crt", certs / "server.key"
        context = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        gateway_port, backend_port = available_port(), available_port()
        while gateway_port == backend_port:
            backend_port = available_port()
        backend = start_backend(backend_port)
        gateway = None
        try:
            gateway = start_proxy(cert, key, gateway_port, backend_port)
            for path, wanted in (("/", b"hello from python backend\n"),
                                 ("/health", b"ok\n"),
                                 ("/absent", b"not found\n")):
                status, body = request(gateway_port, context, path)
                assert status == (b"HTTP/1.1 404 Not Found" if path == "/absent"
                                  else b"HTTP/1.1 200 OK"), status
                assert body == wanted, (path, body)
            print("PASS: HTTPS termination forwards backend 200 and 404 responses")

            fragmented = [b"GET /hea", b"lth HTTP/1.1\r\nHo",
                          b"st: localhost\r\n", b"\r\n"]
            status, body = request(gateway_port, context, chunks=fragmented)
            assert status == b"HTTP/1.1 200 OK" and body == b"ok\n"
            print("PASS: split TLS reads form one valid HTTP request")

            status, body = request(gateway_port, context,
                                   chunks=[b"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n"])
            assert status == b"HTTP/1.1 405 Method Not Allowed"
            assert body == b"GET only\n"
            print("PASS: unsupported HTTP methods rejected")

            weak = ssl.create_default_context(cafile=str(certs / "ca.crt"))
            weak.maximum_version = ssl.TLSVersion.TLSv1_2
            try:
                request(gateway_port, weak)
                raise AssertionError("TLS 1.2 was accepted")
            except ssl.SSLError:
                pass
            print("PASS: TLS 1.2 clients refused")

            gateway.send_signal(signal.SIGTERM)
            stdout, stderr = gateway.communicate(timeout=8)
            assert gateway.returncode == 0, (stdout, stderr)
            assert stdout.count("Forwarded HTTPS GET") == 4, stdout
            assert "TLS proxy stopped" in stdout
            gateway = None
            print("PASS: clean shutdown after multiple connections")

            backend.send_signal(signal.SIGTERM)
            backend.communicate(timeout=5)
            backend = None
            down_port = available_port()  # nothing listening here
            gateway = start_proxy(cert, key, gateway_port, down_port)
            status, body = request(gateway_port, context)
            assert status == b"HTTP/1.1 502 Bad Gateway" and body == b"backend unavailable\n"
            gateway.send_signal(signal.SIGTERM)
            gateway.communicate(timeout=5)
            gateway = None
            print("PASS: unreachable backend returns HTTP 502")

            bad_ports = subprocess.run([str(PROGRAM), "--tls-proxy", str(cert),
                                        str(key), "0", str(down_port)],
                                       capture_output=True, text=True, timeout=5)
            assert bad_ports.returncode == 2
            print("PASS: invalid listener port rejected")
        finally:
            if gateway is not None and gateway.poll() is None:
                gateway.kill()
                gateway.communicate(timeout=5)
            if backend is not None and backend.poll() is None:
                backend.kill()
                backend.communicate(timeout=5)


if __name__ == "__main__":
    main()
