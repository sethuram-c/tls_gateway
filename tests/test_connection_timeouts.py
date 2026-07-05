#!/usr/bin/env python3
"""Phase 36: monotonic stage deadlines for the epoll HTTPS proxy.

No external dependencies. A threaded loopback backend makes deliberate stalls
without blocking healthy requests. Temporary certificate keys are deleted.
"""
import os
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build" / "tls-gateway"
HOST = "127.0.0.1"


def free_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def log_text(log):
    return os.pread(log.fileno(), 200_000, 0).decode(errors="replace")


def wait_ready(proc, log):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        if "epoll TLS proxy ready" in log_text(log):
            assert proc.poll() is None
            return
        if proc.poll() is not None:
            raise AssertionError(log_text(log))
        time.sleep(.04)
    raise AssertionError("gateway did not start\n" + log_text(log))


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        packet = bytearray()
        try:
            while b"\r\n\r\n" not in packet and len(packet) < 8192:
                data = self.request.recv(4096)
                if not data:
                    return
                packet.extend(data)
            path = bytes(packet).split(b" ", 2)[1]
            if path == b"/hang":
                self.server.release.wait(12)
                return
            if path == b"/partial":
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\n"
                                     b"Connection: close\r\n\r\npart")
                self.server.release.wait(12)
                return
            body = b"ok\n"
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"
                b"Connection: close\r\n\r\n" + body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass


class ThreadingBackend(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def tls_client(ctx, port):
    sock = socket.create_connection((HOST, port), timeout=4)
    sock.settimeout(9)
    return ctx.wrap_socket(sock, server_hostname="localhost")


def receive_all(client):
    chunks = []
    while True:
        try:
            data = client.recv(4096)
        except (ConnectionResetError, ssl.SSLEOFError):
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def send_get(ctx, port, path):
    with tls_client(ctx, port) as client:
        client.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        return receive_all(client)


def run():
    with tempfile.TemporaryDirectory(prefix="tls-phase36-") as td:
        certs = Path(td) / "certs"
        subprocess.run(["bash", str(ROOT / "scripts/generate_dev_certs.sh"),
                        str(certs)], check=True, timeout=25, capture_output=True)
        ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with ThreadingBackend((HOST, 0), Handler) as backend:
            backend.release = threading.Event()
            worker = threading.Thread(target=backend.serve_forever, daemon=True)
            worker.start()
            listen_port = free_port()
            while listen_port == backend.server_address[1]:
                listen_port = free_port()
            with tempfile.TemporaryFile() as logfile:
                gateway = subprocess.Popen([
                    str(BINARY), "--epoll-tls-proxy",
                    str(certs / "server.crt"), str(certs / "server.key"),
                    str(listen_port), str(backend.server_address[1])],
                    stdout=logfile, stderr=subprocess.STDOUT)
                raw = None
                try:
                    wait_ready(gateway, logfile)
                    # A peer that never sends a complete ClientHello consumes
                    # a slot but cannot starve a completed TLS handshake.
                    raw = socket.create_connection((HOST, listen_port), timeout=3)
                    raw.settimeout(8)
                    raw.sendall(b"\x16\x03\x03\x00")
                    begin = time.monotonic()
                    assert b"ok\n" in send_get(ctx, listen_port, "/health")
                    assert raw.recv(1) == b"", "stalled ClientHello was not closed"
                    elapsed = time.monotonic() - begin
                    assert 2.8 <= elapsed < 7.5, elapsed
                    raw.close()
                    raw = None
                    print("PASS: unfinished TLS handshake closes after monotonic deadline")

                    # Incomplete HTTP request is an application idle timeout.
                    with tls_client(ctx, listen_port) as client:
                        client.sendall(b"GET /unfin")
                        begin = time.monotonic()
                        reply = receive_all(client)
                        elapsed = time.monotonic() - begin
                        assert reply.startswith(b"HTTP/1.1 408 Request Timeout"), reply
                        assert reply.endswith(b"request timeout\n"), reply
                        assert 3.8 <= elapsed < 8.0, elapsed
                    print("PASS: idle verified TLS client gets HTTP 408")

                    # A backend which accepts and never sends a response causes
                    # 504, while a second healthy client is served immediately.
                    def hang_get():
                        return send_get(ctx, listen_port, "/hang")

                    from concurrent.futures import ThreadPoolExecutor
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        future = pool.submit(hang_get)
                        time.sleep(.35)
                        begin = time.monotonic()
                        assert b"ok\n" in send_get(ctx, listen_port, "/health")
                        assert time.monotonic() - begin < 2.5
                        reply = future.result(timeout=9)
                    assert reply.startswith(b"HTTP/1.1 504 Gateway Timeout"), reply
                    assert reply.endswith(b"gateway timeout\n"), reply
                    print("PASS: hung upstream gets HTTPS 504 without blocking peers")

                    # Once a 200 response has started, switching to 504 would
                    # corrupt the HTTP stream: close instead.
                    reply = send_get(ctx, listen_port, "/partial")
                    assert reply.startswith(b"HTTP/1.1 200 OK"), reply
                    assert reply.endswith(b"part"), reply
                    assert b"504 Gateway Timeout" not in reply, reply
                    assert b"ok\n" in send_get(ctx, listen_port, "/health")
                    print("PASS: stalled streamed response closes without injecting 504")
                    print("PASS: valid HTTPS requests still work after all timeouts")
                    assert gateway.poll() is None, log_text(logfile)
                finally:
                    backend.release.set()
                    if raw is not None:
                        raw.close()
                    if gateway.poll() is None:
                        gateway.send_signal(signal.SIGTERM)
                    try:
                        gateway.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        gateway.kill()
                        gateway.wait(timeout=5)
                    backend.shutdown()
                    worker.join(timeout=3)
                assert gateway.returncode == 0, log_text(logfile)


if __name__ == "__main__":
    run()
