#!/usr/bin/env python3
"""Phase 39: loopback HTTP failure injection and recovery for the epoll TLS proxy.

Only Python stdlib. Every malformed request must return 400 without creating
an upstream connection; clients intentionally disconnect at multiple stages.
"""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "build" / "tls-gateway"
HOST = "127.0.0.1"


def free_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def logs(file):
    return os.pread(file.fileno(), 200_000, 0).decode(errors="replace")


def wait_ready(proc, file):
    deadline = time.monotonic() + 7
    while time.monotonic() < deadline:
        if "epoll TLS proxy ready" in logs(file):
            assert proc.poll() is None, logs(file)
            return
        assert proc.poll() is None, logs(file)
        time.sleep(.03)
    raise AssertionError("gateway did not start: " + logs(file))


def receive_all(client):
    data = bytearray()
    while True:
        try:
            chunk = client.recv(8192)
        except (ConnectionResetError, ssl.SSLEOFError):
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def tls_client(ctx, port):
    raw = socket.create_connection((HOST, port), timeout=4)
    raw.settimeout(8)
    try:
        return ctx.wrap_socket(raw, server_hostname="localhost")
    except BaseException:
        raw.close()
        raise


def request(ctx, port, payload, *, split=False):
    with tls_client(ctx, port) as client:
        if split:
            pieces = [payload[:8], payload[8:29], payload[29:]]
            for piece in pieces:
                if piece:
                    client.sendall(piece)
                    time.sleep(.015)
        else:
            client.sendall(payload)
        return receive_all(client)


class Backend(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.lock = threading.Lock()
        self.count = 0
        self.paths = []
        self.release_slow = threading.Event()
        self.slow_started = threading.Event()

    def record(self, path):
        with self.lock:
            self.count += 1
            self.paths.append(path)

    def snapshot(self):
        with self.lock:
            return self.count


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            incoming = bytearray()
            while b"\r\n\r\n" not in incoming and len(incoming) < 10000:
                buf = self.request.recv(4096)
                if not buf:
                    return
                incoming.extend(buf)
            if b"\r\n\r\n" not in incoming:
                return
            path = bytes(incoming).split(b" ", 2)[1]
            self.server.record(path)
            if path == b"/slow":
                self.server.slow_started.set()
                if not self.server.release_slow.wait(5):
                    return
            if path == b"/stream":
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n"
                                     b"Connection: close\r\n\r\npart")
                time.sleep(.5)
                self.request.sendall(b"done")
                return
            body = b"ok\n"
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"
                                 b"Connection: close\r\n\r\n" + body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout, IndexError):
            pass


def check_status(response, status):
    line = response.partition(b"\r\n")[0]
    assert line == f"HTTP/1.1 {status}".encode(), (line, response[:160])


def wait_fd_baseline(proc, baseline, timeout=6):
    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        assert proc.poll() is None, "gateway crashed during failures"
        last = len(os.listdir(f"/proc/{proc.pid}/fd"))
        if last <= baseline:
            return
        time.sleep(.04)
    raise AssertionError(f"resource cleanup failed: fd count {last} > {baseline}")


def run():
    with tempfile.TemporaryDirectory(prefix="tls-phase39-") as td:
        cert_dir = Path(td) / "certs"
        subprocess.run(["bash", str(ROOT / "scripts/generate_dev_certs.sh"),
                        str(cert_dir)], check=True, capture_output=True, timeout=25)
        ctx = ssl.create_default_context(cafile=str(cert_dir / "ca.crt"))
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with Backend((HOST, 0), Handler) as backend:
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            port = free_port()
            while port == backend.server_address[1]:
                port = free_port()
            with tempfile.TemporaryFile() as logfile:
                gateway = subprocess.Popen([
                    str(PROGRAM), "--epoll-tls-proxy",
                    str(cert_dir / "server.crt"), str(cert_dir / "server.key"),
                    str(port), str(backend.server_address[1])],
                    stdout=logfile, stderr=subprocess.STDOUT)
                raw = None
                try:
                    wait_ready(gateway, logfile)
                    baseline_fd = len(os.listdir(f"/proc/{gateway.pid}/fd"))
                    good = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
                    check_status(request(ctx, port, good, split=True), "200 OK")
                    explicit = (b"GET /health HTTP/1.1\r\nHost: localhost\r\n"
                                b"Connection: close\r\n\r\n")
                    check_status(request(ctx, port, explicit), "200 OK")
                    print("PASS: fragmented and explicit-close HTTPS GET still forward")

                    bad_requests = {
                        "unsupported POST": b"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                        "missing Host": b"GET / HTTP/1.1\r\nX-Test: yes\r\n\r\n",
                        "duplicate Host": b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
                        "Content-Length": b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n",
                        "Transfer-Encoding": b"GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
                        "Expect": b"GET / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n\r\n",
                        "Upgrade": b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n",
                        "keep-alive": b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
                        "duplicate Connection": b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nConnection: close\r\n\r\n",
                        "invalid field syntax": b"GET / HTTP/1.1\r\nHost: localhost\r\nBad Header: yes\r\n\r\n",
                        "folded header": b"GET / HTTP/1.1\r\nHost: localhost\r\n continuation\r\n\r\n",
                        "control byte": b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: \x00bad\r\n\r\n",
                        "non-origin target": b"GET http://example.com/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
                        "pipelined requests": good + good,
                        "oversized headers": b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: " + b"a" * 9000 + b"\r\n\r\n",
                    }
                    old = backend.snapshot()
                    for label, payload in bad_requests.items():
                        check_status(request(ctx, port, payload), "400 Bad Request")
                    time.sleep(.2)
                    assert backend.snapshot() == old, (old, backend.snapshot())
                    print(f"PASS: {len(bad_requests)} malformed requests -> 400, zero backend hits")

                    # Disconnect after TLS negotiation but before request completion.
                    for _ in range(24):
                        with tls_client(ctx, port) as client:
                            client.sendall(b"GET /hea")
                    wait_fd_baseline(gateway, baseline_fd)
                    assert backend.snapshot() == old
                    print("PASS: 24 early TLS disconnects release descriptors; no upstream")

                    # An already connected but incomplete ClientHello cannot
                    # block a second, healthy client's request.
                    raw = socket.create_connection((HOST, port), timeout=3)
                    raw.sendall(b"\x16\x03\x03\x00")
                    check_status(request(ctx, port, good), "200 OK")
                    raw.close()
                    raw = None
                    print("PASS: stalled handshake does not block a valid HTTPS client")

                    # A blocked upstream must not starve another connection.
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        future = pool.submit(request, ctx, port,
                                             b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        assert backend.slow_started.wait(3)
                        start = time.monotonic()
                        check_status(request(ctx, port, good), "200 OK")
                        assert time.monotonic() - start < 2.5
                        backend.release_slow.set()
                        check_status(future.result(timeout=5), "200 OK")
                    print("PASS: slow backend does not block concurrent healthy requests")

                    # Peer closes after a streamed reply has started.
                    with tls_client(ctx, port) as client:
                        client.sendall(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        chunk = client.recv(4096)
                        assert chunk.startswith(b"HTTP/1.1 200 OK"), chunk
                    wait_fd_baseline(gateway, baseline_fd)
                    check_status(request(ctx, port, good), "200 OK")
                    print("PASS: mid-response disconnect recovers without crashes/leaks")
                    assert gateway.poll() is None, logs(logfile)
                finally:
                    backend.release_slow.set()
                    if raw is not None:
                        raw.close()
                    if gateway.poll() is None:
                        gateway.send_signal(signal.SIGTERM)
                    try:
                        gateway.wait(timeout=6)
                    except subprocess.TimeoutExpired:
                        gateway.kill()
                        gateway.wait(timeout=5)
                    backend.shutdown()
                    thread.join(timeout=3)
                assert gateway.returncode == 0, logs(logfile)


if __name__ == "__main__":
    run()
