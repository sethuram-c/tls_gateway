#!/usr/bin/env python3
"""Phase 32: prove rejected mTLS peers never create an upstream TCP connection.

Standard-library only, all sockets bound to 127.0.0.1, disposable keys.
Run after `make`: python3 tests/test_mtls_rejections.py
"""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build" / "tls-gateway"


def run_cmd(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=35)


def ephemeral_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class CountingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        self.lock = threading.Lock()
        self.accepts = 0
        self.requests = 0
        super().__init__(("127.0.0.1", 0), CountingHandler)

    def get_request(self):
        conn = super().get_request()
        with self.lock:
            self.accepts += 1
        return conn

    def snapshot(self):
        with self.lock:
            return self.accepts, self.requests


class CountingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with self.server.lock:
            self.server.requests += 1
        payload = b"ok\n" if self.path == "/health" else b"not found\n"
        self.send_response(200 if self.path == "/health" else 404)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def log_message(self, *_args):
        pass


def tls_context(ca, cert=None, key=None, tls12=False, check_hostname=True):
    ctx = ssl.create_default_context(cafile=str(ca))
    version = ssl.TLSVersion.TLSv1_2 if tls12 else ssl.TLSVersion.TLSv1_3
    ctx.minimum_version = ctx.maximum_version = version
    ctx.check_hostname = check_hostname
    if cert is not None:
        ctx.load_cert_chain(str(cert), str(key))
    return ctx


def https_get(ctx, port, hostname="localhost"):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as tcp:
        tcp.settimeout(3)
        with ctx.wrap_socket(tcp, server_hostname=hostname) as tls:
            request = f"GET /health HTTP/1.1\r\nHost: {hostname or 'localhost'}\r\nConnection: close\r\n\r\n"
            tls.sendall(request.encode("ascii"))
            received = bytearray()
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    return bytes(received)
                received.extend(chunk)


def rejected(ctx, port, hostname="localhost"):
    """A rejected session must never return HTTP 200, even if TLS opens first."""
    try:
        data = https_get(ctx, port, hostname)
    except (ssl.SSLError, ConnectionError, TimeoutError, EOFError, OSError):
        return
    assert b"HTTP/1.1 200" not in data, f"unauthorized response: {data[:160]!r}"


def read_log(file):
    return os.pread(file.fileno(), 150000, 0).decode(errors="replace")


def launch_gateway(args, logfile):
    proc = subprocess.Popen(args, stdout=logfile, stderr=subprocess.STDOUT)
    until = time.monotonic() + 7
    while time.monotonic() < until:
        if "mTLS mode: client certificate required" in read_log(logfile):
            return proc
        if proc.poll() is not None:
            raise AssertionError(f"gateway unexpectedly exited:\n{read_log(logfile)}")
        time.sleep(0.025)
    stop_gateway(proc)
    raise AssertionError(f"gateway start timed out:\n{read_log(logfile)}")


def stop_gateway(proc):
    if proc is None:
        return
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=4)
            raise AssertionError("gateway would not stop on SIGTERM")
    assert proc.returncode in (0, -signal.SIGTERM), proc.returncode


def assert_no_upstream(server, previous):
    # Gives concurrent event loops time to process late packets before checking.
    time.sleep(0.1)
    current = server.snapshot()
    assert current == previous, f"Rejected peer reached backend: before={previous}, after={current}"


def main():
    assert BINARY.is_file(), "Run make before this test"
    with tempfile.TemporaryDirectory(prefix="phase32-mtls-") as tmp:
        temp = Path(tmp)
        certs, foreign = temp / "certs", temp / "foreign"
        run_cmd("bash", str(ROOT / "scripts/generate_dev_certs.sh"), str(certs))
        run_cmd("bash", str(ROOT / "scripts/generate_sni_cert.sh"), str(certs))
        run_cmd("bash", str(ROOT / "scripts/generate_client_cert.sh"), str(certs))
        run_cmd("bash", str(ROOT / "scripts/generate_dev_certs.sh"), str(foreign))
        run_cmd("bash", str(ROOT / "scripts/generate_client_cert.sh"), str(foreign))

        trusted = tls_context(certs / "ca.crt", certs / "client.crt", certs / "client.key")
        missing = tls_context(certs / "ca.crt")
        wrong_eku = tls_context(certs / "ca.crt", certs / "server.crt", certs / "server.key")
        foreign_client = tls_context(certs / "ca.crt", foreign / "client.crt", foreign / "client.key")
        old_tls = tls_context(certs / "ca.crt", certs / "client.crt", certs / "client.key", tls12=True)
        without_sni = tls_context(certs / "ca.crt", certs / "client.crt", certs / "client.key", check_hostname=False)

        # A certificate paired with another key should be rejected client-side.
        try:
            tls_context(certs / "ca.crt", certs / "client.crt", certs / "server.key")
        except ssl.SSLError:
            pass
        else:
            raise AssertionError("mismatched client certificate/key unexpectedly loaded")
        print("PASS: mismatched client certificate/private key is invalid")

        with CountingHTTPServer() as backend:
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            proxy_port = ephemeral_port()
            while proxy_port == backend.server_address[1]:
                proxy_port = ephemeral_port()
            args = [str(BINARY), "--epoll-tls-proxy-mtls",
                    str(certs / "server.crt"), str(certs / "server.key"),
                    str(proxy_port), str(backend.server_address[1]),
                    str(certs / "ca.crt"), str(certs / "api.test.crt"),
                    str(certs / "api.test.key")]
            with tempfile.TemporaryFile() as logfile:
                gateway = launch_gateway(args, logfile)
                try:
                    for hostname in ("localhost", "api.test"):
                        result = https_get(trusted, proxy_port, hostname)
                        assert b"HTTP/1.1 200" in result and result.endswith(b"ok\n"), result
                    # Without SNI, the default localhost certificate is selected.
                    result = https_get(without_sni, proxy_port, hostname=None)
                    assert b"HTTP/1.1 200" in result and result.endswith(b"ok\n"), result
                    baseline = backend.snapshot()
                    assert baseline == (3, 3), baseline
                    print("PASS: 3 trusted client requests reach the backend across SNI modes")

                    for hostname in ("localhost", "api.test"):
                        rejected(missing, proxy_port, hostname)
                        assert_no_upstream(backend, baseline)
                    print("PASS: missing client certificate rejected for both SNI hostnames")

                    rejected(wrong_eku, proxy_port)
                    assert_no_upstream(backend, baseline)
                    rejected(foreign_client, proxy_port)
                    assert_no_upstream(backend, baseline)
                    print("PASS: wrong-EKU and foreign-CA client certificates rejected upstream")

                    rejected(trusted, proxy_port, "unknown.test")
                    assert_no_upstream(backend, baseline)
                    rejected(old_tls, proxy_port)
                    assert_no_upstream(backend, baseline)
                    print("PASS: unknown SNI and TLS 1.2 do not bypass mTLS")

                    # Bare TCP/partial ClientHello should not connect upstream.
                    with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as stalled:
                        stalled.sendall(b"\x16")
                        assert b"HTTP/1.1 200" in https_get(trusted, proxy_port)
                        baseline = backend.snapshot()
                        assert_no_upstream(backend, baseline)
                    print("PASS: a stalled handshake cannot block or access the backend")

                    # Probe concurrency and ensure the process remains healthy.
                    with ThreadPoolExecutor(max_workers=8) as pool:
                        outcomes = list(pool.map(lambda host: https_get(trusted, proxy_port, host),
                                                 ["localhost", "api.test"] * 5))
                    assert all(b"HTTP/1.1 200" in result for result in outcomes)
                    accepts, requests = backend.snapshot()
                    assert accepts == requests == 14, (accepts, requests)
                    assert gateway.poll() is None
                    print("PASS: 10 subsequent authorized requests succeed; backend counts match")
                finally:
                    stop_gateway(gateway)
            backend.shutdown()
            thread.join(timeout=4)

        # Invalid CA must abort startup, not revert silently to one-way TLS.
        bad = subprocess.run(args[:6] + [str(temp / "missing-ca.pem")] + args[7:],
                             capture_output=True, timeout=5)
        assert bad.returncode != 0
        print("PASS: invalid client CA prevents listener startup (fail closed)")
        print("PASS: Phase 32 mTLS rejection and backend-isolation security tests")


if __name__ == "__main__":
    main()
