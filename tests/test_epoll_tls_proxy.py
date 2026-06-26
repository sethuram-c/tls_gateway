#!/usr/bin/env python3
"""Phase 26: HTTPS -> non-blocking epoll TLS proxy -> Python HTTP backend."""
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
PROGRAM = ROOT / "build" / "tls-gateway"
BACKEND = ROOT / "tests" / "http_backend.py"
GENERATOR = ROOT / "scripts" / "generate_dev_certs.sh"
HOST = "127.0.0.1"


def unused_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def logs(f):
    return os.pread(f.fileno(), 2_000_000, 0).decode(errors="replace")


def wait_log(proc, logfile, text, timeout=7):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if text in logs(logfile):
            return
        if proc.poll() is not None:
            raise AssertionError(logs(logfile))
        time.sleep(.03)
    raise AssertionError(f"missing {text!r}\n" + logs(logfile))


def launch(cmd, log, ready):
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
    wait_log(proc, log, ready)
    return proc


def stop(proc, expected_signal=False):
    if proc is None:
        return
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=4)
            raise AssertionError("subprocess failed to stop")
    assert proc.returncode in ((0, -signal.SIGTERM) if expected_signal else (0,)), proc.returncode


def get(ctx, port, path="/", fragments=False, explicit_close=False):
    with socket.create_connection((HOST, port), timeout=5) as raw:
        raw.settimeout(5)
        with ctx.wrap_socket(raw, server_hostname="localhost") as client:
            assert client.version() == "TLSv1.3"
            request = (f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                       + ("Connection: close\r\n" if explicit_close else "")
                       + "\r\n").encode()
            if fragments:
                for chunk in (request[:6], request[6:21], request[21:]):
                    client.sendall(chunk)
                    time.sleep(.02)
            else:
                client.sendall(request)
            data = bytearray()
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
            head, marker, body = bytes(data).partition(b"\r\n\r\n")
            assert marker, bytes(data)
            return head.split(b"\r\n")[0], body


def main():
    with tempfile.TemporaryDirectory(prefix="phase26-") as temp:
        directory = Path(temp) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(directory)],
                       check=True, capture_output=True, timeout=25)
        ctx = ssl.create_default_context(cafile=str(directory / "ca.crt"))
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        proxy_port, backend_port = unused_port(), unused_port()
        while proxy_port == backend_port:
            backend_port = unused_port()
        with tempfile.TemporaryFile() as backend_log, tempfile.TemporaryFile() as gateway_log:
            backend = launch(["python3", str(BACKEND), "--port", str(backend_port)],
                             backend_log, "Python HTTP backend listening")
            gateway = None
            slow = None
            try:
                gateway = launch([str(PROGRAM), "--epoll-tls-proxy",
                                  str(directory / "server.crt"),
                                  str(directory / "server.key"),
                                  str(proxy_port), str(backend_port)],
                                 gateway_log, "epoll TLS proxy ready")
                for path, expected in (("/", b"hello from python backend\n"),
                                       ("/health", b"ok\n"),
                                       ("/unknown", b"not found\n")):
                    status, body = get(ctx, proxy_port, path)
                    assert status.startswith(b"HTTP/1.1 404") if path == "/unknown" \
                        else status.startswith(b"HTTP/1.1 200"), (status, path)
                    assert body == expected, (path, body)
                print("PASS: HTTPS GET forwards 200 and 404 backend responses")
                status, body = get(ctx, proxy_port, "/health", fragments=True)
                assert status.startswith(b"HTTP/1.1 200") and body == b"ok\n"
                print("PASS: fragmented TLS HTTP headers")
                status, body = get(ctx, proxy_port, "/health", explicit_close=True)
                assert status.startswith(b"HTTP/1.1 200") and body == b"ok\n"
                print("PASS: explicit Connection: close accepted")
                status, body = get(ctx, proxy_port, "/large")
                assert status.startswith(b"HTTP/1.1 200")
                assert len(body) == 64 * 1024 and body == b"x" * (64 * 1024)
                print("PASS: 64 KiB response streams through 8 KiB buffer")
                slow = socket.create_connection((HOST, proxy_port), timeout=5)
                slow.sendall(b"\x16\x03")  # Incomplete ClientHello must not block loop.

                def worker(n):
                    status, body = get(ctx, proxy_port, "/health" if n % 2 else "/")
                    assert status.startswith(b"HTTP/1.1 200")
                    assert body in (b"ok\n", b"hello from python backend\n")
                    return n

                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                    assert list(pool.map(worker, range(20))) == list(range(20))
                print("PASS: 20 concurrent HTTPS requests with stalled handshake")
                slow.close()
                slow = None
                weak = ssl.create_default_context(cafile=str(directory / "ca.crt"))
                weak.maximum_version = ssl.TLSVersion.TLSv1_2
                try:
                    get(weak, proxy_port)
                except ssl.SSLError:
                    pass
                else:
                    raise AssertionError("TLS 1.2 unexpectedly accepted")
                print("PASS: TLS 1.2 rejected")
            finally:
                if slow is not None:
                    slow.close()
                stop(gateway)
                stop(backend, expected_signal=True)
        # Refused upstream -> valid HTTPS 502 without hanging.
        bad_port, dead_backend = unused_port(), unused_port()
        with tempfile.TemporaryFile() as log:
            gateway = launch([str(PROGRAM), "--epoll-tls-proxy",
                              str(directory / "server.crt"),
                              str(directory / "server.key"),
                              str(bad_port), str(dead_backend)],
                             log, "epoll TLS proxy ready")
            try:
                status, body = get(ctx, bad_port)
                assert status == b"HTTP/1.1 502 Bad Gateway" and body == b"bad gateway\n"
                print("PASS: unavailable backend returns HTTPS 502")
            finally:
                stop(gateway)
        args = [str(PROGRAM), "--epoll-tls-proxy", str(directory / "server.crt"),
                str(directory / "server.key"), "18444", "18444"]
        assert subprocess.run(args, capture_output=True, timeout=3).returncode == 2
        print("PASS: invalid CLI ports rejected")


if __name__ == "__main__":
    main()
