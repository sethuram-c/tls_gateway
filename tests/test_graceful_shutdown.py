#!/usr/bin/env python3
"""Phase 37: SIGTERM/SIGINT drain active HTTPS requests and stop accepting.

Pure Python standard library.  All networking is loopback-only, and the
certificate/key material lives only in a disposable temporary directory.
"""
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
GATEWAY = ROOT / "build" / "tls-gateway"
HOST = "127.0.0.1"


def unused_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def log_text(file):
    return os.pread(file.fileno(), 200_000, 0).decode(errors="replace")


def await_log(process, file, phrase, seconds=6):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if phrase in log_text(file):
            return
        if process.poll() is not None:
            raise AssertionError("unexpected gateway exit\n" + log_text(file))
        time.sleep(.025)
    raise AssertionError("missing log: " + phrase + "\n" + log_text(file))


class BackendHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        request = bytearray()
        try:
            while b"\r\n\r\n" not in request and len(request) < 8192:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                request.extend(chunk)
            route = bytes(request).split(b" ", 2)[1]
            if route == b"/slow":
                self.server.slow_started.set()
                self.server.slow_release.wait(8)
            elif route == b"/hang":
                self.server.hang_started.set()
                self.server.hang_release.wait(8)
                return
            body = b"ok\n"
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"
                                 b"Connection: close\r\n\r\n" + body)
        except (OSError, IndexError):
            return


class Backend(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def open_tls(context, port):
    raw = socket.create_connection((HOST, port), timeout=2)
    raw.settimeout(8)
    return context.wrap_socket(raw, server_hostname="localhost")


def get(client, route):
    client.sendall(f"GET {route} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())


def read_response(client):
    chunks = []
    while True:
        try:
            chunk = client.recv(4096)
        except (OSError, ssl.SSLError):
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def port_refuses(port):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=.2):
                pass
        except ConnectionRefusedError:
            return True
        time.sleep(.025)
    return False


def start_gateway(cert_dir, listener, backend_port, file):
    proc = subprocess.Popen([
        str(GATEWAY), "--epoll-tls-proxy",
        str(cert_dir / "server.crt"), str(cert_dir / "server.key"),
        str(listener), str(backend_port)], stdout=file,
        stderr=subprocess.STDOUT)
    await_log(proc, file, "epoll TLS proxy ready")
    return proc


def shutdown(proc):
    if proc is None:
        return
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)
        raise


def run():
    with tempfile.TemporaryDirectory(prefix="phase37-") as temp:
        certs = Path(temp) / "certs"
        subprocess.run(["bash", str(ROOT / "scripts/generate_dev_certs.sh"),
                        str(certs)], capture_output=True, check=True, timeout=25)
        context = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        with Backend((HOST, 0), BackendHandler) as backend:
            backend.slow_started = threading.Event()
            backend.slow_release = threading.Event()
            backend.hang_started = threading.Event()
            backend.hang_release = threading.Event()
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            try:
                # In-flight HTTPS response should survive SIGTERM.
                listener = unused_port()
                with tempfile.TemporaryFile() as log:
                    proc = start_gateway(certs, listener, backend.server_address[1], log)
                    client = None
                    try:
                        client = open_tls(context, listener)
                        get(client, "/slow")
                        assert backend.slow_started.wait(timeout=3)
                        proc.send_signal(signal.SIGTERM)
                        await_log(proc, log, "TLS proxy draining")
                        assert port_refuses(listener), "listener still accepts after SIGTERM"
                        backend.slow_release.set()
                        reply = read_response(client)
                        assert reply.startswith(b"HTTP/1.1 200 OK"), reply
                        assert reply.endswith(b"ok\n"), reply
                        proc.wait(timeout=5)
                        assert proc.returncode == 0
                        assert "TLS proxy drain complete" in log_text(log)
                        print("PASS: SIGTERM stops new accepts and completes in-flight HTTPS")
                    finally:
                        backend.slow_release.set()
                        if client is not None:
                            client.close()
                        shutdown(proc)

                # An upstream that never responds must not delay shutdown
                # forever; close remaining connections at the drain deadline.
                listener = unused_port()
                with tempfile.TemporaryFile() as log:
                    proc = start_gateway(certs, listener, backend.server_address[1], log)
                    client = None
                    try:
                        client = open_tls(context, listener)
                        get(client, "/hang")
                        assert backend.hang_started.wait(timeout=3)
                        start = time.monotonic()
                        proc.send_signal(signal.SIGTERM)
                        await_log(proc, log, "TLS proxy draining")
                        assert port_refuses(listener)
                        reply = read_response(client)
                        proc.wait(timeout=6)
                        elapsed = time.monotonic() - start
                        assert 3 <= elapsed < 6, elapsed
                        assert reply == b"", reply  # no spurious 504 or 200
                        assert proc.returncode == 0, log_text(log)
                        assert "TLS proxy drain deadline reached" in log_text(log)
                        with socket.socket() as check:
                            check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            check.bind((HOST, listener))
                        print("PASS: 4 s drain deadline closes stalled upstream and frees port")
                    finally:
                        backend.hang_release.set()
                        if client is not None:
                            client.close()
                        shutdown(proc)

                # SIGINT shares graceful semantics; no active client means
                # immediate shutdown instead of waiting for full grace period.
                listener = unused_port()
                with tempfile.TemporaryFile() as log:
                    proc = start_gateway(certs, listener, backend.server_address[1], log)
                    try:
                        begin = time.monotonic()
                        proc.send_signal(signal.SIGINT)
                        proc.wait(timeout=3)
                        assert time.monotonic() - begin < 2.5
                        assert proc.returncode == 0
                        assert "TLS proxy drain complete" in log_text(log)
                        print("PASS: SIGINT with no active clients exits promptly")
                    finally:
                        shutdown(proc)
            finally:
                backend.slow_release.set()
                backend.hang_release.set()
                backend.shutdown()
                thread.join(timeout=3)


if __name__ == "__main__":
    run()
