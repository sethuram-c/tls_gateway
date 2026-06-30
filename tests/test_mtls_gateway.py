#!/usr/bin/env python3
"""Phase 31: live mTLS enforcement on the non-blocking C TLS gateway.

No persistent keys, privileged ports, or third-party Python packages.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build" / "tls-gateway"
BACKEND = ROOT / "tests" / "http_backend.py"


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=35)


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def logs(file):
    return os.pread(file.fileno(), 1000000, 0).decode(errors="replace")


def launch(argv, file, expected, seconds=6):
    proc = subprocess.Popen(argv, stdout=file, stderr=subprocess.STDOUT)
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if expected in logs(file):
            return proc
        if proc.poll() is not None:
            raise AssertionError(f"Process exited: {logs(file)}")
        time.sleep(0.025)
    terminate(proc)
    raise AssertionError(f"Startup failed: {logs(file)}")


def terminate(proc):
    if proc is None:
        return
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=4)
            raise AssertionError("server would not terminate")
    assert proc.returncode in (0, -signal.SIGTERM), proc.returncode


def client_context(ca_file, cert=None, key=None):
    ctx = ssl.create_default_context(cafile=str(ca_file))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if cert is not None:
        ctx.load_cert_chain(str(cert), str(key))
    return ctx


def request(ctx, port, hostname="localhost"):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        raw.settimeout(4)
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            tls.sendall(f"GET /health HTTP/1.1\r\nHost: {hostname}\r\n\r\n".encode())
            response = bytearray()
            while True:
                block = tls.recv(4096)
                if not block:
                    return bytes(response)
                response.extend(block)


def must_reject(ctx, port, hostname="localhost"):
    try:
        payload = request(ctx, port, hostname)
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError, EOFError, OSError):
        return
    assert b"HTTP/1.1 200" not in payload, f"unauthenticated HTTP accepted: {payload[:160]!r}"


def run():
    with tempfile.TemporaryDirectory(prefix="phase31-mtls-") as temp:
        path = Path(temp)
        certs = path / "certs"
        command("bash", str(ROOT / "scripts" / "generate_dev_certs.sh"), str(certs))
        command("bash", str(ROOT / "scripts" / "generate_sni_cert.sh"), str(certs))
        command("bash", str(ROOT / "scripts" / "generate_client_cert.sh"), str(certs))
        alien = path / "alien"
        command("bash", str(ROOT / "scripts" / "generate_dev_certs.sh"), str(alien))
        trusted = client_context(certs / "ca.crt", certs / "client.crt", certs / "client.key")
        missing = client_context(certs / "ca.crt")
        wrong_purpose = client_context(certs / "ca.crt", certs / "server.crt", certs / "server.key")
        untrusted = client_context(certs / "ca.crt", alien / "server.crt", alien / "server.key")

        proxy_port, backend_port = unused_port(), unused_port()
        while backend_port == proxy_port:
            backend_port = unused_port()
        args = [str(BINARY), "--epoll-tls-proxy-mtls", str(certs / "server.crt"),
                str(certs / "server.key"), str(proxy_port), str(backend_port),
                str(certs / "ca.crt"), str(certs / "api.test.crt"),
                str(certs / "api.test.key")]
        with tempfile.TemporaryFile() as backend_log, tempfile.TemporaryFile() as gateway_log:
            backend = launch(["python3", str(BACKEND), "--port", str(backend_port)],
                             backend_log, "Python HTTP backend listening")
            proxy = None
            try:
                proxy = launch(args, gateway_log, "mTLS mode: client certificate required")
                for name in ("localhost", "api.test"):
                    response = request(trusted, proxy_port, name)
                    assert b"HTTP/1.1 200" in response and response.endswith(b"ok\n"), response
                print("PASS: authenticated mTLS requests forward for localhost and api.test")

                must_reject(missing, proxy_port)
                must_reject(missing, proxy_port, "api.test")
                print("PASS: both SNI certificates require a client certificate")

                must_reject(wrong_purpose, proxy_port)
                must_reject(untrusted, proxy_port)
                print("PASS: wrong-purpose and untrusted client certificates rejected")

                with ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(lambda name: request(trusted, proxy_port, name),
                                            ["localhost", "api.test"] * 10))
                assert len(results) == 20 and all(b"HTTP/1.1 200" in x for x in results)
                print("PASS: 20 concurrent authenticated HTTPS requests")

                # Failed authentication must not be forwarded to the HTTP backend.
                assert logs(backend_log).count('"GET /health HTTP/1.1" 200') == 22, logs(backend_log)
                print("PASS: unauthenticated requests never reached the backend")
            finally:
                terminate(proxy)
                terminate(backend)

        # Invalid CA is a startup error; it must not silently become one-way TLS.
        broken = subprocess.run(args[:6] + [str(path / "missing-ca.pem")] + args[7:],
                                capture_output=True, timeout=5)
        assert broken.returncode != 0
        print("PASS: nonexistent client CA fails closed before listener startup")

        # Backwards-compatible one-way TLS command remains intentionally usable.
        with tempfile.TemporaryFile() as gateway_log, tempfile.TemporaryFile() as backend_log:
            backend = launch(["python3", str(BACKEND), "--port", str(backend_port)],
                             backend_log, "Python HTTP backend listening")
            proxy = None
            try:
                proxy = launch([str(BINARY), "--epoll-tls-proxy",
                                str(certs / "server.crt"), str(certs / "server.key"),
                                str(proxy_port), str(backend_port)],
                               gateway_log, "epoll TLS proxy ready")
                assert b"HTTP/1.1 200" in request(missing, proxy_port)
                print("PASS: existing non-mTLS mode remains backward compatible")
            finally:
                terminate(proxy)
                terminate(backend)


if __name__ == "__main__":
    run()
