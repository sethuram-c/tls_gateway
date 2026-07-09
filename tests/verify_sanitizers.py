#!/usr/bin/env python3
"""Phase 40: instrumented C gateway exercises; stdlib only, no committed keys.

This script is intentionally NOT test_*.py: it needs separate sanitizer
builds and runs only with `make test-sanitize`, not normal `make test`.
"""

import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate_dev_certs.sh"
BACKEND = ROOT / "tests" / "http_backend.py"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def log_text(file):
    return os.pread(file.fileno(), 1_000_000, 0).decode(errors="replace")


def launch(command, log, phrase, *, env=None, timeout=8):
    proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                            env=env, start_new_session=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"server exited {proc.returncode}:\n{log_text(log)}")
        if phrase in log_text(log):
            return proc
        time.sleep(.05)
    stop(proc)
    raise AssertionError(f"server did not start:\n{log_text(log)}")


def stop(proc):
    if proc is None:
        return
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=7)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
            raise AssertionError("server did not terminate")
    assert proc.returncode == 0, f"server exit status {proc.returncode}"


def fetch(ctx, listen, path):
    with socket.create_connection(("127.0.0.1", listen), timeout=5) as raw:
        raw.settimeout(5)
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall((f"GET {path} HTTP/1.1\r\n"
                         "Host: localhost\r\nConnection: close\r\n\r\n").encode())
            response = bytearray()
            while True:
                fragment = tls.recv(8192)
                if not fragment:
                    return bytes(response)
                response.extend(fragment)


def exercise(binary, kind):
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1:abort_on_error=1"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"

    version = subprocess.run([str(binary), "--version"], capture_output=True,
                             text=True, timeout=6, env=env)
    assert version.returncode == 0 and "tls-gateway" in version.stdout, version.stderr
    invalid = subprocess.run([str(binary), "--epoll-server", "70000"],
                             capture_output=True, text=True, timeout=6, env=env)
    assert invalid.returncode == 2, (invalid.returncode, invalid.stderr)

    with tempfile.TemporaryDirectory(prefix=f"phase40-{kind}-") as temp:
        certs = Path(temp) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(certs)],
                       check=True, capture_output=True, timeout=25)
        ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        listen = free_port()
        backend_port = free_port()
        while backend_port == listen:
            backend_port = free_port()

        with tempfile.TemporaryFile() as backend_log, tempfile.TemporaryFile() as gateway_log:
            backend = None
            gateway = None
            try:
                backend = launch(["python3", str(BACKEND), "--port", str(backend_port)],
                                 backend_log, "Python HTTP backend listening")
                gateway = launch([str(binary), "--epoll-tls-proxy", str(certs / "server.crt"),
                                  str(certs / "server.key"), str(listen), str(backend_port)],
                                 gateway_log, "epoll TLS proxy ready", env=env)
                for _ in range(5):
                    response = fetch(ctx, listen, "/health")
                    assert response.startswith(b"HTTP/1.1 200 OK") and \
                           response.endswith(b"\r\n\r\nok\n"), response
                response = fetch(ctx, listen, "/unknown")
                assert response.startswith(b"HTTP/1.1 404"), response
            finally:
                try:
                    stop(gateway)
                finally:
                    if backend is not None:
                        os.killpg(backend.pid, signal.SIGTERM)
                        backend.wait(timeout=5)
            logs = log_text(gateway_log)
            assert "ERROR: AddressSanitizer" not in logs, logs
            assert "runtime error:" not in logs, logs
        print(f"PASS: {kind} HTTPS proxy requests + graceful cleanup")


def main():
    for name, directory in (("AddressSanitizer", "build-asan"),
                            ("UndefinedBehaviorSanitizer", "build-ubsan")):
        binary = ROOT / directory / "tls-gateway"
        if not binary.is_file():
            raise SystemExit(f"Missing {binary}: run make asan && make ubsan first")
        exercise(binary, name)
    print("PASS: instrumented builds use separate directories")


if __name__ == "__main__":
    main()
