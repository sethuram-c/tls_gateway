#!/usr/bin/env python3
"""Phase 35: process-level resource and failure-path regression (Fedora/Linux).

Runs only on loopback, uses disposable certificates, and needs no third-party
Python packages. /proc/PID/fd is used to detect unclosed socket descriptors.
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


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def text(file):
    return os.pread(file.fileno(), 500_000, 0).decode(errors="replace")


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        raise AssertionError("gateway/backend did not stop after SIGTERM")


def launch(cmd, logfile, ready):
    # Ignore old startup messages if the same log file is reused on restart.
    seen = len(text(logfile))
    proc = subprocess.Popen(cmd, stdout=logfile, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 7
    while time.monotonic() < deadline:
        if ready in text(logfile)[seen:]:
            assert proc.poll() is None, text(logfile)
            return proc
        if proc.poll() is not None:
            raise AssertionError(f"process exited: {text(logfile)}")
        time.sleep(0.03)
    stop(proc)
    raise AssertionError(f"listener startup timed out: {text(logfile)}")


def fd_count(proc):
    return len(os.listdir(f"/proc/{proc.pid}/fd"))


def wait_fds(proc, maximum, *, timeout=6):
    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        assert proc.poll() is None, "gateway crashed during resource test"
        last = fd_count(proc)
        if last <= maximum:
            return last
        time.sleep(0.04)
    raise AssertionError(f"file descriptors did not drain: {last} > {maximum}")


def request(ctx, tls_port, *, hostname="localhost"):
    with socket.create_connection(("127.0.0.1", tls_port), timeout=4) as sock:
        sock.settimeout(4)
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            tls.sendall((f"GET /health HTTP/1.1\r\nHost: {hostname}\r\n"
                         "Connection: close\r\n\r\n").encode())
            received = bytearray()
            while True:
                data = tls.recv(8192)
                if not data:
                    return bytes(received)
                received.extend(data)


def run():
    assert Path("/proc/self/fd").is_dir(), "Linux /proc is required"
    with tempfile.TemporaryDirectory(prefix="tls-phase35-") as td:
        folder = Path(td)
        certs = folder / "certs"
        for script in ("generate_dev_certs.sh", "generate_sni_cert.sh",
                       "generate_client_cert.sh"):
            subprocess.run(["bash", str(ROOT / "scripts" / script), str(certs)],
                           check=True, stdout=subprocess.DEVNULL, timeout=20)
        gateway_port, backend_port = free_port(), free_port()
        while gateway_port == backend_port:
            backend_port = free_port()
        config = folder / "gateway.conf"
        config.write_text(
            f"listen_port = {gateway_port}\nbackend_port = {backend_port}\n"
            f"server_cert = {certs / 'server.crt'}\n"
            f"server_key = {certs / 'server.key'}\n"
            f"api_cert = {certs / 'api.test.crt'}\n"
            f"api_key = {certs / 'api.test.key'}\n"
            f"require_mtls = true\nclient_ca = {certs / 'ca.crt'}\n"
        )
        ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(str(certs / "client.crt"), str(certs / "client.key"))
        bad_ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        bad_ctx.minimum_version = bad_ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        with tempfile.TemporaryFile() as gateway_log, tempfile.TemporaryFile() as backend_log:
            backend = launch(["python3", str(BACKEND), "--port", str(backend_port)],
                             backend_log, "Python HTTP backend listening")
            gateway = None
            try:
                gateway = launch([str(BINARY), "--config", str(config)],
                                 gateway_log, "mTLS mode: client certificate required")
                # Capture the initial descriptor count before serving clients.
                baseline = fd_count(gateway)
                assert request(ctx, gateway_port).endswith(b"ok\n")
                wait_fds(gateway, baseline)

                # Unfinished handshakes and clients closing just after accept
                # must not retain SSL objects, fds or credential references.
                for i in range(45):
                    with socket.create_connection(("127.0.0.1", gateway_port), timeout=3) as raw:
                        if i % 3 == 0:
                            raw.sendall(b"\x16\x03\x03\x00")
                wait_fds(gateway, baseline)
                print("PASS: 45 interrupted/empty TCP sessions release their fds")

                # Unauthenticated handshakes may fail at different TLS stages.
                for _ in range(15):
                    try:
                        request(bad_ctx, gateway_port)
                    except (ssl.SSLError, ConnectionError, EOFError, OSError):
                        pass
                    else:
                        raise AssertionError("missing client identity was accepted")
                wait_fds(gateway, baseline)
                print("PASS: rejected mTLS clients leave no connected fds")

                def healthy(i):
                    data = request(ctx, gateway_port,
                                   hostname="api.test" if i % 2 else "localhost")
                    assert b"HTTP/1.1 200" in data and data.endswith(b"ok\n"), data

                with ThreadPoolExecutor(max_workers=12) as pool:
                    list(pool.map(healthy, range(36)))
                wait_fds(gateway, baseline)
                print("PASS: 36 concurrent valid HTTPS sessions drain to baseline")

                # After each signal, a new context replaces the old one. The
                # old context must be collectable after its users disappear.
                for i in range(6):
                    gateway.send_signal(signal.SIGHUP)
                    deadline = time.monotonic() + 5
                    while text(gateway_log).count("TLS credentials reloaded successfully") < i + 1:
                        assert time.monotonic() < deadline, text(gateway_log)
                        time.sleep(0.03)
                    healthy(i)
                wait_fds(gateway, baseline)
                print("PASS: repeated SIGHUP reloads release old generations")

                # A refused upstream must not leak the outgoing socket. A
                # healthy upstream should still work after it restarts.
                stop(backend)
                backend = None
                for _ in range(12):
                    response = request(ctx, gateway_port)
                    assert b"HTTP/1.1 502 Bad Gateway" in response, response
                wait_fds(gateway, baseline)
                backend = launch(["python3", str(BACKEND), "--port", str(backend_port)],
                                 backend_log, "Python HTTP backend listening")
                healthy(0)
                wait_fds(gateway, baseline)
                print("PASS: refused backends release socket and later recover")
            finally:
                stop(gateway)
                stop(backend)
            assert gateway is not None and gateway.returncode == 0, (
                f"unexpected gateway exit: {text(gateway_log)}")
            with socket.socket() as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", gateway_port))
            print("PASS: SIGTERM exits cleanly and listener port is reusable")


if __name__ == "__main__":
    run()
