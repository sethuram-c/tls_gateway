#!/usr/bin/env python3
"""Phase 22: verify non-blocking TLS application reads (stdlib only)."""
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
BINARY = ROOT / "build" / "tls-gateway"
GENERATOR = ROOT / "scripts" / "generate_dev_certs.sh"
HOST = "127.0.0.1"


def unused_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def log_contents(logfile):
    # pread does not move the subprocess's shared file offset.
    return os.pread(logfile.fileno(), 2_000_000, 0).decode(errors="replace")


def wait_for(logfile, process, predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        content = log_contents(logfile)
        if predicate(content):
            return content
        assert process.poll() is None, content
        time.sleep(0.02)
    raise AssertionError(f"Timed out; log:\n{log_contents(logfile)}")


def verified_context(cert_dir):
    context = ssl.create_default_context(cafile=str(cert_dir / "ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context


def open_tls(port, context):
    raw = socket.create_connection((HOST, port), timeout=3)
    raw.settimeout(3)
    try:
        secured = context.wrap_socket(raw, server_hostname="localhost")
        assert secured.version() == "TLSv1.3"
        return secured
    except BaseException:
        raw.close()
        raise


def test_reads(certs):
    port = unused_port()
    with tempfile.TemporaryFile(mode="w+t") as log:
        process = subprocess.Popen(
            [str(BINARY), "--epoll-tls", str(certs / "server.crt"),
             str(certs / "server.key"), str(port)],
            stdout=log, stderr=subprocess.STDOUT,
        )
        idle = None
        secured = None
        try:
            wait_for(log, process, lambda s: "epoll TLS listener ready" in s)
            context = verified_context(certs)
            secured = open_tls(port, context)
            # A completed handshake no longer causes an immediate close.
            secured.sendall(b"\x00A\xff")
            assert secured.recv(3) == b"\x00A\xff"
            wait_for(log, process,
                     lambda s: "bytes=3 total=3 hex=0041ff" in s)
            secured.sendall(b"hello")
            assert secured.recv(5) == b"hello"
            wait_for(log, process,
                     lambda s: "bytes=5 total=8 hex=68656c6c6f" in s)
            assert process.poll() is None
            print("PASS: TLS session persists; binary and split payloads decrypted")

            # unwrap() sends close_notify and expects the peer's close_notify.
            raw = secured.unwrap()
            raw.close()
            secured = None
            wait_for(log, process,
                     lambda s: "TLS close_notify received:" in s and "total=8" in s)
            print("PASS: clean TLS close_notify closes per-client state")

            # One TCP peer never completes its TLS handshake. Other clients
            # must still be able to handshake, send bytes and close.
            idle = socket.create_connection((HOST, port), timeout=3)
            idle.sendall(b"\x16\x03")

            def worker(index):
                with open_tls(port, context) as client:
                    client.sendall(f"client-{index:02d}".encode("ascii"))
                return index

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                assert list(pool.map(worker, range(20))) == list(range(20))
            wait_for(log, process,
                     lambda s: s.count("TLS application data:") >= 22)
            assert process.poll() is None
            print("PASS: 20 active TLS readers unaffected by stalled handshake")

            # Cap app-data consumption at 64 KiB per TLS client. No need to
            # rely on a particular number of SSL_read() calls or TCP packets.
            flood = open_tls(port, context)
            try:
                # Alternate sends/receives: an echo service must not be forced
                # to buffer 64 KiB in userspace while the client never reads.
                for _ in range(16):
                    flood.sendall(b"Z" * 4096)
                    echoed = bytearray()
                    while len(echoed) < 4096:
                        block = flood.recv(4096 - len(echoed))
                        assert block
                        echoed.extend(block)
                    assert echoed == b"Z" * 4096
                wait_for(log, process,
                         lambda s: "TLS read limit reached:" in s and "total=65536" in s)
            finally:
                flood.close()
            print("PASS: 64 KiB per-client application-data cap enforced")

            # Abruptly disconnected clients must not terminate the process.
            with open_tls(port, context) as abrupt:
                abrupt.sendall(b"disconnect")
            with open_tls(port, context) as survivor:
                survivor.sendall(b"still here")
            wait_for(log, process,
                     lambda s: "hex=7374696c6c2068657265" in s)
            assert process.poll() is None
            print("PASS: abrupt disconnect does not affect subsequent readers")

            idle.close()
            idle = None
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=5) == 0, log_contents(log)
            assert "epoll TLS listener stopped" in log_contents(log)
            print("PASS: SIGTERM closes live SSL sessions and listener")
        finally:
            if secured is not None:
                secured.close()
            if idle is not None:
                idle.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="tls-gateway-phase22-") as temp:
        certs = Path(temp) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(certs)],
                       check=True, capture_output=True, timeout=25)
        test_reads(certs)
    print("PASS: epoll TLS application reads phase 22")
