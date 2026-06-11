#!/usr/bin/env python3
"""Phase 11: a TLS-context-backed TCP listener, without TLS handshake."""
import signal
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "build" / "tls-gateway"
GENERATOR = ROOT / "scripts" / "generate_dev_certs.sh"
HOST = "127.0.0.1"


def call(*args):
    return subprocess.run([str(PROGRAM), *map(str, args)], capture_output=True,
                          text=True, timeout=10)


def available_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def connect_when_ready(port, process):
    for _ in range(60):
        if process.poll() is not None:
            raise AssertionError("Listener exited before accepting connections")
        try:
            return socket.create_connection((HOST, port), timeout=0.25)
        except OSError:
            time.sleep(0.05)
    raise AssertionError("Listener did not open its TCP port")


def main():
    with tempfile.TemporaryDirectory(prefix="tls-gateway-phase11-") as tmp:
        certs = Path(tmp) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(certs)], check=True,
                       capture_output=True, text=True, timeout=25)
        crt, key = certs / "server.crt", certs / "server.key"
        port = available_port()
        server = subprocess.Popen([str(PROGRAM), "--tls-listen",
                                   str(crt), str(key), str(port)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
        try:
            with connect_when_ready(port, server):
                pass
            with socket.create_connection((HOST, port), timeout=1):
                pass
            print("PASS: listener accepts repeated TCP clients on loopback")

            # The listener deliberately does not call SSL_accept() in Phase 11.
            client_context = ssl.create_default_context(cafile=str(certs / "ca.crt"))
            with socket.create_connection((HOST, port), timeout=2) as transport:
                transport.settimeout(2)
                try:
                    with client_context.wrap_socket(transport, server_hostname="localhost"):
                        raise AssertionError("TLS handshake must not succeed in Phase 11")
                except (ssl.SSLError, OSError):
                    pass
            print("PASS: no TLS handshake yet (intentional Phase 11 behavior)")

            server.send_signal(signal.SIGTERM)
            stdout, stderr = server.communicate(timeout=5)
            assert server.returncode == 0, (stdout, stderr)
            assert "TLS listener ready" in stdout and "TLS listener stopped" in stdout
            print("PASS: clean SIGTERM shutdown and socket cleanup")
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate(timeout=5)

        # A mismatched key and invalid command arguments must fail cleanly.
        mismatch = call("--tls-listen", crt, certs / "ca.key", port)
        assert mismatch.returncode != 0 and "invalid TLS configuration" in mismatch.stderr
        missing = call("--tls-listen", certs / "absent.crt", key, port)
        assert missing.returncode != 0
        bad_port = call("--tls-listen", crt, key, 70000)
        assert bad_port.returncode == 2 and "invalid TLS listener port" in bad_port.stderr
        print("PASS: mismatch, missing certificate, and invalid port rejected")

        # Port collisions are reported, not silently ignored.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            held.bind((HOST, 0))
            held.listen(1)
            busy = held.getsockname()[1]
            collision = call("--tls-listen", crt, key, busy)
            assert collision.returncode != 0
            assert "TLS listener socket setup" in collision.stderr
        print("PASS: occupied listener port rejected")


if __name__ == "__main__":
    main()
