#!/usr/bin/env python3
"""Integration test: TCP accept, response, repeated connections, clean stop."""
import signal
import socket
import subprocess
import time
from pathlib import Path

BINARY = Path(__file__).resolve().parents[1] / "build" / "tls-gateway"
HOST, PORT = "127.0.0.1", 18080
REPLY = b"Hello from the C TCP server!\n"


def main():
    process = subprocess.Popen([str(BINARY), "--tcp-server"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise AssertionError(f"server exited early: {process.stderr.read()!r}")
            try:
                connection = socket.create_connection((HOST, PORT), timeout=0.2)
                connection.close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("server did not start")
        for _ in range(3):
            with socket.create_connection((HOST, PORT), timeout=2) as conn:
                conn.settimeout(2)
                data = bytearray()
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data.extend(chunk)
                assert bytes(data) == REPLY, data
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=3) == 0
        print("PASS: TCP accept, response, repeated clients, SIGTERM shutdown")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)

if __name__ == "__main__":
    main()
