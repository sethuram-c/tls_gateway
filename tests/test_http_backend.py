#!/usr/bin/env python3
"""Black-box integration tests: real HTTP requests over localhost sockets."""
import http.client
import socket
import subprocess
import sys
import time
from pathlib import Path

SCRIPT = Path(__file__).with_name("http_backend.py")
HOST = "127.0.0.1"


def get(port, path):
    conn = http.client.HTTPConnection(HOST, port, timeout=2)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read()
        return response.status, response.getheader("Content-Type"), body, response.getheader("Content-Length")
    finally:
        conn.close()


def main():
    # Reserve an OS-selected candidate. Release it before the child binds.
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen([sys.executable, str(SCRIPT), "--port", str(port)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(60):
            if process.poll() is not None:
                raise AssertionError(f"backend exited early: {process.stderr.read()!r}")
            try:
                with socket.create_connection((HOST, port), timeout=0.15):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("backend failed to listen")
        for path, status, expected in [
            ("/", 200, b"hello from python backend\n"),
            ("/health", 200, b"ok\n"),
            ("/missing", 404, b"not found\n"),
        ]:
            actual_status, content_type, body, length = get(port, path)
            assert actual_status == status, (path, actual_status)
            assert content_type == "text/plain; charset=utf-8", content_type
            assert body == expected, (path, body)
            assert length == str(len(body)), (path, length)
        # A second request shows the server continues accepting connections.
        assert get(port, "/health")[0] == 200
        print("PASS: Python HTTP backend routes, status, headers, repeated requests")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


if __name__ == "__main__":
    main()
