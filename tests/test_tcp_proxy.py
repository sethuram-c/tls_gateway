#!/usr/bin/env python3
"""End-to-end HTTP over a byte-transparent local TCP proxy."""
import http.client
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def reserve_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def wait_for_port(port, process):
    for _ in range(70):
        if process.poll() is not None:
            raise AssertionError(f"process exited: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError(f"port {port} not listening")

def check(port, path, expected_status, expected_body):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request("GET", path, headers={"Connection": "close"})
    response = conn.getresponse()
    data = response.read()
    assert response.status == expected_status, (response.status, path)
    assert data == expected_body, (data, path)
    conn.close()

def main():
    backend_port, gateway_port = reserve_port(), reserve_port()
    while gateway_port == backend_port:
        gateway_port = reserve_port()
    backend = subprocess.Popen([sys.executable, "tests/http_backend.py", "--port", str(backend_port)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    gateway = None
    try:
        wait_for_port(backend_port, backend)
        gateway = subprocess.Popen([str(ROOT / "build/tls-gateway"), "--tcp-proxy", str(gateway_port), str(backend_port)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for_port(gateway_port, gateway)
        for _ in range(3):
            check(gateway_port, "/", 200, b"hello from python backend\n")
            check(gateway_port, "/health", 200, b"ok\n")
            check(gateway_port, "/unknown", 404, b"not found\n")
        gateway.terminate()
        gateway.wait(timeout=4)
        assert gateway.returncode == 0
        print("PASS: proxy forwards HTTP status/body, repeat clients, SIGTERM")
    finally:
        if gateway and gateway.poll() is None:
            gateway.kill(); gateway.wait()
        backend.terminate()
        try:
            backend.wait(timeout=3)
        except subprocess.TimeoutExpired:
            backend.kill(); backend.wait()

if __name__ == "__main__":
    main()
