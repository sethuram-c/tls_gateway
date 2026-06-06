#!/usr/bin/env python3
"""Black-box verification of gateway outbound connect(), using a loopback listener."""
import socket
import subprocess
from pathlib import Path

BINARY = Path(__file__).resolve().parents[1] / "build" / "tls-gateway"
HOST = "127.0.0.1"


def run(port):
    return subprocess.run([str(BINARY), "--backend-connect", str(port)],
                          capture_output=True, text=True, timeout=3)


def main():
    # Keep the listener open while the gateway tries to connect.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((HOST, 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        result = run(port)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert "Backend TCP connection established" in result.stdout
        client, _ = listener.accept()
        with client:
            # Phase 6 must not emit HTTP data or act like a proxy.
            client.settimeout(1)
            assert client.recv(1) == b""

    for invalid in ("0", "65536", "abc", "-1", "80oops"):
        result = subprocess.run([str(BINARY), "--backend-connect", invalid],
                                capture_output=True, text=True, timeout=3)
        assert result.returncode == 2, (invalid, result.stdout, result.stderr)

    # Binding and closing a loopback listener leaves a likely-unused port.
    with socket.socket() as temp:
        temp.bind((HOST, 0))
        closed_port = temp.getsockname()[1]
    result = run(closed_port)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "connect:" in result.stderr
    print("PASS: backend connect, close, invalid ports, refused connection")


if __name__ == "__main__":
    main()
