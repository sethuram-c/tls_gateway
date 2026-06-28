#!/usr/bin/env python3
"""Phase 28: two certs, selected by SNI in OpenSSL's servername callback."""
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

from test_epoll_tls_proxy import (BACKEND, HOST, PROGRAM, launch, stop,
                                  unused_port, wait_log)

ROOT = Path(__file__).resolve().parents[1]


def certificate_for(context, port, hostname):
    with socket.create_connection((HOST, port), timeout=5) as tcp:
        tcp.settimeout(5)
        with context.wrap_socket(tcp, server_hostname=hostname) as tls:
            assert tls.version() == "TLSv1.3"
            peer = tls.getpeercert()
            request = (f"GET /health HTTP/1.1\r\nHost: {hostname or 'localhost'}\r\n"
                       "Connection: close\r\n\r\n").encode()
            tls.sendall(request)
            response = bytearray()
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
            assert b"HTTP/1.1 200 OK" in response, response
            assert response.endswith(b"ok\n"), response
            return peer


def rejected(context, port, hostname):
    try:
        certificate_for(context, port, hostname)
    except (ssl.SSLError, ConnectionResetError):
        return
    raise AssertionError(f"unexpectedly accepted SNI/hostname {hostname!r}")


def main():
    with tempfile.TemporaryDirectory(prefix="phase28-") as folder:
        certs = Path(folder) / "certs"
        for script in ("generate_dev_certs.sh", "generate_sni_cert.sh"):
            subprocess.run(["bash", str(ROOT / "scripts" / script), str(certs)],
                           capture_output=True, check=True, timeout=30)
        ca = str(certs / "ca.crt")
        verified = ssl.create_default_context(cafile=ca)
        verified.minimum_version = verified.maximum_version = ssl.TLSVersion.TLSv1_3

        proxy_port, backend_port = unused_port(), unused_port()
        while proxy_port == backend_port:
            backend_port = unused_port()
        cmd = [str(PROGRAM), "--epoll-tls-proxy",
               str(certs / "server.crt"), str(certs / "server.key"),
               str(proxy_port), str(backend_port),
               str(certs / "api.test.crt"), str(certs / "api.test.key")]
        with tempfile.TemporaryFile() as backend_log, tempfile.TemporaryFile() as proxy_log:
            backend = launch(["python3", str(BACKEND), "--port", str(backend_port)],
                             backend_log, "Python HTTP backend listening")
            proxy = None
            try:
                proxy = launch(cmd, proxy_log, "epoll TLS proxy ready")
                default = certificate_for(verified, proxy_port, "localhost")
                assert ("DNS", "localhost") in default["subjectAltName"]
                assert ("DNS", "api.test") not in default["subjectAltName"]
                print("PASS: SNI localhost => verified localhost certificate and HTTP 200")

                alternate = certificate_for(verified, proxy_port, "api.test")
                assert ("DNS", "api.test") in alternate["subjectAltName"]
                assert ("DNS", "localhost") not in alternate["subjectAltName"]
                wait_log(proxy, proxy_log, "TLS client SNI: api.test (selected api.test certificate)")
                print("PASS: SNI api.test => verified alternate certificate and HTTP 200")

                # SNI match is case-insensitive; certificate hostname rules also are.
                certificate_for(verified, proxy_port, "API.TEST")
                print("PASS: hostname case-insensitive routing")

                # Clients without SNI may use the default certificate, but still verify it.
                no_sni = ssl.create_default_context(cafile=ca)
                no_sni.check_hostname = False  # Only this no-SNI experiment.
                no_sni.minimum_version = no_sni.maximum_version = ssl.TLSVersion.TLSv1_3
                absent = certificate_for(no_sni, proxy_port, None)
                assert ("DNS", "localhost") in absent["subjectAltName"]
                print("PASS: no SNI => default certificate")

                rejected(no_sni, proxy_port, "unknown.test")
                # Hostname checks are OFF in no_sni context, so this proves
                # the SERVER rejected unknown SNI instead of falling back.
                wait_log(proxy, proxy_log, "TLS client SNI: api.test")
                print("PASS: unsupported SNI is rejected during handshake")

                ip_cert = certificate_for(verified, proxy_port, "127.0.0.1")
                assert ("IP Address", "127.0.0.1") in ip_cert["subjectAltName"]
                print("PASS: IP-address connection verifies default IP SAN without SNI")

                # Verify that this did not kill the event loop.
                certificate_for(verified, proxy_port, "api.test")
                print("PASS: connections succeed after rejected SNI")
            finally:
                stop(proxy)
                stop(backend, expected_signal=True)

        # Invalid alternate key/certificate must fail before listening.
        bad = subprocess.run([str(PROGRAM), "--epoll-tls-proxy",
                              str(certs / "server.crt"), str(certs / "server.key"),
                              str(unused_port()), str(unused_port()),
                              str(certs / "api.test.crt"), str(certs / "server.key")],
                             capture_output=True, timeout=5)
        assert bad.returncode != 0
        print("PASS: mismatched alternate private key fails startup")


if __name__ == "__main__":
    main()
