#!/usr/bin/env python3
"""Phase 27: generate two SAN certificates and observe SNI (no routing yet)."""
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

from test_epoll_tls_proxy import (PROGRAM, BACKEND, HOST, unused_port,
                                  launch, stop, wait_log)

ROOT = Path(__file__).resolve().parents[1]
BASE_CERTS = ROOT / "scripts" / "generate_dev_certs.sh"
SNI_CERT = ROOT / "scripts" / "generate_sni_cert.sh"


def tls_request(ctx, port, hostname):
    with socket.create_connection((HOST, port), timeout=5) as sock:
        sock.settimeout(5)
        with ctx.wrap_socket(sock, server_hostname=hostname) as client:
            assert client.version() == "TLSv1.3"
            cert = client.getpeercert()
            request = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            client.sendall(request)
            response = bytearray()
            while True:
                block = client.recv(4096)
                if not block:
                    break
                response.extend(block)
            assert b"HTTP/1.1 200 OK" in response and response.endswith(b"ok\n"), response
            return cert


def run_cert_generator(cmd):
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=25, check=True)


def main():
    with tempfile.TemporaryDirectory(prefix="phase27-") as temp:
        directory = Path(temp) / "certs"
        run_cert_generator(["bash", str(BASE_CERTS), str(directory)])
        run_cert_generator(["bash", str(SNI_CERT), str(directory)])
        run_cert_generator(["openssl", "verify", "-CAfile", str(directory / "ca.crt"),
                            "-purpose", "sslserver", "-verify_hostname", "api.test",
                            str(directory / "api.test.crt")])
        mismatch = subprocess.run(["openssl", "verify", "-CAfile", str(directory / "ca.crt"),
                                   "-verify_hostname", "localhost",
                                   str(directory / "api.test.crt")],
                                  capture_output=True, timeout=5)
        assert mismatch.returncode != 0
        print("PASS: api.test SAN certificate signed by existing local CA")
        again = subprocess.run(["bash", str(SNI_CERT), str(directory)],
                               capture_output=True, timeout=5)
        assert again.returncode != 0
        assert (directory / "api.test.key").is_file()
        print("PASS: existing keys are not overwritten")

        ca = str(directory / "ca.crt")
        trusted = ssl.create_default_context(cafile=ca)
        trusted.minimum_version = trusted.maximum_version = ssl.TLSVersion.TLSv1_3
        observational = ssl.create_default_context(cafile=ca)
        observational.minimum_version = observational.maximum_version = ssl.TLSVersion.TLSv1_3
        observational.check_hostname = False  # ONLY to observe wrong cert in this lab.
        proxy_port, backend_port = unused_port(), unused_port()
        while backend_port == proxy_port:
            backend_port = unused_port()
        with tempfile.TemporaryFile() as backend_log, tempfile.TemporaryFile() as gateway_log:
            backend = launch(["python3", str(BACKEND), "--port", str(backend_port)],
                             backend_log, "Python HTTP backend listening")
            gateway = None
            try:
                gateway = launch([str(PROGRAM), "--epoll-tls-proxy",
                                  str(directory / "server.crt"),
                                  str(directory / "server.key"), str(proxy_port),
                                  str(backend_port)], gateway_log, "epoll TLS proxy ready")
                cert = tls_request(trusted, proxy_port, "localhost")
                assert ('DNS', 'localhost') in cert['subjectAltName']
                wait_log(gateway, gateway_log, "TLS client SNI: localhost")
                print("PASS: localhost SNI logged; verified default certificate")

                # The server still returns the localhost certificate for api.test.
                try:
                    tls_request(trusted, proxy_port, "api.test")
                except ssl.SSLCertVerificationError:
                    pass
                else:
                    raise AssertionError("api.test incorrectly matched default certificate")
                print("PASS: hostname verification rejects api.test on default certificate")
                cert = tls_request(observational, proxy_port, "api.test")
                assert ('DNS', 'localhost') in cert['subjectAltName']
                assert ('DNS', 'api.test') not in cert['subjectAltName']
                wait_log(gateway, gateway_log, "TLS client SNI: api.test")
                print("PASS: api.test SNI observed; NO certificate routing yet")

                tls_request(observational, proxy_port, None)
                wait_log(gateway, gateway_log, "TLS client SNI: (none)")
                print("PASS: client without SNI handled")
            finally:
                stop(gateway)
                stop(backend, expected_signal=True)


if __name__ == "__main__":
    main()
