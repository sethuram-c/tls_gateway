#!/usr/bin/env python3
"""Phase 29: strict SNI/certificate validation matrix against the real C proxy.

No production CA or global trust changes: all certificates live in temp folders.
"""
import concurrent.futures
import hashlib
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

from test_epoll_tls_proxy import (BACKEND, HOST, PROGRAM, launch, stop,
                                  unused_port)

ROOT = Path(__file__).resolve().parents[1]
GEN_CA = ROOT / "scripts" / "generate_dev_certs.sh"
GEN_ALT = ROOT / "scripts" / "generate_sni_cert.sh"


def generate(script, destination):
    subprocess.run(["bash", str(script), str(destination)],
                   check=True, capture_output=True, timeout=30)


def trusted_context(ca):
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context


def expected_digest(cert):
    der = ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))
    return hashlib.sha256(der).hexdigest()


def request(context, port, server_name, host_header="localhost"):
    """Return exact leaf fingerprint and HTTPS response after validated TLS.

    The *context* determines whether CA and hostname validation is required.
    """
    with socket.create_connection((HOST, port), timeout=5) as tcp:
        tcp.settimeout(5)
        with context.wrap_socket(tcp, server_hostname=server_name) as tls:
            assert tls.version() == "TLSv1.3"
            peer = tls.getpeercert(binary_form=True)
            assert peer
            tls.sendall((f"GET /health HTTP/1.1\r\nHost: {host_header}\r\n"
                         "Connection: close\r\n\r\n").encode("ascii"))
            response = bytearray()
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
            return hashlib.sha256(peer).hexdigest(), bytes(response)


def expect_tls_rejection(context, port, host):
    try:
        request(context, port, host)
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
        return
    raise AssertionError(f"TLS connection should have been rejected: {host!r}")


def assert_ok(payload):
    assert payload.startswith(b"HTTP/1.1 200"), payload
    assert payload.endswith(b"\r\n\r\nok\n"), payload


def main():
    with tempfile.TemporaryDirectory(prefix="phase29-") as temp:
        root = Path(temp)
        certs = root / "certs"
        foreign = root / "foreign-certs"
        generate(GEN_CA, certs)
        generate(GEN_ALT, certs)
        generate(GEN_CA, foreign)  # A separate CA; it must NOT trust our gateway.

        good = trusted_context(certs / "ca.crt")
        wrong_ca = trusted_context(foreign / "ca.crt")
        local_digest = expected_digest(certs / "server.crt")
        api_digest = expected_digest(certs / "api.test.crt")
        assert local_digest != api_digest

        # An otherwise valid CA-signed certificate must still fail when its
        # SAN does not match the expected hostname. Verify this explicitly,
        # instead of allowing the SNI callback to conceal the mismatch.
        for cert, wrong_hostname in ((certs / "server.crt", "api.test"),
                                     (certs / "api.test.crt", "localhost")):
            result = subprocess.run(
                ["openssl", "verify", "-purpose", "sslserver", "-CAfile",
                 str(certs / "ca.crt"), "-verify_hostname", wrong_hostname,
                 str(cert)], capture_output=True, timeout=5)
            assert result.returncode != 0, (cert, wrong_hostname, result.stdout)
        print("PASS: cross-hostname certificate verification rejects wrong SAN")

        # Unverified TLS is used *only* to distinguish server-side SNI rejection
        # from a client-side certificate verification failure.
        diagnostic = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        diagnostic.check_hostname = False
        diagnostic.verify_mode = ssl.CERT_NONE
        diagnostic.minimum_version = diagnostic.maximum_version = ssl.TLSVersion.TLSv1_3

        # Trust the CA without giving Python a name to check. This is a
        # controlled inspection of the no-SNI default, NOT a secure client mode.
        no_sni = trusted_context(certs / "ca.crt")
        no_sni.check_hostname = False

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

                for hostname, expected in (("localhost", local_digest),
                                           ("api.test", api_digest),
                                           ("API.TEST", api_digest)):
                    digest, payload = request(good, proxy_port, hostname, hostname)
                    assert digest == expected, (hostname, digest, expected)
                    assert_ok(payload)
                print("PASS: strict TLS hostname verification and exact leaf cert selection")

                # SNI and HTTP Host are not equivalent. Changing Host after the
                # handshake must not change which certificate was presented.
                digest, payload = request(good, proxy_port, "api.test", "localhost")
                assert digest == api_digest
                assert_ok(payload)
                print("PASS: HTTP Host cannot override SNI certificate selection")

                digest, payload = request(no_sni, proxy_port, None)
                assert digest == local_digest
                assert_ok(payload)
                digest, payload = request(good, proxy_port, "127.0.0.1")
                assert digest == local_digest
                assert_ok(payload)
                print("PASS: absent SNI defaults to localhost; IP SAN verifies")

                expect_tls_rejection(wrong_ca, proxy_port, "api.test")
                print("PASS: untrusted CA rejects otherwise correct hostname")

                # Unlike the trusted context, this test cannot fail merely due
                # to mismatched hostname / CA. The server must reject unknown SNI.
                expect_tls_rejection(diagnostic, proxy_port, "unknown.test")
                print("PASS: server rejects unknown DNS SNI with verification disabled")

                # A partial handshake should not block the event loop or cross-
                # contaminate concurrent certificate selection across clients.
                with socket.create_connection((HOST, proxy_port), timeout=5) as stalled:
                    stalled.sendall(b"\x16\x03")
                    def check(n):
                        hostname = "localhost" if n % 2 == 0 else "api.test"
                        expected = local_digest if n % 2 == 0 else api_digest
                        digest, payload = request(good, proxy_port, hostname, hostname)
                        assert digest == expected
                        assert_ok(payload)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                        list(pool.map(check, range(20)))
                print("PASS: 20 mixed-SNI clients while another handshake stalls")
            finally:
                stop(proxy)
                stop(backend, expected_signal=True)


if __name__ == "__main__":
    main()
