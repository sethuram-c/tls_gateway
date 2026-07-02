#!/usr/bin/env python3
"""Phase 33: SIGHUP reload must be atomic, preserve live sessions and mTLS.

Only standard-library modules; disposable keys and local loopback sockets.
"""
import hashlib
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "build" / "tls-gateway"
BACKEND = ROOT / "tests" / "http_backend.py"


def cmd(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=30)


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def output(file):
    return os.pread(file.fileno(), 1000000, 0).decode(errors="replace")


def start(args, file, marker):
    p = subprocess.Popen(args, stdout=file, stderr=subprocess.STDOUT)
    end = time.monotonic() + 8
    while time.monotonic() < end:
        if marker in output(file):
            return p
        if p.poll() is not None:
            raise AssertionError(f"Unexpected exit: {output(file)}")
        time.sleep(0.025)
    p.terminate()
    raise AssertionError(f"Start timed out: {output(file)}")


def wait_log(file, needle, count=1):
    end = time.monotonic() + 6
    while time.monotonic() < end:
        if output(file).count(needle) >= count:
            return
        time.sleep(0.025)
    raise AssertionError(f"Missing {needle!r}: {output(file)}")


def stop(p):
    if p is None:
        return
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)


def ctx(certs, client=True):
    c = ssl.create_default_context(cafile=str(certs / "ca.crt"))
    c.minimum_version = c.maximum_version = ssl.TLSVersion.TLSv1_3
    if client:
        c.load_cert_chain(str(certs / "client.crt"), str(certs / "client.key"))
    return c


def open_tls(context, listen, hostname):
    sock = socket.create_connection(("127.0.0.1", listen), timeout=4)
    sock.settimeout(4)
    try:
        return context.wrap_socket(sock, server_hostname=hostname)
    except BaseException:
        sock.close()
        raise


def response(tls):
    out = bytearray()
    while True:
        piece = tls.recv(8192)
        if not piece:
            break
        out.extend(piece)
    assert b"HTTP/1.1 200" in out and out.endswith(b"ok\n"), out
    return bytes(out)


def fingerprint(tls):
    return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def check(context, listen, host):
    with open_tls(context, listen, host) as tls:
        fp = fingerprint(tls)
        tls.sendall((f"GET /health HTTP/1.1\r\nHost: {host}\r\n"
                     "Connection: close\r\n\r\n").encode())
        response(tls)
        return fp


def issue_replacement(certs, dest, name):
    """Sign a *new* private key / leaf cert with the same development CA."""
    dest.mkdir(exist_ok=True)
    key = dest / f"{name}.key"
    csr = dest / f"{name}.csr"
    ext = dest / f"{name}.ext"
    crt = dest / f"{name}.crt"
    cmd("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={name}")
    san = "DNS:localhost,IP:127.0.0.1" if name == "localhost" else "DNS:api.test"
    ext.write_text("basicConstraints=critical,CA:FALSE\n"
                   "keyUsage=critical,digitalSignature\n"
                   "extendedKeyUsage=serverAuth\n"
                   f"subjectAltName={san}\n")
    cmd("openssl", "x509", "-req", "-sha256", "-days", "7",
        "-in", str(csr), "-CA", str(certs / "ca.crt"),
        "-CAkey", str(certs / "ca.key"), "-set_serial",
        "0x" + os.urandom(12).hex(), "-extfile", str(ext), "-out", str(crt))
    cmd("openssl", "verify", "-CAfile", str(certs / "ca.crt"),
        "-purpose", "sslserver", "-verify_hostname", name, str(crt))
    return crt, key


def replace_pair(cert, key, newcert, newkey):
    os.replace(newcert, cert)
    os.replace(newkey, key)


def main():
    with tempfile.TemporaryDirectory(prefix="phase33-reload-") as tmp:
        work = Path(tmp)
        certs = work / "certs"
        for script in ("generate_dev_certs.sh", "generate_sni_cert.sh",
                       "generate_client_cert.sh"):
            cmd("bash", str(ROOT / "scripts" / script), str(certs))
        trusted = ctx(certs)
        no_identity = ctx(certs, client=False)
        listen, upstream = port(), port()
        while listen == upstream:
            upstream = port()
        args = [str(PROGRAM), "--epoll-tls-proxy-mtls",
                str(certs / "server.crt"), str(certs / "server.key"),
                str(listen), str(upstream), str(certs / "ca.crt"),
                str(certs / "api.test.crt"), str(certs / "api.test.key")]
        with tempfile.TemporaryFile() as blog, tempfile.TemporaryFile() as glog:
            backend = start(["python3", str(BACKEND), "--port", str(upstream)],
                            blog, "Python HTTP backend listening")
            gateway = None
            held = None
            try:
                gateway = start(args, glog, "mTLS mode: client certificate required")
                old_a = check(trusted, listen, "localhost")
                old_b = check(trusted, listen, "api.test")
                print("PASS: initial localhost and api.test certificates verified")
                # Client connects under old generation; deliberately send half a request.
                held = open_tls(trusted, listen, "api.test")
                assert fingerprint(held) == old_b
                held.sendall(b"GET /health HTTP/1.1\r\nHost: api.test\r\n")
                time.sleep(0.1)

                new = work / "new"
                new_a, new_a_key = issue_replacement(certs, new, "localhost")
                new_b, new_b_key = issue_replacement(certs, new, "api.test")
                replace_pair(certs / "server.crt", certs / "server.key", new_a, new_a_key)
                replace_pair(certs / "api.test.crt", certs / "api.test.key", new_b, new_b_key)
                gateway.send_signal(signal.SIGHUP)
                wait_log(glog, "TLS credentials reloaded successfully", 1)
                assert gateway.poll() is None
                new_fp_a = check(trusted, listen, "localhost")
                new_fp_b = check(trusted, listen, "api.test")
                assert old_a != new_fp_a and old_b != new_fp_b
                print("PASS: SIGHUP activates new certificates for both SNI names")

                # Existing TLS connection is still allowed to finish on old SSL_CTX.
                held.sendall(b"Connection: close\r\n\r\n")
                response(held)
                held.close()
                held = None
                print("PASS: in-flight old-generation TLS session finishes after reload")

                # Remove a credential temporarily. Reload must fail closed.
                missing = work / "withheld-server.key"
                os.replace(certs / "server.key", missing)
                gateway.send_signal(signal.SIGHUP)
                wait_log(glog, "TLS credential reload failed; keeping previous generation")
                assert check(trusted, listen, "localhost") == new_fp_a
                assert check(trusted, listen, "api.test") == new_fp_b
                print("PASS: broken replacement keeps last good certificates active")
                os.replace(missing, certs / "server.key")

                # A new client without identity must still be rejected after rotation.
                try:
                    with open_tls(no_identity, listen, "localhost") as tls:
                        tls.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        payload = tls.recv(4096)
                    assert b"200" not in payload, payload
                except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError):
                    pass
                print("PASS: mTLS policy survives reload")
                assert gateway.poll() is None
            finally:
                if held is not None:
                    held.close()
                stop(gateway)
                stop(backend)


if __name__ == "__main__":
    main()
