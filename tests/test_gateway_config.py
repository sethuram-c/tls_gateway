#!/usr/bin/env python3
"""Phase 34: strict key=value parsing + end-to-end config-driven HTTPS/mTLS.

No external Python packages, no persistent keys or changed system settings.
"""
from pathlib import Path
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build" / "tls-gateway"
BACKEND = ROOT / "tests" / "http_backend.py"


def command(*args):
    return subprocess.run(args, capture_output=True, check=True, timeout=40)


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def output(file):
    return os.pread(file.fileno(), 200000, 0).decode(errors="replace")


def start(args, file, expected, seconds=6):
    proc = subprocess.Popen(args, stdout=file, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"startup exited: {output(file)}")
        if expected in output(file):
            return proc
        time.sleep(0.03)
    stop(proc)
    raise AssertionError(f"startup timed out: {output(file)}")


def stop(proc):
    if proc is not None and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            raise AssertionError("server did not stop")


def cfg_text(listen, backend, certs, *, mtls=False, sni=False):
    text = (f"  # ignored comment\n listen_port = {listen}\n"
            f"backend_port = {backend}\n"
            f"server_cert = {certs / 'server.crt'}\n"
            f"server_key = {certs / 'server.key'}\n"
            f"require_mtls = {'true' if mtls else 'false'}\n")
    if sni:
        text += (f"api_cert = {certs / 'api.test.crt'}\n"
                 f"api_key = {certs / 'api.test.key'}\n")
    if mtls:
        text += f"client_ca = {certs / 'ca.crt'}\n"
    return text


def run_config(path, text, *, valid, error=""):
    path.write_text(text)
    result = subprocess.run([str(BINARY), "--check-config", str(path)],
                            capture_output=True, text=True, timeout=5)
    if valid:
        assert result.returncode == 0 and "Config OK:" in result.stdout, result
    else:
        assert result.returncode == 2 and error in result.stderr, result
    return result


def client_ctx(certs, *, mtls):
    ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if mtls:
        ctx.load_cert_chain(str(certs / "client.crt"), str(certs / "client.key"))
    return ctx


def request(context, listen, name):
    with socket.create_connection(("127.0.0.1", listen), timeout=4) as raw:
        raw.settimeout(4)
        with context.wrap_socket(raw, server_hostname=name) as tls:
            tls.sendall((f"GET /health HTTP/1.1\r\nHost: {name}\r\n"
                         "Connection: close\r\n\r\n").encode())
            data = bytearray()
            while True:
                chunk = tls.recv(8192)
                if not chunk:
                    return bytes(data)
                data.extend(chunk)


def main():
    with tempfile.TemporaryDirectory(prefix="phase34-config-") as temp:
        folder = Path(temp)
        certs = folder / "certs"
        for script in ("generate_dev_certs.sh", "generate_sni_cert.sh", "generate_client_cert.sh"):
            command("bash", str(ROOT / "scripts" / script), str(certs))
        listen, backend = port(), port()
        while listen == backend:
            backend = port()
        config = folder / "gateway.conf"
        base = cfg_text(listen, backend, certs)
        result = run_config(config, base, valid=True)
        assert "mTLS=off" in result.stdout and "default-only" in result.stdout
        print("PASS: comments, whitespace and valid default config")

        bad = {
            "unknown setting": (base + "keep_alive = yes\n", "unknown setting"),
            "duplicate": (base + "listen_port = 3456\n", "duplicate setting"),
            "missing required": (base.replace(f"backend_port = {backend}\n", ""), "missing required"),
            "invalid port": (base.replace(f"{listen}", "70000", 1), "invalid value"),
            "same port": (base.replace(f"backend_port = {backend}", f"backend_port = {listen}"), "must differ"),
            "broken syntax": (base + "not_an_assignment\n", "expected key = value"),
            "invalid boolean": (base.replace("require_mtls = false", "require_mtls = yes"), "invalid value"),
            "client CA without mTLS": (base + f"client_ca = {certs / 'ca.crt'}\n", "client_ca is invalid"),
            "missing client CA": (base.replace("require_mtls = false", "require_mtls = true"), "needs client_ca"),
            "unpaired SNI": (base + f"api_cert = {certs / 'api.test.crt'}\n", "must appear together"),
            "empty key path": (base.replace(f"server_key = {certs / 'server.key'}", "server_key =  "), "invalid value"),
            "huge line": (base + "#" + ("x" * 1100) + "\n", "oversized line"),
        }
        for label, (text, message) in bad.items():
            run_config(config, text, valid=False, error=message)
        assert subprocess.run([str(BINARY), "--check-config", str(folder / "missing")],
                              capture_output=True, timeout=5).returncode == 2
        print(f"PASS: {len(bad)} malformed configurations and missing file fail closed")

        # --check-config deliberately checks syntax, not certificate file contents.
        config.write_text(cfg_text(listen, backend, certs, sni=True, mtls=True))
        result = subprocess.run([str(BINARY), "--check-config", str(config)],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 0 and "mTLS=on" in result.stdout and "api.test" in result.stdout
        with tempfile.TemporaryFile() as blog, tempfile.TemporaryFile() as glog:
            backend_proc = start(["python3", str(BACKEND), "--port", str(backend)],
                                 blog, "Python HTTP backend listening")
            gateway = None
            try:
                gateway = start([str(BINARY), "--config", str(config)], glog,
                                "mTLS mode: client certificate required")
                trusted = client_ctx(certs, mtls=True)
                anonymous = client_ctx(certs, mtls=False)
                for name in ("localhost", "api.test"):
                    result = request(trusted, listen, name)
                    assert b"HTTP/1.1 200" in result and result.endswith(b"ok\n"), result
                try:
                    result = request(anonymous, listen, "localhost")
                except (ssl.SSLError, ConnectionError, EOFError, OSError):
                    pass
                else:
                    assert b"HTTP/1.1 200" not in result
                assert output(blog).count('"GET /health HTTP/1.1" 200') == 2
                print("PASS: config starts HTTPS proxy with SNI, mTLS and backend isolation")
            finally:
                stop(gateway)
                stop(backend_proc)

        with tempfile.TemporaryFile() as blog, tempfile.TemporaryFile() as glog:
            config.write_text(base)
            backend_proc = start(["python3", str(BACKEND), "--port", str(backend)],
                                 blog, "Python HTTP backend listening")
            gateway = None
            try:
                gateway = start([str(BINARY), "--config", str(config)], glog,
                                "epoll TLS proxy ready")
                result = request(client_ctx(certs, mtls=False), listen, "localhost")
                assert b"HTTP/1.1 200" in result and result.endswith(b"ok\n")
                print("PASS: default config enables regular one-way HTTPS proxy")
            finally:
                stop(gateway)
                stop(backend_proc)


if __name__ == "__main__":
    main()
