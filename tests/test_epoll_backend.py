#!/usr/bin/env python3
"""Phase 25: real TLS clients trigger epoll-managed non-blocking TCP connects."""
import concurrent.futures
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / 'build' / 'tls-gateway'
HOST = '127.0.0.1'


def port_number():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def output(log):
    return os.pread(log.fileno(), 4_000_000, 0).decode(errors='replace')


def wait_for(log, proc, snippet, timeout=7):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = output(log)
        if snippet in data:
            return data
        assert proc.poll() is None, data
        time.sleep(0.03)
    raise AssertionError('Missing %r\n%s' % (snippet, output(log)))


class AcceptCounter:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((HOST, 0))
        self.listener.listen()
        self.listener.settimeout(0.15)
        self.port = self.listener.getsockname()[1]
        self.count = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.count += 1
            conn.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=3)


def start_gateway(certdir, port, upstream, log):
    args = [str(GATEWAY), '--epoll-tls-connect',
            str(certdir / 'server.crt'), str(certdir / 'server.key'),
            str(port), str(upstream)]
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    wait_for(log, proc, 'Non-blocking upstream connection lab enabled')
    return proc


def echo(ctx, port, payload):
    with socket.create_connection((HOST, port), timeout=5) as raw:
        raw.settimeout(5)
        with ctx.wrap_socket(raw, server_hostname='localhost') as client:
            client.sendall(payload)
            remaining = len(payload)
            received = bytearray()
            while remaining:
                data = client.recv(remaining)
                assert data, 'TLS echo connection ended early'
                received.extend(data)
                remaining -= len(data)
            assert bytes(received) == payload


def stop_gateway(proc, log):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
            raise
    assert proc.returncode == 0, output(log)


def main():
    with tempfile.TemporaryDirectory(prefix='tls-phase25-') as folder:
        certdir = Path(folder) / 'certs'
        subprocess.run(['bash', str(ROOT / 'scripts/generate_dev_certs.sh'),
                        str(certdir)], check=True, capture_output=True, timeout=30)
        ctx = ssl.create_default_context(cafile=str(certdir / 'ca.crt'))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with AcceptCounter() as upstream:
            port = port_number()
            with tempfile.TemporaryFile(mode='w+t') as log:
                gateway = start_gateway(certdir, port, upstream.port, log)
                stall = None
                try:
                    # A completed handshake must NOT initiate upstream yet.
                    with socket.create_connection((HOST, port), timeout=5) as raw:
                        with ctx.wrap_socket(raw, server_hostname='localhost'):
                            time.sleep(0.08)
                            assert upstream.count == 0
                    print('PASS: TLS handshakes alone do not open backend connections')
                    stall = socket.create_connection((HOST, port), timeout=5)
                    stall.sendall(b'\x16\x03')  # incomplete handshake
                    echo(ctx, port, b'hello-outbound\x00')
                    wait_for(log, gateway, 'Upstream connect succeeded')
                    assert upstream.count >= 1
                    print('PASS: connect EINPROGRESS -> epoll -> SO_ERROR=0 -> TLS echo')
                    def worker(n):
                        echo(ctx, port, ('client-%02d' % n).encode())
                        return n
                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                        assert list(pool.map(worker, range(20))) == list(range(20))
                    wait_for(log, gateway, 'BACKEND_CONNECTING -> WRITING')
                    assert upstream.count >= 21, (upstream.count, output(log))
                    assert gateway.poll() is None
                    print('PASS: 20 simultaneous TLS clients plus a stalled handshake')
                    stall.close()
                    stall = None
                finally:
                    if stall is not None:
                        stall.close()
                    stop_gateway(gateway, log)

        # An unused local port reliably triggers ECONNREFUSED via SO_ERROR.
        upstream_port = port_number()
        tls_port = port_number()
        with tempfile.TemporaryFile(mode='w+t') as log:
            gateway = start_gateway(certdir, tls_port, upstream_port, log)
            try:
                echo(ctx, tls_port, b'backend-down')
                wait_for(log, gateway, 'Upstream connect failed')
                assert 'Connection refused' in output(log)
                assert gateway.poll() is None
                print('PASS: refused backend is detected without crashing gateway')
            finally:
                stop_gateway(gateway, log)
        invalid = subprocess.run([str(GATEWAY), '--epoll-tls-connect',
                                  str(certdir / 'server.crt'), str(certdir / 'server.key'),
                                  str(tls_port), str(tls_port)], capture_output=True,
                                 timeout=5)
        assert invalid.returncode == 2
        print('PASS: rejects identical listener/upstream ports')


if __name__ == '__main__':
    main()
