#!/usr/bin/env python3
"""Phase 41: exercise the benchmark against the real C TLS gateway."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "build" / "tls-gateway"
BACKEND = ROOT / "tests" / "http_backend.py"
CERT_GENERATOR = ROOT / "scripts" / "generate_dev_certs.sh"
BENCH = ROOT / "bench" / "https_bench.py"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start(command, logfile, ready):
    process = subprocess.Popen(command, stdout=logfile, stderr=subprocess.STDOUT)
    until = time.monotonic() + 8
    while time.monotonic() < until:
        text = os.pread(logfile.fileno(), 150_000, 0).decode(errors="replace")
        if ready in text:
            return process
        if process.poll() is not None:
            raise AssertionError(f"failed to start: {text}")
        time.sleep(0.03)
    process.terminate()
    process.wait(timeout=3)
    raise AssertionError(f"readiness timeout: {ready}")


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=7)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
            raise AssertionError("subprocess failed to exit")
    assert process.returncode in (0, -signal.SIGTERM), process.returncode


def main():
    with tempfile.TemporaryDirectory(prefix="phase41-bench-") as temporary:
        temporary = Path(temporary)
        certs = temporary / "certs"
        subprocess.run(["bash", str(CERT_GENERATOR), str(certs)],
                       capture_output=True, check=True, timeout=25)
        gateway_port = free_port()
        backend_port = free_port()
        while backend_port == gateway_port:
            backend_port = free_port()
        with tempfile.TemporaryFile() as backend_log, tempfile.TemporaryFile() as gateway_log:
            backend = None
            gateway = None
            try:
                backend = start([sys.executable, str(BACKEND), "--port", str(backend_port)],
                                backend_log, "Python HTTP backend listening")
                gateway = start([str(GATEWAY), "--epoll-tls-proxy", str(certs / "server.crt"),
                                 str(certs / "server.key"), str(gateway_port), str(backend_port)],
                                gateway_log, "epoll TLS proxy ready")
                output = temporary / "baseline.json"
                call = [sys.executable, str(BENCH), "--port", str(gateway_port),
                        "--ca", str(certs / "ca.crt"), "--requests", "24",
                        "--warmup", "3", "--concurrency", "4", "--json-out", str(output)]
                proc = subprocess.run(call, capture_output=True, text=True, timeout=25)
                assert proc.returncode == 0, (proc.stdout, proc.stderr)
                stats = json.loads(output.read_text())
                assert stats["successful_requests"] == 24, stats
                assert stats["failed_requests"] == 0, stats
                assert stats["successful_rps"] > 0, stats
                assert stats["latency_ms"]["p50"] <= stats["latency_ms"]["p95"]
                assert stats["latency_ms"]["p95"] <= stats["latency_ms"]["p99"]
                assert stats["configuration"]["certificate_verification"] is True
                print("PASS: 24 HTTPS requests; positive RPS, valid latency percentiles")

                wrong_body = subprocess.run(call[:-2] + ["--warmup", "0", "--expect-body", "wrong"],
                                            capture_output=True, text=True, timeout=25)
                assert wrong_body.returncode == 1, (wrong_body.stdout, wrong_body.stderr)
                assert "failed" in wrong_body.stdout
                print("PASS: incorrect body is counted as failed requests")

                missing_ca = subprocess.run([sys.executable, str(BENCH), "--ca",
                                             str(temporary / "absent.pem")],
                                            capture_output=True, text=True, timeout=5)
                assert missing_ca.returncode != 0 and "CA file not found" in missing_ca.stderr
                print("PASS: missing trusted CA fails closed")
            finally:
                stop(gateway)
                stop(backend)


if __name__ == "__main__":
    main()
