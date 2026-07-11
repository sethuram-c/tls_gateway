#!/usr/bin/env python3
"""Phase 42: exercise a real gateway with the Linux resource profiler."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile

from test_https_benchmark import free_port, start, stop

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "build" / "tls-gateway"
BACKEND = ROOT / "tests" / "http_backend.py"
CERT_GENERATOR = ROOT / "scripts" / "generate_dev_certs.sh"
PROFILER = ROOT / "bench" / "concurrency_profile.py"


def main():
    with tempfile.TemporaryDirectory(prefix="phase42-profile-") as tmp:
        directory = Path(tmp)
        certs = directory / "certs"
        subprocess.run(["bash", str(CERT_GENERATOR), str(certs)], check=True,
                       capture_output=True, timeout=25)
        gateway_port = free_port()
        backend_port = free_port()
        while backend_port == gateway_port:
            backend_port = free_port()
        with tempfile.TemporaryFile() as backend_log, tempfile.TemporaryFile() as gateway_log:
            backend = gateway = None
            try:
                backend = start([sys.executable, str(BACKEND), "--port", str(backend_port)],
                                backend_log, "Python HTTP backend listening")
                gateway = start([str(GATEWAY), "--epoll-tls-proxy", str(certs / "server.crt"),
                                 str(certs / "server.key"), str(gateway_port), str(backend_port)],
                                gateway_log, "epoll TLS proxy ready")
                output = directory / "profile.json"
                command = [sys.executable, str(PROFILER), "--pid", str(gateway.pid),
                           "--port", str(gateway_port), "--ca", str(certs / "ca.crt"),
                           "--levels", "1,4,8", "--requests", "18", "--warmup", "2",
                           "--sample-interval", "0.01", "--json-out", str(output)]
                proc = subprocess.run(command, capture_output=True, text=True, timeout=45)
                assert proc.returncode == 0, (proc.stdout, proc.stderr)
                stats = json.loads(output.read_text())
                assert [x["concurrency"] for x in stats["levels"]] == [1, 4, 8]
                for value in stats["levels"]:
                    res = value["resources"]
                    assert value["requests"] == 18 and value["failed_requests"] == 0
                    assert value["rps"] > 0
                    assert value["latency_ms"]["p50"] <= value["latency_ms"]["p95"] <= value["latency_ms"]["p99"]
                    assert res["cpu_seconds"] >= 0
                    assert res["max_rss_kib"] > 0
                    assert res["max_open_fds"] >= res["baseline_open_fds"] >= 1
                    assert res["samples"] >= 2
                print("PASS: concurrency 1/4/8, verified TLS requests, RPS and latency")
                print("PASS: gateway /proc CPU, peak RSS, FD counts and JSON schema")

                bad_args = command.copy()
                bad_args[3] = "999999999"
                bad = subprocess.run(bad_args, capture_output=True, text=True, timeout=6)
                assert bad.returncode != 0 and "PROFILE ERROR" in bad.stderr
                bad_levels = subprocess.run(command + ["--levels", "1,1"],
                                            capture_output=True, text=True, timeout=6)
                assert bad_levels.returncode != 0 and "unique" in bad_levels.stderr
                print("PASS: missing process and duplicate concurrency are rejected")
            finally:
                stop(gateway)
                stop(backend)


if __name__ == "__main__":
    main()
