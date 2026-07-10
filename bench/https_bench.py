#!/usr/bin/env python3
"""Loopback HTTPS benchmark: verified TLS 1.3, one GET per new connection.

Reports completed responses per wall-clock second and latency percentiles.
Run only against the local development gateway, never against public targets.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import socket
import ssl
import sys
import time

MAX_RESPONSE = 1024 * 1024


def percentile(values, pct):
    """Nearest-rank percentile of non-empty sorted sample values."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * pct / 100) - 1)]


def fetch(context, connect_host, hostname, port, path, timeout, expected_status, expected_body):
    """Complete a single TCP + TLS + HTTP request; never reuse the socket."""
    started = time.perf_counter_ns()
    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as tcp:
            tcp.settimeout(timeout)
            with context.wrap_socket(tcp, server_hostname=hostname) as tls:
                if tls.version() != "TLSv1.3":
                    raise ValueError("negotiated protocol is not TLS 1.3")
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {hostname}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                tls.sendall(request)
                chunks = bytearray()
                while True:
                    data = tls.recv(16384)
                    if not data:
                        break
                    chunks.extend(data)
                    if len(chunks) > MAX_RESPONSE:
                        raise ValueError("response exceeds 1 MiB benchmark limit")
        header, sep, body = bytes(chunks).partition(b"\r\n\r\n")
        if not sep:
            raise ValueError("HTTP response headers missing")
        status_line = header.split(b"\r\n", 1)[0].split(b" ")
        if len(status_line) < 2 or status_line[0] != b"HTTP/1.1":
            raise ValueError("unexpected HTTP response status line")
        status = int(status_line[1])
        if status != expected_status:
            raise ValueError(f"HTTP status {status}, expected {expected_status}")
        if body != expected_body:
            raise ValueError(f"body mismatch ({len(body)} bytes)")
        return {"latency_ms": (time.perf_counter_ns() - started) / 1e6, "error": None}
    except (OSError, ValueError, UnicodeError, ssl.SSLError) as exc:
        return {"latency_ms": None, "error": f"{type(exc).__name__}: {str(exc)[:120]}"}


def run(args):
    context = ssl.create_default_context(cafile=str(args.ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    body = args.expect_body.encode("utf-8").replace(b"\\n", b"\n")
    operation = lambda: fetch(context, "127.0.0.1", args.host, args.port, args.path,
                              args.timeout, args.expect_status, body)
    for _ in range(args.warmup):
        result = operation()
        if result["error"] is not None:
            raise RuntimeError("warmup failed: " + result["error"])

    wall_start = time.perf_counter()
    samples = []
    errors = Counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for future in as_completed(pool.submit(operation) for _ in range(args.requests)):
            result = future.result()
            if result["error"]:
                errors[result["error"]] += 1
            else:
                samples.append(result["latency_ms"])
    elapsed = max(time.perf_counter() - wall_start, 1e-9)
    latency = None
    if samples:
        latency = {
            "min": round(min(samples), 3),
            "mean": round(sum(samples) / len(samples), 3),
            "p50": round(percentile(samples, 50), 3),
            "p95": round(percentile(samples, 95), 3),
            "p99": round(percentile(samples, 99), 3),
            "max": round(max(samples), 3),
        }
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": {"system": platform.system(), "release": platform.release(),
                        "python": platform.python_version(), "logical_cpus": os.cpu_count()},
        "configuration": {"connect_host": "127.0.0.1", "tls_hostname": args.host,
                          "port": args.port, "path": args.path, "requests": args.requests,
                          "warmup": args.warmup, "concurrency": args.concurrency,
                          "new_connection_per_request": True, "tls": "1.3", "certificate_verification": True},
        "elapsed_seconds": round(elapsed, 4),
        "successful_requests": len(samples),
        "failed_requests": sum(errors.values()),
        "successful_rps": round(len(samples) / elapsed, 2),
        "latency_ms": latency,
        "errors": dict(errors.most_common(5)),
    }


def main():
    parser = argparse.ArgumentParser(description="Verified loopback TLS 1.3 /health benchmark")
    parser.add_argument("--host", default="localhost", help="TLS SNI + verified certificate hostname")
    parser.add_argument("--port", type=int, default=18444)
    parser.add_argument("--ca", type=Path, default=Path("certs/ca.crt"))
    parser.add_argument("--path", default="/health")
    parser.add_argument("--requests", type=int, default=100, help="measured requests")
    parser.add_argument("--concurrency", type=int, default=4, help="simultaneous client workers")
    parser.add_argument("--warmup", type=int, default=10, help="untimed requests")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-socket operation timeout")
    parser.add_argument("--expect-status", type=int, default=200)
    parser.add_argument("--expect-body", default=r"ok\n", help="literal expected body; \\n means newline")
    parser.add_argument("--json-out", type=Path, help="optional result path; do not commit machine-specific data")
    args = parser.parse_args()
    if args.host not in ("localhost", "api.test"):
        parser.error("--host must be localhost or api.test (local development only)")
    if not (1 <= args.port <= 65535 and 1 <= args.requests <= 100000
            and 1 <= args.concurrency <= 64 and 0 <= args.warmup <= 10000
            and 0 < args.timeout <= 60 and 100 <= args.expect_status <= 599):
        parser.error("invalid port/request/concurrency/warmup/timeout/status setting")
    if not args.path.startswith("/") or any(c in args.path for c in "\r\n \t") or len(args.path) > 1024:
        parser.error("--path must be a short origin-form path without whitespace")
    if not args.ca.is_file():
        parser.error(f"CA file not found: {args.ca}")
    try:
        result = run(args)
    except (OSError, ssl.SSLError, RuntimeError, ValueError) as exc:
        print(f"BENCH ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Requests: {result['successful_requests']}/{args.requests} OK, "
          f"{result['failed_requests']} failed | elapsed={result['elapsed_seconds']:.3f}s | "
          f"RPS={result['successful_rps']:.2f}")
    if result["latency_ms"]:
        lat = result["latency_ms"]
        print(f"Latency (ms): mean={lat['mean']:.3f} p50={lat['p50']:.3f} "
              f"p95={lat['p95']:.3f} p99={lat['p99']:.3f} max={lat['max']:.3f}")
    for error, count in result["errors"].items():
        print(f"ERROR x{count}: {error}")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Result saved: {args.json_out}")
    return 1 if result["failed_requests"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
