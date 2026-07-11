#!/usr/bin/env python3
"""Profile LOCAL HTTPS gateway across client concurrency levels (Linux /proc).

Reuses Phase 41's verified TLS 1.3 benchmark. Requires an existing gateway
process PID; it does not launch or alter gateway/backend services.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import sys
import threading
import time
from types import SimpleNamespace

import https_bench


class ProcessSampler:
    """Best-effort periodic /proc sampler; failures terminate the measurement."""

    def __init__(self, pid, interval):
        self.pid = pid
        self.interval = interval
        self.stop_event = threading.Event()
        self.thread = None
        self.samples = []
        self.error = None
        self.hz = os.sysconf("SC_CLK_TCK")
        self.initial = self.read()
        self.start_time = self.initial["start_ticks"]

    def read(self):
        # /proc/PID/stat field 2 (comm) can contain spaces and parentheses.
        text = Path(f"/proc/{self.pid}/stat").read_text(encoding="ascii")
        right = text.rfind(")")
        if right < 0:
            raise ValueError("malformed /proc/PID/stat")
        fields = text[right + 2:].split()  # field 3 is index 0
        if len(fields) < 20:
            raise ValueError("incomplete /proc/PID/stat")
        ticks = int(fields[11]) + int(fields[12])  # utime + stime: fields 14, 15
        start_ticks = int(fields[19])  # field 22, detects PID reuse
        status = Path(f"/proc/{self.pid}/status").read_text(encoding="ascii")
        rss = next((int(line.split()[1]) for line in status.splitlines()
                    if line.startswith("VmRSS:")), 0)
        fds = len(os.listdir(f"/proc/{self.pid}/fd"))
        return {"ticks": ticks, "start_ticks": start_ticks, "rss_kib": rss, "fds": fds}

    def collect(self):
        try:
            sample = self.read()
            if sample["start_ticks"] != self.start_time:
                raise RuntimeError("process PID was reused during profiling")
            self.samples.append(sample)
        except (OSError, ValueError, RuntimeError) as exc:
            self.error = exc
            self.stop_event.set()

    def loop(self):
        while not self.stop_event.wait(self.interval):
            self.collect()

    def start(self):
        self.samples.append(self.initial)
        self.thread = threading.Thread(target=self.loop, name="proc-sampler", daemon=True)
        self.thread.start()

    def finish(self, elapsed):
        self.stop_event.set()
        self.thread.join(timeout=2)
        if self.error:
            raise RuntimeError(f"process sampling failed: {self.error}") from self.error
        self.collect()
        if self.error:
            raise RuntimeError(f"process sampling failed: {self.error}") from self.error
        last = self.samples[-1]
        first = self.samples[0]
        cpu_seconds = (last["ticks"] - first["ticks"]) / self.hz
        return {
            "cpu_seconds": round(cpu_seconds, 4),
            "cpu_percent_one_core_100": round(100 * cpu_seconds / max(elapsed, 1e-9), 2),
            "max_rss_kib": max(s["rss_kib"] for s in self.samples),
            "max_open_fds": max(s["fds"] for s in self.samples),
            "baseline_rss_kib": first["rss_kib"],
            "baseline_open_fds": first["fds"],
            "final_open_fds": last["fds"],
            "samples": len(self.samples),
        }


def run_one(args, concurrency):
    kwargs = vars(args).copy()
    kwargs["concurrency"] = concurrency
    kwargs["warmup"] = 0
    run_args = SimpleNamespace(**kwargs)
    if args.warmup:
        warm_args = SimpleNamespace(**{**kwargs, "requests": args.warmup})
        warm = https_bench.run(warm_args)
        if warm["failed_requests"]:
            raise RuntimeError(f"warmup failed for concurrency={concurrency}: {warm['errors']}")

    sampler = ProcessSampler(args.pid, args.sample_interval)
    sampler.start()
    started = time.perf_counter()
    try:
        results = https_bench.run(run_args)
    finally:
        elapsed = time.perf_counter() - started
        resources = sampler.finish(elapsed)
    return {"concurrency": concurrency, "requests": results["successful_requests"] + results["failed_requests"],
            "rps": results["successful_rps"], "latency_ms": results["latency_ms"],
            "errors": results["errors"], "failed_requests": results["failed_requests"],
            "elapsed_seconds": results["elapsed_seconds"], "resources": resources}


def parse_levels(text):
    try:
        levels = [int(item.strip()) for item in text.split(",")]
    except ValueError as exc:
        raise ValueError("concurrency values must be integers") from exc
    if not levels or len(levels) > 8 or len(set(levels)) != len(levels) or any(n < 1 or n > 64 for n in levels):
        raise ValueError("provide 1-8 unique concurrency levels from 1 to 64")
    return levels


def main():
    parser = argparse.ArgumentParser(description="LOCAL verified TLS concurrency + /proc gateway profiler")
    parser.add_argument("--pid", type=int, required=True, help="PID of the already-running C gateway")
    parser.add_argument("--levels", default="1,4,8,16", help="comma-separated concurrency, max 64")
    parser.add_argument("--requests", type=int, default=100, help="requests at EACH concurrency level")
    parser.add_argument("--warmup", type=int, default=10, help="untimed warmup requests per level")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=18444)
    parser.add_argument("--ca", type=Path, default=Path("certs/ca.crt"))
    parser.add_argument("--path", default="/health")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--expect-status", type=int, default=200)
    parser.add_argument("--expect-body", default=r"ok\n")
    parser.add_argument("--sample-interval", type=float, default=0.02, help="/proc sampling period in seconds")
    parser.add_argument("--json-out", type=Path, default=Path("bench_results/phase42-profile.json"))
    args = parser.parse_args()
    try:
        levels = parse_levels(args.levels)
    except ValueError as exc:
        parser.error(str(exc))
    if (platform.system() != "Linux" or args.pid <= 0 or args.host not in ("localhost", "api.test")
            or not 1 <= args.port <= 65535 or not 1 <= args.requests <= 100000
            or not 0 <= args.warmup <= 10000 or not 0 < args.timeout <= 60
            or not 0.005 <= args.sample_interval <= 1
            or not 100 <= args.expect_status <= 599 or not args.ca.is_file()
            or not args.path.startswith("/") or len(args.path) > 1024
            or any(c in args.path for c in "\r\n \t")):
        parser.error("invalid configuration or missing CA file (Linux local gateway only)")
    try:
        # Validates /proc permissions and process existence before making requests.
        ProcessSampler(args.pid, args.sample_interval)
        output = []
        for n in levels:
            item = run_one(args, n)
            output.append(item)
            r = item["resources"]
            lat = item["latency_ms"] or {}
            print(f"c={n:>2} RPS={item['rps']:>8.2f} p95={lat.get('p95', 'n/a')} ms "
                  f"CPU={r['cpu_percent_one_core_100']:>6.1f}% "
                  f"RSS_peak={r['max_rss_kib']} KiB FD_peak={r['max_open_fds']} "
                  f"failed={item['failed_requests']}")
        report = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "environment": {"kernel": platform.release(), "python": platform.python_version(),
                            "logical_cpus": os.cpu_count()},
            "method": "new verified TLS 1.3 connection per request; /proc sampled gateway process",
            "pid": args.pid, "requests_per_level": args.requests,
            "warmup_per_level": args.warmup, "sample_interval_seconds": args.sample_interval,
            "levels": output,
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Saved: {args.json_out}")
        return 1 if any(item["failed_requests"] for item in output) else 0
    except (OSError, ValueError, RuntimeError, ssl.SSLError) as exc:
        print(f"PROFILE ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
