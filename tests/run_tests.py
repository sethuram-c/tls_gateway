#!/usr/bin/env python3
"""Small Linux/Python-stdlib runner for TLS gateway integration scripts.

Each script runs in its own process group. On a timeout, both the test and
any services it spawned within that group are terminated, not just the test.
"""

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


TEST_DIR = Path(__file__).resolve().parent
PROJECT_DIR = TEST_DIR.parent


def discover():
    """Run the historical smoke test first, then discover test_*.py scripts."""
    found = sorted(TEST_DIR.glob("test_*.py"))
    smoke = TEST_DIR / "smoke_test.py"
    return ([smoke] if smoke.is_file() else []) + found


def terminate_group(pid, sig):
    """Signal the isolated test process group; it may already be gone."""
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        pass


def execute(path, timeout):
    start = time.monotonic()
    command = [sys.executable, "-u", str(path)]
    try:
        proc = subprocess.Popen(
            command,
            cwd=PROJECT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except OSError as exc:
        return False, 0.0, f"Cannot launch {path.name}: {exc}", "START ERROR"

    timed_out = False
    try:
        try:
            output, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_group(proc.pid, signal.SIGKILL)
            output, _ = proc.communicate()
    finally:
        # Any forgotten child service still in this test's process group
        # must not be allowed to interfere with the next integration test.
        terminate_group(proc.pid, signal.SIGTERM)

    seconds = time.monotonic() - start
    if timed_out:
        return False, seconds, output, "TIMEOUT"
    if proc.returncode != 0:
        return False, seconds, output, f"EXIT {proc.returncode}"
    return True, seconds, output, "PASS"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run isolated TLS gateway integration scripts")
    parser.add_argument("--list", action="store_true", help="list selected tests without running them")
    parser.add_argument("--match", default="", help="run test filenames containing this substring")
    parser.add_argument("--timeout", type=int, default=90, help="per-test timeout in seconds (default: 90)")
    parser.add_argument("--repeat", type=int, default=1, help="repeat selected tests to detect flakes")
    parser.add_argument("--fail-fast", action="store_true", help="stop on first failing test")
    args = parser.parse_args(argv)

    if args.timeout < 1 or args.repeat < 1:
        parser.error("--timeout and --repeat must be positive integers")

    selected = [test for test in discover() if args.match.casefold() in test.name.casefold()]
    if not selected:
        print("No test scripts matched the selection", file=sys.stderr)
        return 2
    if args.list:
        for test in selected:
            print(test.name)
        return 0

    failures = 0
    completed = 0
    start = time.monotonic()
    total = len(selected) * args.repeat
    print(f"Running {len(selected)} test scripts x {args.repeat} (timeout {args.timeout}s each)", flush=True)
    for cycle in range(args.repeat):
        for script in selected:
            ok, duration, output, status = execute(script, args.timeout)
            completed += 1
            print(f"[{completed}/{total}] {status:>8} {script.name} ({duration:.2f}s)", flush=True)
            if not ok:
                failures += 1
                print("--- captured test output (last 50 lines) ---", flush=True)
                print("\n".join(output.splitlines()[-50:]) or "(no output)", flush=True)
                print("--- end test output ---", flush=True)
                if args.fail_fast:
                    break
        if args.fail_fast and failures:
            break

    elapsed = time.monotonic() - start
    print(f"Summary: {completed - failures} passed, {failures} failed, "
          f"{completed} executed in {elapsed:.1f}s", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
