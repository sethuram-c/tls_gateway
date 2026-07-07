#!/usr/bin/env python3
"""Self-test the test runner using tiny disposable scripts, not the gateway."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent


def run(runner, *args):
    return subprocess.run(
        [sys.executable, str(runner), *args],
        capture_output=True, text=True, timeout=12,
    )


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    with tempfile.TemporaryDirectory(prefix="tls-runner-selftest-") as temp:
        scripts = Path(temp) / "tests"
        scripts.mkdir()
        runner = scripts / "run_tests.py"
        shutil.copyfile(ROOT / "run_tests.py", runner)

        (scripts / "smoke_test.py").write_text("print('smoke ok')\n")
        (scripts / "test_a_pass.py").write_text("print('pass ok')\n")
        (scripts / "test_b_fail.py").write_text("import sys\nsys.exit(7)\n")
        (scripts / "test_c_sleep.py").write_text("import time\ntime.sleep(12)\n")
        (scripts / "http_backend.py").write_text("raise Exception('not a test')\n")

        result = run(runner, "--list")
        check(result.returncode == 0 and result.stdout.splitlines() == [
            "smoke_test.py", "test_a_pass.py", "test_b_fail.py", "test_c_sleep.py"
        ], "discovery should include only test scripts in stable order")

        result = run(runner, "--match", "pass", "--repeat", "2")
        check(result.returncode == 0 and "2 passed, 0 failed" in result.stdout,
              "matching and repeat must pass")

        result = run(runner, "--match", "fail")
        check(result.returncode == 1 and "EXIT 7" in result.stdout,
              "failing test should make runner exit nonzero")

        started = time.monotonic()
        result = run(runner, "--match", "sleep", "--timeout", "1")
        check(result.returncode == 1 and "TIMEOUT" in result.stdout and
              time.monotonic() - started < 6,
              "hung test must be terminated promptly")

        result = run(runner, "--match", "missing")
        check(result.returncode == 2, "zero selected tests must fail")

        result = run(runner, "--timeout", "0")
        check(result.returncode != 0, "invalid arguments must be rejected")

    print("PASS: runner discovery, filtering, repeat, failures, timeouts, empty selection")


if __name__ == "__main__":
    main()
