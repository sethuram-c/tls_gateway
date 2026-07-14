# Tests

Tests are plain Python scripts. Most start a gateway and backend on temporary loopback ports, generate temporary certificates, exercise one behavior, and stop their subprocesses before exiting. No pytest installation is required.

## Running tests

```sh
make                    # build the C gateway first
make test               # test-runner checks + all integration tests
make test-list          # see the scripts that will run
make test-smoke         # CLI smoke test only
```

To narrow down a failure or rerun a flaky test:

```sh
python3 tests/run_tests.py --match mtls
python3 tests/run_tests.py --match sni --repeat 3
python3 tests/run_tests.py --fail-fast
python3 tests/run_tests.py --match epoll_tls_proxy --timeout 120
```

The runner starts each script in its own process group, captures its output, and applies a 90-second timeout by default. It also terminates leftover child processes before moving on. Tests run sequentially; there is no shared background gateway for the whole suite.

## What to run when changing a component

| Area | Useful test scripts or targets |
|---|---|
| TCP and socket handling | `test_tcp_server.py`, `test_tcp_proxy.py`, `test_epoll_server.py`, `test_connection_registry.py` |
| TLS handshakes and I/O | `test_tls_listener.py`, `test_epoll_tls.py`, `test_epoll_tls_read.py`, `test_epoll_tls_write.py` |
| HTTPS forwarding | `test_epoll_tls_proxy.py`, `test_failure_injection.py` / `make test-edge` |
| SNI and certificate validation | `test_sni_selection.py`, `test_sni_security.py` |
| Client-certificate authentication | `test_mtls_gateway.py`, `test_mtls_rejections.py` |
| Certificate reload | `test_cert_reload.py` |
| Config, failures, cleanup | `test_gateway_config.py`, `test_connection_timeouts.py`, `test_resource_cleanup.py`, `test_graceful_shutdown.py` |
| Benchmark and `/proc` tools | `test_https_benchmark.py`, `test_concurrency_profile.py` |
| Release checks | `test_release_check.py`, `make release-check` |

The individual socket, output-buffer, and TLS-state probes compile small C programs from `tests/` as part of their Python tests.

## Focused Make targets

```sh
make test-edge          # malformed requests and disconnects
make test-timeouts      # takes longer: waits for real deadlines
make test-resources     # fd counts and failure-path cleanup
make test-drain         # SIGTERM/SIGINT behavior
make test-bench         # benchmark output sanity checks
make test-profile       # profiler behavior and /proc samples
make asan ubsan
make test-sanitize      # HTTPS smoke test against instrumented builds
```

The tests use the Python standard library and OpenSSL CLI. Most certificate tests create a throwaway CA under a temporary directory rather than using `certs/` from your working tree. Some Linux-only tests read `/proc/<pid>/fd` or `/proc/<pid>/status`.

If a test times out, run that script by itself first. Check for leftover gateway processes with `pgrep -af tls-gateway` and listening ports with `ss -ltnp`. A passing focused test does not automatically mean the entire suite passed; rerun `make test` before tagging a release.
