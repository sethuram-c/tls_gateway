# Tests and local fixtures

`make test` runs four Python standard-library tests: `smoke_test.py`, `test_tcp_server.py`, `test_http_backend.py`, `test_backend_connect.py`.

The backend connector test uses an OS-assigned loopback port, asserts successful TCP connection followed by EOF, checks rejected port arguments, and verifies connection-refused handling. The Python HTTP server (`http_backend.py`) is a local test fixture, not part of the C executable.

Phase 7: `test_tcp_proxy.py` launches its own backend and proxy on dynamically
selected loopback ports, checks HTTP status and body, then shuts down both.

Phase 8: `python3 tests/test_tls_handshake.py` uses an ephemeral, loopback-only
`openssl s_server` and Python's `ssl` module to verify TLS 1.3, trust-chain
behavior, and hostname matching. No test certificates are committed.
