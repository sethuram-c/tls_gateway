# Tests and local fixtures

`make test` runs `smoke_test.py`, `test_tcp_server.py` and `test_http_backend.py`.
All three use Python's standard library. `http_backend.py` is a separate loopback-only test fixture, not part of the C gateway binary.
Run it manually using `python3 tests/http_backend.py` (default port 18081).
