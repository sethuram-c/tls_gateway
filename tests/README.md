# Tests and local fixtures

`make test` runs four Python standard-library tests: `smoke_test.py`, `test_tcp_server.py`, `test_http_backend.py`, `test_backend_connect.py`.

The backend connector test uses an OS-assigned loopback port, asserts successful TCP connection followed by EOF, checks rejected port arguments, and verifies connection-refused handling. The Python HTTP server (`http_backend.py`) is a local test fixture, not part of the C executable.
