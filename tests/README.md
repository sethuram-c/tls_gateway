# Tests and local fixtures

`make test` runs all Python standard-library smoke and integration tests listed in the Makefile.

The backend connector test uses an OS-assigned loopback port, asserts successful TCP connection followed by EOF, checks rejected port arguments, and verifies connection-refused handling. The Python HTTP server (`http_backend.py`) is a local test fixture, not part of the C executable.

Phase 7: `test_tcp_proxy.py` launches its own backend and proxy on dynamically
selected loopback ports, checks HTTP status and body, then shuts down both.

Phase 8: `python3 tests/test_tls_handshake.py` uses an ephemeral, loopback-only
`openssl s_server` and Python's `ssl` module to verify TLS 1.3, trust-chain
behavior, and hostname matching. No test certificates are committed.

Phase 9: `test_certificates.py` creates a throwaway CA and signed server cert,
checks key permissions, chain, purpose, DNS/IP SAN, rejection of the wrong
hostname, and refusal to overwrite existing secrets. No certs are committed.

Phase 10: `test_tls_context.py` generates temporary certificates, runs the C
`--tls-check` diagnostic and asserts success, key mismatch rejection, missing
certificate rejection and CLI errors. It needs no listener or checked-in keys.

Phase 11: `test_tls_listener.py` runs the C loopback TLS listener with
disposable certificates and tests TCP acceptance, expected handshake failure
(because `SSL_accept` is a future phase), graceful SIGTERM shutdown,
invalid certificates/ports, and port-in-use failure.

Phase 12: `test_tls_listener.py` now verifies real, trusted TLS 1.3
handshakes, rejects wrong hostnames and untrusted development CAs, checks
plaintext and TLS 1.2 rejection, exercises repeated connections, shutdown,
and invalid configuration. The gateway intentionally sends no HTTP yet.

Phase 13: `test_tls_listener.py` now sends application bytes before expecting
TLS closure. `test_tls_read.py` exercises text, binary payloads, bounded reads,
empty close_notify, and a silent client, using temporary CA/server certificates.
No certificates or learning PDF belong in Git.
