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

Phase 14: `test_tls_write.py` verifies an actual HTTPS response through the C
OpenSSL listener: trusted TLS 1.3, HTTP status/headers/body, multiple requests,
no response before input, and TLS 1.2 rejection. Phase 13 read tests now
expect a response after nonempty data. Tests use a temporary CA and ephemeral
ports; no certificate or PDF is committed.

## Phase 15: C TLS-to-HTTP gateway integration

Run `python3 tests/test_tls_proxy.py` (included in `make test`). It creates a
temporary CA/server certificate, starts the Python HTTP backend and C gateway,
verifies backend status/body (200/404), fragmented TLS request headers,
unsupported method handling, TLS 1.2 refusal, SIGTERM cleanup, invalid port
arguments and the 502 response when upstream is down. Private keys are removed
after the test. All traffic stays on 127.0.0.1.

## Phase 16: non-blocking I/O lab

Run `python3 tests/test_nonblock_demo.py` or `make test`. The test executes
`--nonblock-demo` three times, checking empty-read `EAGAIN`, short reads,
EOF after half-close and send-buffer backpressure. Tests do not assume a
specific kernel send-buffer size. The C demo uses socketpair, so there are
no open listening ports or TLS certificate requirements.

## Phase 17: socket flag helpers

`test_socket_flags.py` compiles the tiny C fixture `socket_flags_probe.c` into
an OS temporary directory and runs it, then checks the updated `--nonblock-demo`
output. It covers toggling `O_NONBLOCK`, preserved status flags, repeated calls,
independence of the two socketpair peers, sharing across `dup()` aliases,
`EBADF` errors, and restoration to blocking mode. No ports or keys are needed.

## Phase 18: epoll readiness demo

`test_epoll_demo.py` reruns `--epoll-demo` three times and checks event ordering
for ADD, readable data, level-triggered repeat after short read, empty poll,
MOD+EPOLLRDHUP, EOF, DEL and argument errors. It uses only Python's standard
library and a Unix socketpair; no root, network ports, certs or test fixtures.


## Phase 19: non-blocking epoll TCP listener

Run `python3 tests/test_epoll_server.py` to check dynamic loopback binding,
concurrent open sockets, interleaved client reads, EOF handling, SIGTERM,
port collisions, and argument validation. The listener intentionally
receives/discards bytes; later phases will add connection state and forwarding.

## Phase 20: connection registry and lifecycle

`python3 tests/test_connection_registry.py` compiles `tests/connection_probe.c`
with `src/connection.c` and checks owning/closing descriptors, slot reuse,
unique generation tokens, capacity (128), and cleanup. It also runs the real
`--epoll-server` with three overlapping clients, verifies independent byte
totals and active counts, and reopens a client to check token uniqueness.
`test_epoll_server.py` is retained as a Phase 19 regression test.

## Phase 21: epoll-driven OpenSSL handshake

`test_epoll_tls.py` uses only the Python standard library and disposable
certificates. It checks trusted TLS 1.3, many concurrent clients with one
incomplete ClientHello, plaintext/TLS 1.2 rejection, hostname verification,
invalid configuration, port collision, and SIGTERM cleanup. No HTTP response
is expected from `--epoll-tls`; the previous TLS proxy regression tests
continue to validate HTTPS forwarding independently.


## Phase 22: non-blocking TLS read tests

`python3 tests/test_epoll_tls_read.py` starts the event-driven C TLS listener
with disposable CA/server certificates. It checks that a successful handshake
stays open, split TLS records and binary payloads are read accurately, the
per-client 64-KiB receive cap closes excessive traffic, a stalled handshake
does not block active readers, and the process survives disconnects and stops
on SIGTERM. The test uses only the Python standard library. The Phase 21
handshake tests remain as regression coverage, but sessions now stay open
until they receive TLS close_notify, disconnect, reach the read limit, or the
process is stopped. No HTTP response is expected from `--epoll-tls` yet.


## Phase 23: buffered SSL_write and backpressure

`test_output_buffer.py` compiles and runs `tests/output_buffer_probe.c` with
AddressSanitizer/UBSan, checking binary data, partial-consumption offsets,
failed enqueues while a write is pending, queue reuse and capacity rejection.
`test_epoll_tls_write.py` starts `--epoll-tls` using disposable certificates
and verifies binary-safe TLS echo, record fragmentation, 20 concurrent TLS
clients during a stalled handshake, a 48-KiB transfer with a slower reader,
and SIGTERM cleanup. Phase 22's read regression now consumes echoed bytes
before calling `unwrap()`, and drains echoes while checking the 64-KiB cap.
All these tests require only Python's standard library on Fedora.

## Phase 24: TLS state machine

`python3 tests/test_tls_state.py` compiles a separate C probe that validates
legal/illegal transitions under UBSan, then runs the epoll TLS listener with
disposable CA/server certs. It confirms state transitions for a trusted TLS
handshake, echoed binary payload, clean `close_notify`, simultaneous stalled
handshake, another client, and SIGTERM. Prior TLS echo tests remain active.

## Phase 25 - non-blocking upstream connection integration

`python3 tests/test_epoll_backend.py` starts a temporary CA and server
certificate, exercises the new `--epoll-tls-connect` mode, and asserts that:
(1) TLS handshake by itself does not initiate an upstream connect;
(2) an application-data chunk triggers a real accepted TCP connection;
(3) the TLS client receives an echo after SO_ERROR confirms success;
(4) 20 clients still progress while another has a partial ClientHello;
(5) a refused backend is reported without taking down the gateway.
The test is self-contained and requires no third-party Python modules.
