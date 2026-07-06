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

### Phase 26: epoll TLS reverse proxy

`python3 tests/test_epoll_tls_proxy.py` starts a real local TLS 1.3 gateway
and Python HTTP backend on temporary ports. Checks 200/404/502, fragmented
requests, explicit `Connection: close`, 64-KiB response streaming, 20
concurrent TLS clients alongside a stalled handshake, TLS 1.2 rejection,
and invalid CLI arguments. No installed Python packages are needed.

### Phase 27: SNI observation (certificate selection comes next)

`python3 tests/test_sni_observation.py` creates a disposable CA and two server
certificates (`localhost`, `api.test`) and checks their SANs. It verifies that
`--epoll-tls-proxy` logs the client-requested SNI but still uses the default
`localhost` certificate. In particular, a verified `api.test` connection must
fail hostname verification until Phase 28's certificate selection is added.
No files from this test are committed, and no global CA trust is changed.


## Phase 28 - TLS SNI certificate selection

Run `python3 tests/test_sni_selection.py` (or `make test`). Tests generate a
throwaway local CA and both hostname certificates, then launch the real C
non-blocking proxy and Python HTTP backend. They assert successful strict
TLS 1.3 hostname verification for localhost, api.test, and API.TEST; default
certificate for no SNI / loopback IP; rejection of unknown DNS SNI; recovery
after failed handshakes; and startup failure for a mismatched alternate key.
The earlier Phase 27 single-certificate test remains unchanged.


## Phase 29: stricter SNI regression matrix

`python3 tests/test_sni_security.py` tests exact leaf-certificate selection
by SHA-256 DER fingerprint with strict CA/hostname verification, uppercase
SNI, Host-header independence, no-SNI/IP behavior, wrong CA, unknown-SNI
server rejection, and concurrent hostname isolation during a stalled TLS
handshake. It uses only Python's standard library and temporary certificate
files. `CERT_NONE` is used only in the negative server-rejection probe.


## Phase 30: client certificates and mTLS fundamentals

`python3 tests/test_mtls_fundamentals.py` generates isolated temporary CA,
server, and `clientAuth` certificate files. Checks OpenSSL purpose restrictions,
permissions, refusal to overwrite keys, and a live loopback OpenSSL TLS 1.3
server requiring a client certificate. Trusted client identity succeeds;
missing client certificate and a `serverAuth` certificate are rejected. The
C gateway remains unchanged in this learning phase.

## Phase 31: mandatory client certificate verification in C

`python3 tests/test_mtls_gateway.py` generates disposable CA, two server
certificates, and client identities; launches the actual `--epoll-tls-proxy-mtls`
C gateway and local Python backend; then checks authenticated requests on both
SNI hostnames, rejection of missing / wrong-purpose / alien-CA certificates,
20 concurrent authenticated clients, and fail-closed startup for an invalid
client CA path. It additionally asserts rejected clients never reached the
backend and checks that the original `--epoll-tls-proxy` mode still accepts
one-way TLS. No third-party Python libraries, committed keys, or PDFs.

## Phase 32: rejected mTLS sessions never reach the backend

`python3 tests/test_mtls_rejections.py` generates temporary certificates
and runs a threaded loopback backend that counts **accepted TCP connections**
as well as HTTP requests. Negative TLS cases must not increment either
count. Valid clients must increment both counts by the same amount. It also
checks mixed-SNI behavior, no-SNI fallback, a stalled handshake, concurrent
authenticated recovery, key mismatch, and fail-closed startup with a missing
client CA. Requires no root or third-party Python packages.

## Phase 33 - hot certificate reload

`python3 tests/test_cert_reload.py` starts its own local HTTP backend and a
mandatory-mTLS, two-SNI gateway. It replaces both server certificates with
new CA-signed identities, issues `SIGHUP`, verifies new certificate fingerprints
and unchanged hostname trust, finishes an already-open session, then proves a
broken key reload retains the previous working configuration and mTLS policy.
All keys are disposable and temporary; no certificates or PDF are committed.

## Phase 34: config-driven gateway tests

`python3 tests/test_gateway_config.py` exercises the actual C config parser
using `--check-config` and a dozen fail-closed cases (duplicates, missing
required keys, bad port, malformed assignment, contradictory mTLS settings,
and incomplete SNI pairs). It then generates disposable development keys,
launches a local Python backend and C gateway via `--config`, and confirms
verified TLS 1.3 HTTPS forwarding with and without mandatory mTLS. Both SNI
hostnames are tested; an anonymous client must not reach the upstream in
mTLS mode. No third-party Python library is required. All local ports are
selected from the ephemeral range, and temporary keys/logs are removed.

## Phase 35: resource-lifecycle checks

`python3 tests/test_resource_cleanup.py` is a Linux-only, stdlib Python
integration test. It creates temporary CA/server/client certificates,
starts a config-driven SNI+mTLS proxy, and confirms ` /proc/<pid>/fd ` returns
to its starting descriptor count after failed or successful sessions.
It exercises interrupted handshakes, missing client certificates, concurrent
HTTPS requests, repeated certificate reloads, missing backends, recovery,
and SIGTERM cleanup. The test uses dynamic loopback ports and deletes its
temporary keys and config file automatically. `make test-resources` runs only
this slower resource regression; `make test` runs it with earlier tests.

## Phase 36 - stage-specific timeout regression

Run `make test-timeouts` (or `python3 tests/test_connection_timeouts.py`).
It deliberately holds TLS handshakes, HTTP requests and upstream replies to
verify 408/504 handling, close-after-partial-response, and unaffected healthy
clients. It takes approximately 20 seconds because it tests real deadlines.
Python's standard library is the only test dependency. No generated keys are
committed.

## Phase 37: graceful termination

`python3 tests/test_graceful_shutdown.py` (or `make test-drain`) starts a
loopback TLS gateway and an instrumented Python backend. It verifies:

- `SIGTERM` immediately removes the listening socket, but finishes a request
  already waiting on the backend.
- A backend that never replies is cut off by the four-second process-wide
  drain deadline; no incorrect HTTP error is injected mid-stream.
- The listening port is reusable and `SIGINT` exits promptly without clients.

The test generates disposable development certificates and does not modify
real `certs/` or rely on global services. Run `make test` for regressions.
