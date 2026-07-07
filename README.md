# TLS Gateway (learning project)

C17 + GNU Make on Fedora. Python standard library is used for testing.

## Build and test

```bash
make clean && make && make test
```

## Phase 6: connect C program to Python HTTP backend

Terminal A:

```bash
python3 tests/http_backend.py
```

Terminal B:

```bash
./build/tls-gateway --backend-connect 18081
curl -i http://127.0.0.1:18081/health
```

The C command makes one outbound TCP connection to `127.0.0.1:18081` and immediately closes it; it **does not send HTTP or forward client traffic**. Phase 7 will implement forwarding. To observe sockets, use `ss -ltnp | grep 18081` while Python is running. Everything binds to loopback.

Legacy commands `--socket-demo` and `--tcp-server` remain available.

## Phase 7: blocking TCP proxy

In one terminal run `python3 tests/http_backend.py`. In another run
`./build/tls-gateway --tcp-proxy 18080 18081`. Test with
`curl -i -H 'Connection: close' http://127.0.0.1:18080/health`.

The proxy is loopback-only, handles one client at a time, and forwards raw
TCP bytes in both directions. No TLS, epoll, or concurrent clients yet.
Use `make test` for automated verification.

## Phase 8: TLS 1.3 handshake lab

Run `python3 tests/test_tls_handshake.py` (or `make test`) to start a temporary
OpenSSL TLS 1.3 server and exercise certificate trust, hostname verification,
and negotiated protocol/cipher from a Python client. Temporary keys are deleted.
**The C TCP proxy remains plaintext in Phase 8.** TLS termination comes later.

## Phase 9: local CA and TLS server certificate (development only)

Generate a disposable CA and signed server certificate with DNS and IP SANs:

```bash
make certs
openssl verify -CAfile certs/ca.crt -purpose sslserver \
  -verify_hostname localhost certs/server.crt
openssl verify -CAfile certs/ca.crt -purpose sslserver \
  -verify_ip 127.0.0.1 certs/server.crt
```

Generated files are in `certs/`, **ignored by Git**. The script refuses to
overwrite an existing directory. `ca.key` is the private CA signing key;
`server.key` is the server's private key. Never publish either key or install
this development CA into the system trust store. The C proxy remains plaintext.
Run `python3 tests/test_certificates.py` for disposable certificate tests.

## Phase 10: OpenSSL object lifetime diagnostic

The C executable now links to `libssl`/`libcrypto` and can validate that a
server certificate and private key form a usable **TLS 1.3-only** `SSL_CTX`.
The `SSL` object is created with two memory BIOs to demonstrate ownership,
then all objects are freed. **No handshake or TLS listener exists yet.**

```bash
make certs                       # only if certs/ does not exist
make clean && make && make test
./build/tls-gateway --tls-check certs/server.crt certs/server.key
```

The diagnostic verifies that the certificate matches the key; it **does not**
validate a remote peer or prove that a CA chain is trusted. The legacy TCP proxy
remains plaintext. Run `python3 tests/test_tls_context.py` for negative tests.

## Phase 11: TLS listener setup (no handshake yet)

The gateway now creates one TLS 1.3-only `SSL_CTX`, binds a loopback TCP
listener, and prepares an `SSL` object for each accepted TCP connection.
It immediately closes that connection: **there is no `SSL_accept()` yet**,
so `openssl s_client` and HTTPS requests are intentionally unsuccessful.

```bash
make certs  # only if certs/ does not exist
make clean && make && make test
./build/tls-gateway --tls-listen certs/server.crt certs/server.key 18443
# In a second terminal:
ss -ltnp '( sport = :18443 )'
# Ctrl+C to stop the listener
```

Listen address is restricted to `127.0.0.1`. No development private key
is included in source control. `tests/test_tls_listener.py` generates
disposable certificates, validates repeated accepts and clean termination,
and checks expected failures. TLS handshaking starts in Phase 12.

## Phase 12: first TLS 1.3 handshake in C

The `--tls-listen` command now calls **`SSL_accept()`** on each accepted
client socket and prints the negotiated TLS version and cipher. Only TLS 1.3
is enabled. After a successful handshake, the gateway sends TLS `close_notify`
and closes the connection; **it does not read or send HTTP yet**. `SSL_read()`
and `SSL_write()` are introduced in the next phases.

```bash
make certs  # only if certs/ is absent
make clean && make && make test
./build/tls-gateway --tls-listen certs/server.crt certs/server.key 18443
# In another terminal:
openssl s_client -tls1_3 -connect 127.0.0.1:18443 \
  -servername localhost -CAfile certs/ca.crt \
  -verify_hostname localhost -verify_return_error </dev/null
```

Expect `Verification: OK` in the OpenSSL client and `TLS handshake complete`
on the server. Each connection is still handled **sequentially**, with a
3-second socket receive/send timeout during handshaking to avoid hanging
forever on silent peers. A failed client handshake is logged and does not
terminate the listener. Only loopback is exposed. Do not use this lab server
for public traffic or expect HTTPS responses yet. The learning PDF is a
separate personal artifact and is not included in the repository.

## Phase 13: read decrypted TLS application bytes

The `--tls-listen` loop now performs a successful TLS 1.3 handshake and then
reads **one block of up to 4096 decrypted bytes** with `SSL_read()`. It logs
only a short **hexadecimal** preview so binary input cannot inject terminal
control sequences. The preview is educational, and must not be enabled for
real user traffic (which may contain secrets). It neither parses HTTP nor
returns an HTTP response: `SSL_write()` comes in Phase 14.

```bash
make clean && make && make test
make certs  # only if certs/ is absent
./build/tls-gateway --tls-listen certs/server.crt certs/server.key 18443
# separate terminal: 
printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
  openssl s_client -quiet -tls1_3 -connect 127.0.0.1:18443 \
    -servername localhost -CAfile certs/ca.crt -verify_hostname localhost
```

Look for `TLS application data read: ... bytes` in the gateway log. A client
that sends no data is bounded by a 3-second socket timeout, and clients are
still handled one at a time. One `SSL_read()` may read only part of a larger
application message; robust stream framing comes later. `make test` runs
`tests/test_tls_read.py` as well as regression suites.

## Phase 14: send HTTPS response with SSL_write

The TLS listener now returns a valid **fixed HTTP/1.1 response over TLS**
when it receives at least one decrypted application-data block. The
response includes `Content-Length: 23` and `Connection: close`.

```bash
make clean && make && make test
make certs  # only if certs/ is missing
./build/tls-gateway --tls-listen certs/server.crt certs/server.key 18443
# Another terminal:
curl --cacert certs/ca.crt https://localhost:18443/
```

Expected body: `hello from tls gateway`. You can also use the Python
`tests/test_tls_write.py` suite, which generates and cleans up its own CA.

**Limitations:** This is an educational, single-client-at-a-time server, not
an HTTP parser or reverse proxy. It reads only the first 4096 decrypted bytes,
returns the same response for any nonempty payload, uses blocking I/O and a
3-second timeout, and does not yet connect to the Python backend. The hex
preview is for this lab only; application data may contain secrets. Full TLS
termination + backend forwarding is Phase 15. Learning PDFs stay outside Git.

## Phase 15: HTTPS termination with HTTP backend forwarding

New command (loopback-only, blocking):

```bash
make clean && make && make test
make certs  # only if certs/ has not already been generated
# Terminal 1:
python3 tests/http_backend.py
# Terminal 2:
./build/tls-gateway --tls-proxy certs/server.crt certs/server.key 18443 18081
# Terminal 3:
curl -i --cacert certs/ca.crt https://localhost:18443/health
curl -i --cacert certs/ca.crt https://localhost:18443/
curl -i --cacert certs/ca.crt https://localhost:18443/missing
```

The TLS connection ends at the C gateway, which opens a **plaintext** HTTP
connection to the Python backend at `127.0.0.1:18081`. Requests are forwarded
as raw HTTP header bytes; responses are relayed through `SSL_write()`.
`/health` produces `ok`, `/` produces `hello from python backend`, and unknown
paths preserve the backend's `404` status. An unreachable backend returns `502`.

**Learning-stage limitations:** TLS 1.3 only; sequential blocking clients;
loopback-only; only single, bodyless `GET` requests with at most 8192 header
bytes; no pipelining, keep-alive or POST; maximum backend response transfer
1 MiB; 3-second socket I/O timeouts. No full HTTP parser, streaming request
bodies, non-blocking I/O, or upstream TLS. These are deliberate boundaries for
this lesson, **not** a production-ready HTTP proxy. The previous `--tls-listen`
fixed-response lab remains available and all its regression tests still run.

Run `python3 tests/test_tls_proxy.py` for the full HTTPS-forwarding integration
suite. The personal learning PDF is not part of the repo.

## Phase 16: non-blocking socket behavior lab (no production socket changes)

```bash
make clean && make && make test
./build/tls-gateway --nonblock-demo
python3 tests/test_nonblock_demo.py
```

The demo uses a local `socketpair(AF_UNIX, SOCK_STREAM)` (no TCP listener
or network ports). It marks one endpoint `O_NONBLOCK` with `fcntl()` and
contrasts: an empty `recv()` returning `-1`/`EAGAIN`, two intentionally
small reads of a five-byte message, `recv() == 0` after peer `SHUT_WR`,
and a send buffer that eventually fills (`send()` returns `EAGAIN`).
The byte count before saturation varies by kernel and socket buffer size.

**Scope:** The actual TLS reverse proxy from Phase 15 is still blocking.
`O_NONBLOCK` will be applied to network sockets in Phase 17, followed
by readiness polling/`epoll`. Do not treat EAGAIN as a disconnect, and
remember that a successful `send()` need not send the whole application
buffer. No PDF and no generated certificates are tracked in Git.

## Phase 17: reusable non-blocking socket helpers

`include/socket_flags.h` and `src/socket_flags.c` provide
`socket_set_nonblocking(fd, true/false)` and `socket_is_nonblocking(fd)`.
They use `fcntl(F_GETFL/F_SETFL)` to toggle **only** `O_NONBLOCK`, preserving
other file status flags. A repeated toggle is safe; errors return `-1` and
preserve `errno`. `O_NONBLOCK` belongs to the open file description, so it is
shared with `dup()` aliases but **not** with the other socketpair endpoint.

```bash
make clean && make && make test
./build/tls-gateway --nonblock-demo
python3 tests/test_socket_flags.py
```

The existing Phase 16 demo now uses the helper and restores blocking mode
before exit. Python drives a small temporary C test executable that checks
flag preservation, idempotence, `dup()` semantics and `EBADF`. The current
blocking TLS listener/proxy is intentionally **unchanged**: switching its
sockets now would break `SSL_accept()`/`SSL_read()` without an event loop.
Event readiness follows in Phase 18. Learning PDFs are kept out of Git.

## Phase 18: epoll readiness lab (standalone)

Run `./build/tls-gateway --epoll-demo` or `python3 tests/test_epoll_demo.py`.
The C lab uses `socketpair()` (no ports and no certificates). It registers a
non-blocking socket with `epoll_create1`/`epoll_ctl(ADD)`, shows level-triggered
`EPOLLIN` persisting after a partial read, drains all data, changes interest with
`MOD`, detects a peer write half-close using `EPOLLRDHUP`, and removes the fd
using `DEL`. A zero-millisecond `epoll_wait` represents an **immediate poll**,
not a busy-loop design for production. No server or gateway I/O is converted
to epoll in this phase; that begins in Phase 19.

To observe syscalls on Fedora: `strace -e trace=epoll_create1,epoll_ctl,epoll_wait,recvfrom,sendto,shutdown ./build/tls-gateway --epoll-demo`.


## Phase 19: epoll-driven TCP listener (standalone)

Run `./build/tls-gateway --epoll-server 18082` in one terminal. The listener
binds to `127.0.0.1` and sets `O_NONBLOCK`, then registers itself with epoll.
Each accepted client is also non-blocking (`accept4` with `SOCK_NONBLOCK`),
registered for `EPOLLIN | EPOLLRDHUP`, and drained using `recv()` until
`EAGAIN`, EOF, or a per-event 64-KiB fairness budget. The server **discards**
received bytes and reports only byte counts; it does not echo or return HTTP.

```bash
make clean && make && make test
# terminal A
./build/tls-gateway --epoll-server 18082
# terminal B (send a short message using only Python's standard library)
python3 -c "import socket; s=socket.create_connection(('127.0.0.1', 18082)); s.sendall(b'hello'); s.close()"
# terminal C
ss -ltnp '( sport = :18082 )'
```

`python3 tests/test_epoll_server.py` starts the listener on an available
loopback port, verifies overlapping idle client connections, interleaved
payloads, EOF handling, SIGTERM cleanup, refused invalid CLI ports and a
busy port. The Python command uses only the standard library and closes the client
socket explicitly. No root privileges, certs, or third-party Python libraries
are required.

**Scope:** This is a dedicated epoll TCP receiver lab, not the TLS gateway's
I/O path. The Phase 15 TLS proxy remains blocking and unchanged. For clarity,
Phase 19 tracks live client fds in a fixed 128-slot array, and Phase 20 will
introduce explicit per-connection structures. There is no application reply,
TLS, backend routing, or persistent traffic buffer yet. Educational only,
loopback-only; not production ready. Personal learning PDF is outside Git.

## Phase 20: per-connection lifecycle and epoll tokens

The standalone `--epoll-server PORT` now tracks accepted sockets through
`ConnectionRegistry` (`include/connection.h`, `src/connection.c`) instead of
parallel/flat file descriptor bookkeeping. Each `Connection` owns its socket
**only after successful registration**, stores its peer IPv4 address, tracks
received bytes, and moves from `CONN_UNUSED` to `CONN_OPEN` and back.

`epoll_event.data.u64` stores a generation-and-slot token rather than a raw
fd or pointer. Slot zero is reserved for the listener token. Old tokens are
ignored after slot reuse, avoiding accidental dispatch of a queued event for
a connection that has already been closed. The registry supports at most
128 simultaneous clients and explicitly releases all sockets on shutdown.

```bash
make clean && make && make test
python3 tests/test_connection_registry.py
./build/tls-gateway --epoll-server 18082
```

You will see accepted-client tokens, per-client byte totals and an active
connection count. This mode still **receives and discards** TCP data; it has
no TLS handshake, upstream forwarding, response buffers, or HTTP processing.
The blocking `--tls-proxy` from Phase 15 is unchanged. The personal learning
PDF must remain outside the repository.

## Phase 21: event-driven TLS 1.3 handshake (no HTTP yet)

The new `--epoll-tls CERT KEY PORT` command creates one shared server-side
`SSL_CTX`, accepts non-blocking loopback clients, and drives `SSL_accept()` from
`epoll_wait()` events. `SSL_ERROR_WANT_READ` waits for `EPOLLIN` and
`SSL_ERROR_WANT_WRITE` waits for `EPOLLOUT`. Each client owns an `SSL` object,
while the Phase 20 connection registry tracks sockets and guards against
stale event tokens. Handshakes time out after 10 seconds. `SIGPIPE` is ignored
so a client disconnect during `close_notify` cannot kill the server.

```bash
make clean && make && make test
make certs  # only if certs/ does not already exist
./build/tls-gateway --epoll-tls certs/server.crt certs/server.key 18444
# From another terminal:
openssl s_client -tls1_3 -connect 127.0.0.1:18444 \
  -servername localhost -CAfile certs/ca.crt \
  -verify_hostname localhost -verify_return_error </dev/null
```

This is a **handshake-only diagnostic**: on success the gateway attempts to
send `close_notify`, closes the session, and returns to accepting clients.
It will NOT respond to `curl` / HTTP. Phase 22 introduces asynchronous
application-data reads; the blocking `--tls-proxy` command from Phase 15
remains available and unchanged. The lesson PDF stays outside Git, and
`certs/` remains ignored. No production hardening is claimed.

Run `python3 tests/test_epoll_tls.py` to test 20 concurrent handshakes while
one peer stalls, invalid ClientHello, TLS 1.2 refusal, client-side hostname
verification and orderly shutdown using disposable certificates.


## Phase 22: non-blocking TLS application reads (no response yet)

`--epoll-tls CERT KEY PORT` now keeps clients connected after a successful
TLS 1.3 handshake. The existing `epoll` loop drives **`SSL_read()`** using
`SSL_ERROR_WANT_READ` -> `EPOLLIN` and `SSL_ERROR_WANT_WRITE` -> `EPOLLOUT`.
It drains TLS application data, logs a short hex preview with byte counts,
and continues serving other clients. The preview is for an isolated training
lab only: **do not log decrypted requests in production**. A per-client
64-KiB read cap closes a connection to keep this exercise bounded. Clean
TLS `close_notify`, abrupt disconnects, and incomplete handshakes release
both the `SSL` object and the registry-owned socket. Phase 21's 10-second
handshake timeout still applies only to clients that have not authenticated.

```bash
make clean && make
python3 tests/test_epoll_tls_read.py
make test
make certs  # only if you have not generated local certificates
./build/tls-gateway --epoll-tls certs/server.crt certs/server.key 18444
# Second terminal (type some text, then Ctrl+D):
openssl s_client -quiet -tls1_3 -connect 127.0.0.1:18444 \
  -servername localhost -CAfile certs/ca.crt \
  -verify_hostname localhost -verify_return_error
```

A client sees **no HTTP response**, because Phase 22 only receives data.
Phase 23 introduces non-blocking forwarding and output buffers. The
**Phase 15 blocking `--tls-proxy` still forwards HTTPS to the Python backend**.
PDFs and certificates do not belong in the repository.


## Phase 23: bounded buffered TLS writes (echo lab)

`--epoll-tls CERT KEY PORT` now **echoes** decrypted TLS bytes back to the
client using non-blocking `SSL_write()`. `src/output_buffer.c` provides a
fixed-size **4 KiB** output queue *per client*. The event loop stops reading
that client when an output chunk is queued, so a slow receiver cannot trigger
unbounded buffering. On `SSL_ERROR_WANT_WRITE`, it waits for `EPOLLOUT`; on
`SSL_ERROR_WANT_READ`, it waits for `EPOLLIN`, then retries the **same**
`SSL_write` data pointer and length. Successful short writes advance the
queue's offset; a completed queue frees its storage for reuse.

This is a diagnostic **TLS echo mode**, not an HTTP endpoint and not backend
forwarding. `--tls-proxy` from Phase 15 still implements blocking HTTPS to
Python-backend routing. Phase 24 will refine the event state machine and
Phase 25 will add asynchronous backend connections.

```bash
make clean && make
python3 tests/test_output_buffer.py
python3 tests/test_epoll_tls_write.py
make test
make certs  # if your development certificates are not present
./build/tls-gateway --epoll-tls certs/server.crt certs/server.key 18444
# In another terminal:
printf 'echo test\n' | openssl s_client -quiet -tls1_3 \
  -connect 127.0.0.1:18444 -servername localhost \
  -CAfile certs/ca.crt -verify_hostname localhost -verify_return_error
```

No certificate, private key, generated binary, or learning PDF belongs in Git.


## Phase 24: explicit TLS connection state machine

The standalone `--epoll-tls CERT KEY PORT` echo lab now uses a checked finite
state machine: `UNUSED -> HANDSHAKING -> READING <-> WRITING -> CLOSING ->
UNUSED`. A handshake failure can also go straight to `CLOSING`. `TLS_STATE_*`
values describe which OpenSSL operation is active, **not** whether the socket
is readable or writable. Either operation may require `EPOLLIN` or `EPOLLOUT`
according to `SSL_get_error`. Each accepted client owns its `SSL` object and
4-KiB output buffer; a registry token protects against stale epoll events.

```bash
make clean && make
python3 tests/test_tls_state.py
make test
make certs  # only if missing
./build/tls-gateway --epoll-tls certs/server.crt certs/server.key 18444
```

The server emits diagnostic `TLS state:` transition lines for this lab. It
still echoes encrypted application data and closes at the 64-KiB read limit.
The Phase 15 `--tls-proxy` (blocking HTTPS to Python-backend forwarding) is
unchanged. Phase 25 adds asynchronous upstream connection handling. No PDF,
certificate/private key, or generated binary belongs in Git.


## Phase 25: non-blocking outbound backend connections

The new **`--epoll-tls-connect CERT KEY TLS_PORT BACKEND_PORT`** diagnostic
reuses the Phase 24 event-driven TLS echo server. On the first decrypted
application-data chunk for each client, it makes a **non-blocking outbound
TCP connection** to `127.0.0.1:BACKEND_PORT`. A connection in progress enters
`BACKEND_CONNECTING`, is registered with `epoll`, and completes only after
`getsockopt(SOL_SOCKET, SO_ERROR)` reports success. The first TLS chunk stays
in the existing bounded 4-KiB output buffer while the connect is pending;
client reading is paused. Completion (success or refusal) resumes the TLS
echo. Rejected or timed-out outbound connections do not crash the listener.
The generation-tagged epoll token protects against stale backend events,
and upstream sockets are closed on client teardown.

**This is a connection lab, not asynchronous HTTP forwarding.** It never
sends the TLS data to the backend and never reads an upstream response. The
existing `--tls-proxy` is still the working **blocking** HTTPS reverse proxy.
The next development milestone will add full event-driven backend forwarding
before moving on to SNI features.

```bash
make clean && make
python3 tests/test_epoll_backend.py
make test
# In terminal 1:
python3 tests/http_backend.py
# In terminal 2:
./build/tls-gateway --epoll-tls-connect \
  certs/server.crt certs/server.key 18444 18081
# Terminal 3: a verified TLS client; send a line and receive that same line.
openssl s_client -quiet -tls1_3 -connect 127.0.0.1:18444 \
  -servername localhost -CAfile certs/ca.crt \
  -verify_hostname localhost -verify_return_error
```

The Python backend logs may show early EOF because Phase 25 only tests the
TCP connection, not HTTP. The learning PDF is personal, outside Git.

## Phase 26: event-driven HTTPS -> HTTP backend forwarding

`--epoll-tls-proxy CERT KEY TLS_PORT BACKEND_PORT` implements the first full
**non-blocking TLS termination proxy**. A single Linux `epoll` loop manages
per-client `SSL_accept()`/`SSL_read()`/`SSL_write()` and non-blocking backend
`connect()`/`send()`/`recv()`. The upstream is plaintext loopback HTTP.
No thread is created per connection. The legacy Phase 15 `--tls-proxy`
(blocking) and Phase 25 `--epoll-tls-connect` (echo/connect lab) are unchanged.

Example on Fedora, using local development certificates:

```bash
make clean && make && make test
make certs  # only once, if certs/ is missing
# Terminal 1
python3 tests/http_backend.py
# Terminal 2
./build/tls-gateway --epoll-tls-proxy \
  certs/server.crt certs/server.key 18444 18081
# Terminal 3
curl -i --cacert certs/ca.crt https://localhost:18444/health
curl -i --cacert certs/ca.crt https://localhost:18444/large -o /dev/null
```

**Deliberate learning limits:** HTTP/1.1 `GET` only, one request per client
connection, maximum 8 KiB request headers, no request bodies/pipelining,
`Connection: close` required on upstream responses, loopback networking,
128 tracked connections, basic 15-second idle timeout, no mTLS;
Phase 26 predates SNI certificate selection.
The proxy accepts an absent Connection header (adds `Connection: close`) or
an explicit `Connection: close`; other Connection values get HTTP 400.
Upstream responses are streamed with an 8 KiB buffer; the proxy stops
reading upstream while the current TLS output chunk is pending. A refused
upstream connection produces HTTPS 502. It is **not production-ready**:
advanced HTTP framing, request-body streaming, graceful draining, multi-host
routing, comprehensive limits, and robust TLS shutdown are future work.

Run just this phase's integration test:
`python3 tests/test_epoll_tls_proxy.py`.
Generated certificates and learning PDFs must never be committed.

## Phase 27: learn SNI and issue an alternate development certificate

**SNI (Server Name Indication)** is the requested TLS hostname sent in the
ClientHello, before the server chooses its certificate. It is distinct from
the later HTTP `Host` header and is **not proof of client identity**.
`--epoll-tls-proxy` now observes/logs SNI after successful handshakes; it
**still serves only the default `localhost` certificate**, irrespective of SNI.
Selecting certificates will be added in Phase 28.

```bash
make certs       # once, only if certs/ does not exist
make certs-sni   # issue api.test.crt + api.test.key using the existing local CA
openssl verify -CAfile certs/ca.crt -purpose sslserver \
  -verify_hostname api.test certs/api.test.crt
python3 tests/test_sni_observation.py
```

For a live experiment, start the Python backend and the epoll TLS proxy as in
Phase 26, then run:

```bash
# The default localhost cert is still returned, even when SNI=api.test.
openssl s_client -tls1_3 -connect 127.0.0.1:18444 \
  -servername api.test -CAfile certs/ca.crt \
  -verify_hostname api.test -verify_return_error </dev/null
```

This command should **fail hostname verification** in Phase 27. To inspect
without verifying the hostname, use `openssl s_client` without
`-verify_hostname` **only in this isolated lab**. No PDFs, generated
certificates, private keys, or build artifacts belong in Git. `api.test`
is a reserved example hostname; no DNS entry is necessary when connecting
directly to `127.0.0.1` while passing `-servername api.test`.

## Phase 28: select certificates using TLS SNI

The event-driven proxy can now optionally use **two** TLS 1.3 server
certificates: `localhost` (default) and `api.test` (alternate). The alternate
certificate is loaded into its own `SSL_CTX`, and the OpenSSL server-name
callback switches the connection's context during `ClientHello`, before
certificate delivery. Both contexts stay alive until the server exits.

```bash
make certs             # only if you have not generated the CA yet
make certs-sni         # only if api.test certificate has not been generated
make && make test
python3 tests/http_backend.py
# In another terminal:
./build/tls-gateway --epoll-tls-proxy \
  certs/server.crt certs/server.key 18444 18081 \
  certs/api.test.crt certs/api.test.key
# In a third terminal:
curl --cacert certs/ca.crt https://localhost:18444/health
curl --noproxy "*" --cacert certs/ca.crt --resolve api.test:18444:127.0.0.1 \
  https://api.test:18444/health
```

Only `api.test` selects the alternate context. `localhost` and no SNI use
the default certificate, and unknown DNS SNI is rejected using the TLS
`unrecognized_name` alert when two-hostname mode is enabled. An IP-address
client without SNI can still verify the default `127.0.0.1` IP SAN. SNI is
client-supplied and **not authentication**; clients must still verify the
certificate chain and hostname. The HTTP backend remains the same regardless
of SNI (this stage does not implement virtual-host routing).

The original four-argument `--epoll-tls-proxy CERT KEY TLS_PORT BACKEND_PORT`
mode still works and behaves as in Phase 27 (default certificate only).
`tests/test_sni_observation.py` keeps that compatibility covered. The new
`tests/test_sni_selection.py` tests both certificates, negative handshakes,
and invalid key material using temporary CA/certificates. Never commit
`certs/`, any private key, or the separate personal learning PDF.

## Phase 29: multi-hostname TLS security verification

Run `python3 tests/test_sni_security.py` to exercise the real epoll HTTPS
proxy with disposable CAs and certificates. Strict Python TLS 1.3 clients
verify the CA chain and hostname, then compare the *exact* leaf certificate
SHA-256 fingerprint for `localhost`, `api.test` and mixed-case `API.TEST`.
The test also verifies the no-SNI default and loopback IP SAN; confirms an
HTTP `Host` header cannot change a certificate already selected via SNI;
rejects a different CA; and proves unknown SNI fails at the server using a
**diagnostic-only unverified** client. Twenty concurrent mixed-SNI clients
are exercised alongside an incomplete TLS handshake. The C gateway code is
unchanged from Phase 28: this phase adds security-oriented regression coverage.

Run `make test` for all suites. No certificates, keys, or personal PDF are
committed. This is a local TLS learning lab, not a general-purpose hardened
reverse proxy, and the two hostnames still share one HTTP backend.

## Phase 30: mutual TLS fundamentals (client certificates)

We use the existing disposable lab CA to issue a *separate* TLS client identity.
The new script writes `certs/client.crt` and `certs/client.key` without overwriting
existing keys or changing any server certificates:

```bash
make certs-client  # after 'make certs' in earlier phases
openssl verify -CAfile certs/ca.crt -purpose sslclient certs/client.crt
openssl verify -CAfile certs/ca.crt -purpose sslclient certs/server.crt  # expected FAIL
python3 tests/test_mtls_fundamentals.py
```

The test generates throwaway certificates and uses `openssl s_server -Verify 1`
to **require** a client certificate. A Python TLS 1.3 client succeeds with
`client.crt/client.key` but is rejected without them or with a serverAuth-only
certificate. The Phase 30 lab **did not change C gateway authentication**; the Phase 31
implementation below enables and enforces mTLS directly in the gateway. A trusted certificate
proves CA-issued identity, not application authorization; map identities to
permissions explicitly before any real deployment. All lab keys stay in
`certs/` and out of Git.

The original Phase 9 CA and server certificates are valid for only 30 days.
Check `openssl x509 -in certs/ca.crt -noout -dates` before manual demos and
reissue your disposable lab CA/leaf certificates if they've expired. Never
install the test CA in the system trust store.

## Phase 31: require client certificates in the C epoll TLS proxy

The explicit `--epoll-tls-proxy-mtls` command enables two-way TLS
on the event-driven reverse proxy. It loads a **trusted client CA** before
binding the listener and configures both the default and alternate SNI
contexts using `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`. OpenSSL
performs chain and `clientAuth` purpose validation during the TLS handshake;
`SSL_get_verify_result()` and `SSL_get1_peer_certificate()` provide a
post-handshake sanity check before forwarding any HTTP data.

```bash
make certs-client  # once, after generating certs/ with 'make certs'
make certs-sni     # once, to enable optional api.test SNI
make && python3 tests/test_mtls_gateway.py

# Terminal 1: Python backend
python3 tests/http_backend.py
# Terminal 2: C gateway with mandatory client authentication
./build/tls-gateway --epoll-tls-proxy-mtls \
  certs/server.crt certs/server.key 18444 18081 certs/ca.crt \
  certs/api.test.crt certs/api.test.key
# Terminal 3: authenticated client succeeds
curl --noproxy '*' -i --cacert certs/ca.crt \
  --cert certs/client.crt --key certs/client.key \
  https://localhost:18444/health
# No --cert/--key: expected TLS rejection (no HTTP 200)
curl --noproxy '*' -i --cacert certs/ca.crt \
  https://localhost:18444/health
```

The alternate SNI certificate/key pair is optional in mTLS mode. If provided,
client authentication is mandatory for *both* virtual hosts. No-SNI clients
use the default server certificate; unknown SNI is rejected in two-host mode.
The existing `--epoll-tls-proxy` command remains one-way TLS for compatibility.
This project uses only a disposable development CA; do not trust it system-wide
or expose the unaudited educational proxy to public networks. A verified
client certificate authenticates a CA-issued identity but does **not** supply
application authorization or revocation checking. Keep all generated keys
out of Git, and keep the personal learning PDF outside the repo.

## Phase 32: mTLS rejection and upstream-isolation security tests

`python3 tests/test_mtls_rejections.py` uses a disposable CA, three local
client identities and a counting HTTP backend. It asserts that missing,
wrong-purpose and foreign-CA client certificates, unknown SNI, and TLS 1.2
never create a backend TCP connection. Trusted clients work for both SNI
names; an incomplete handshake does not block authenticated traffic. A
missing client CA makes mTLS mode fail at startup rather than silently
downgrading to one-way TLS. Run `make test` for the complete regression suite.

The tests verify **authentication before proxying**, not user-role authorization.
The proxy is still an educational HTTP/1.1 GET-only project and does not
implement certificate revocation or client identity allowlists. Keep it on
loopback and keep the personal phase PDF outside Git.

## Phase 33: SIGHUP certificate hot reload (epoll HTTPS proxy)

The `--epoll-tls-proxy` and `--epoll-tls-proxy-mtls` modes now reload their
configured server certificate/key pairs (including `api.test` when configured)
when they receive `SIGHUP`. The configured mTLS trust file is reloaded too.
Each reload builds and checks **a complete new TLS configuration** first;
only if every certificate/key and CA load succeeds is it used for **new**
connections. If any component is invalid, the last good configuration stays
active. Existing sessions retain their original generation, including the
SNI callback's context pointer, until those sessions close. Reload does not
reopen the listening socket or interrupt existing TLS sessions.

In a development-only terminal, after generating and installing **valid** new
cert/key files at the same configured paths, run:

```bash
# Do not replace only one file and signal before the corresponding key is ready.
kill -HUP "$(pgrep -f '^./build/tls-gateway --epoll-tls-proxy' | head -n 1)"
# Follow logs for "TLS credentials reloaded successfully" or
# "TLS credential reload failed; keeping previous generation".
python3 tests/test_cert_reload.py
```

A safe operator workflow stages the replacements outside the live directory,
verifies keys and certificates, installs **both** configured pairs, and only
then signals the process. File installation is not an atomic multi-file OS
transaction; **the gateway's validated in-memory swap is atomic**. The test
creates a local disposable CA and certs, verifies that certificate fingerprints
change on new sessions, proves an existing partial HTTP request finishes, and
checks invalid reloads plus mTLS enforcement. This is a learning-only loopback
service, **not** a general-purpose production HTTPS proxy.

## Phase 34: minimal gateway configuration file

Instead of typing seven or eight positional arguments, you can start the
existing event-driven HTTPS gateway using a small local `key = value` file.
Only the launch path is new; the original CLI modes and TLS behavior remain
unchanged.

```bash
cp config/gateway.conf.example gateway.conf
make certs                   # if not already generated
make
./build/tls-gateway --check-config gateway.conf
# Terminal 1: python3 tests/http_backend.py
# Terminal 2: ./build/tls-gateway --config gateway.conf
# Terminal 3: curl --noproxy '*' --cacert certs/ca.crt \
#   https://localhost:18444/health
python3 tests/test_gateway_config.py
```

Required keys: `listen_port`, `backend_port`, `server_cert`, `server_key`.
Optional: `api_cert` and `api_key` (must appear together), `require_mtls`
(`true` or `false`, default `false`), and `client_ca` (required only with
`require_mtls=true`). Example for mTLS + two hostnames:

```ini
listen_port = 18444
backend_port = 18081
server_cert = certs/server.crt
server_key = certs/server.key
api_cert = certs/api.test.crt
api_key = certs/api.test.key
require_mtls = true
client_ca = certs/ca.crt
```

Run `make certs-sni` and `make certs-client` to prepare optional features.
Each key appears once. Blank lines and full-line `#` comments are allowed;
unknown keys, duplicates, empty paths, invalid ports, and inconsistent mTLS
settings are rejected **before binding**. There are no sections, includes,
environment expansion, inline comments, or shell quoting. Paths are resolved
against the **process working directory**, not the config file's directory;
run the example from the repository root. `--check-config` checks syntax
and relationships, **not** whether certificates are valid or ports are free;
`--config` performs normal OpenSSL and bind validation on startup.

`gateway.conf` is ignored by Git; only the sanitized example config is
committed. Store **paths**, never private keys or passphrases, in config files.
`SIGHUP` still reloads TLS credentials **from the paths captured at startup**;
it does not re-read configuration or change ports. Keep the gateway bound
to loopback; this remains an educational HTTP/1.1 GET-only proxy.
The Phase 34 personal learning PDF stays outside the repository.

## Phase 35: Resource ownership and failure-path regression

The event-driven HTTPS proxy now uses one `close_upstream()` path for
upstream socket cleanup during normal teardown and `400`/`502` failures.
A `ProxySession` owns its `SSL *` and upstream fd; `ConnectionRegistry`
own its accepted client fd; TLS credential generations are reference-counted
until all sessions using them finish. The client teardown path unregisters
fds from epoll, frees SSL, releases the credential reference, and closes the
accepted socket. A debug assertion detects invalid credential refcounts.

```bash
make clean && make
make test-resources                  # focused process-level cleanup tests
make test                            # all Python regressions
```

The new Python test uses Linux `/proc/<pid>/fd` to ensure the descriptor
count returns to baseline after interrupted handshakes, rejected mTLS
clients, concurrent HTTPS requests, certificate reloads, and backend
connection refusals. It also verifies SIGTERM and port reuse. It generates
throwaway certificates and uses loopback-only ephemeral ports.

To investigate descriptors manually, inspect `/proc/$(pgrep -n tls-gateway)/fd`
or use `ls -l /proc/<PID>/fd` (replace `<PID>` with the actual process ID).
For optional sanitizer exercises, build with matching compiler/linker flags:

```bash
make clean
make CFLAGS='-std=c17 -Wall -Wextra -Wpedantic -Werror -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined' LDFLAGS='-fsanitize=address,undefined'
make test-resources
make clean && make
```

The sanitizer build is an **optional experiment**; `/proc` fd counts are
not a substitute for heap-leak detection, and passing these tests does not
prove the gateway is production-hardened. All learning PDFs are kept outside
Git and are not part of this source ZIP.

## Phase 36: monotonic connection timeouts (2027-01-05)

The event-driven `--epoll-tls-proxy` and config-driven gateway enforce **idle**
limits per stage using `CLOCK_MONOTONIC` rather than the system wall clock.
The clock refreshes on successful reads/writes or a real state transition,
not on `epoll` readiness alone.

| Gateway stage | No-progress deadline | Result |
|---|---:|---|
| TLS handshake | 4 seconds | Close unauthenticated socket |
| Authenticated HTTP request | 5 seconds | HTTP 408, then close |
| Backend TCP connect | 4 seconds | HTTPS 504, then close |
| Backend request send / response receive | 5 seconds | HTTPS 504 if response not begun; otherwise close |
| TLS response write | 5 seconds | Close stalled receiver |

These small values are deliberately chosen for a local educational lab, not
production tuning. A timed-out upstream gets **504**, whereas an immediate
connection failure still gets **502**. Once any response bytes have been sent,
the gateway does not attempt to replace the HTTP status. This is a single-GET,
connection-close-only learning proxy: it does not support persistent HTTP or
request bodies.

```bash
make test-timeouts
make test
```

The timeout test uses disposable CA and server certificates and a loopback
Python backend; it does not put generated credentials in Git. The separate
personal learning PDF is *not* part of this repository.

## Phase 37: graceful shutdown and bounded connection draining (2027-01-06)

The event-driven HTTPS proxy (`--epoll-tls-proxy`, `--epoll-tls-proxy-mtls`,
and `--config`) now handles `SIGTERM` and `SIGINT` by **closing the listener
first**, then servicing existing client/backend sockets for a shared **4-second
shutdown grace period**. If no sessions remain, it exits immediately. On grace
expiry it tears down any remaining sessions using the existing cleanup path.
The handler itself only sets a `sig_atomic_t` flag; socket and OpenSSL work
happens in the main event loop. Signals no longer immediately abort accepted
requests. New TCP connections are refused once draining begins.

```bash
make test-drain             # focused graceful-shutdown tests (~5 seconds)
make test                   # full regression suite
# Terminal A: python3 tests/http_backend.py
# Terminal B: ./build/tls-gateway --config gateway.conf
# Terminal C: pgrep -af tls-gateway
# Terminal C: kill -TERM <gateway-pid>
# Terminal C: ss -ltnp '( sport = :18444 )' # listener disappears
```

Expected logs include `TLS proxy draining: listener closed; grace=4000 ms`,
followed by either `TLS proxy drain complete: no active clients` or
`TLS proxy drain deadline reached: closing N clients`. Already-accepted
requests may finish during the grace interval; no new clients are accepted.
This is a process-local, in-memory shutdown policy, not multi-process
zero-downtime deployment or HTTP keep-alive draining. It does not override the
normal per-stage idle deadlines from Phase 36. The separate Phase 37 learning
PDF remains outside the repository.

## Phase 38: reproducible Python integration test runner

`make test` runs a small runner self-test, then executes `smoke_test.py` and
all `tests/test_*.py` files in filename order. No third-party Python package
is needed. Individual test scripts run in separate process groups, so a
hanging test times out and its child backend/gateway processes are stopped.
A test failure makes `make test` return a nonzero exit code.

```bash
make test-list                            # inspect discovered scripts
make test-runner                          # test the runner itself
make test-smoke                           # fast smoke test
python3 tests/run_tests.py --match mtls   # focused regression subset
python3 tests/run_tests.py --repeat 2 --match epoll_tls_proxy
python3 tests/run_tests.py --timeout 120  # full suite; 120s per test
make test                                 # standard regression command
```

Output reports each script's result and duration, then a summary. A failure
prints the last 50 lines of captured output. The default 90-second **per-script**
limit is a guard, not a performance target. Do not assume tests passing on
loopback proves the gateway is secure for public internet deployment.
