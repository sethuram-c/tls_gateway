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
