# How the gateway works

The code path described here is `run_epoll_tls_proxy()` in `src/epoll_tls_proxy.c`. There are older TCP and TLS examples in `src/`; those are separate exercises, not alternate production implementations.

## Request path

```text
HTTPS client          C gateway                       HTTP backend
     |                    |                                 |
     |--- TLS handshake ->|                                 |
     |                    |  SSL_accept / SNI / optional mTLS|
     |--- GET /health --->|                                 |
     |                    |--- connect() + plaintext GET -->|
     |                    |<---------- HTTP response -------|
     |<-- TLS response ---|                                 |
     |                    |                                 |
```

The gateway listens on `127.0.0.1` and connects to a backend on the same host. OpenSSL handles encryption on the client side. The upstream connection is ordinary TCP, so TLS does **not** extend to the backend.

The event loop registers accepted client sockets and backend sockets with `epoll`. When an operation cannot make progress, it waits for the relevant readiness event rather than blocking the entire server.

## Session states

The proxy's internal stages are:

```text
P_HANDSHAKE -> P_REQUEST -> P_CONNECT -> P_SEND_UPSTREAM
                                        -> P_READ_UPSTREAM -> P_SEND_CLIENT
                                        -> close
```

`SSL_accept()`, `SSL_read()`, and `SSL_write()` can return `SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE`. These results mean "try again when the socket is ready," not "the TLS connection failed." The operation and its pending bytes must be retained for the retry.

Request headers are assembled in a fixed 8 KiB buffer and validated before any upstream connection is opened. A second 8 KiB buffer holds chunks of the backend response. When that buffer has pending data, the gateway stops reading from the backend until the TLS client catches up. A large response can therefore be streamed without holding it all in memory.

Only a narrow HTTP/1.1 subset is supported: a single `GET`, a `Host` header, no request body, and no pipelining. Ambiguous framing and unsupported request forms are rejected rather than forwarded.

## Ownership and cleanup

The main structures are `ConnectionRegistry` (`src/connection.c`) and `ProxySession` (`src/epoll_tls_proxy.c`). The registry has 128 slots and associates each slot with a generation token, so a late `epoll` event can't refer to a new connection that reused the same slot.

For each client:

- The registry owns the accepted client file descriptor.
- The session owns its `SSL *`, optional backend descriptor, and fixed buffers.
- A session holds a reference to the TLS credential generation used for its handshake.

`close_client()` removes socket interests, closes the upstream if present, frees the `SSL` object, releases the credential reference, and then releases the client slot. In particular, freeing a reloaded certificate context before its last session finishes would leave the SNI callback with invalid data.

## TLS configuration

`src/tls_credentials.c` loads the active server contexts. `src/sni_select.c` chooses between `localhost` and `api.test`. With the second certificate configured, an unsupported DNS SNI name is rejected. No SNI uses the default certificate. The HTTP `Host` header doesn't choose a backend.

If mTLS is enabled, `src/mtls.c` configures certificate verification on both TLS contexts. A client must finish a verified handshake before the proxy connects upstream. Trusting a client CA authenticates membership in that trust set; there is no per-user authorization layer.

On `SIGHUP`, the signal handler sets a flag. The event loop loads and validates a complete replacement set of certificates, then swaps it into use for **new** connections. Existing sessions keep the old generation. If loading fails, the active generation is left alone. This reloads credentials, not the config file.

## Timeouts and shutdown

Deadlines use `CLOCK_MONOTONIC`. The configured-in-code limits are 4 seconds for the TLS handshake, 5 seconds for incomplete requests, 4 seconds for backend connect, and 5 seconds for backend I/O or TLS response-write inactivity. A stuck request can receive 408 or 504 where appropriate; once a response has started, the connection is closed instead of writing a second HTTP status.

`SIGINT` and `SIGTERM` close the listening socket and keep processing accepted clients for up to 4 seconds. Remaining sessions are then closed. These short values make the failure tests practical; they are not production tuning advice.

## Where to look

| File | What to inspect |
|---|---|
| `src/epoll_tls_proxy.c` | Event dispatch, HTTP parsing, forwarding, timeouts, shutdown |
| `src/backend_async.c` | Non-blocking `connect()` and `SO_ERROR` |
| `src/connection.c` | Slot allocation and generation tokens |
| `src/tls_credentials.c` | Reload and old-context lifetime |
| `src/sni_select.c`, `src/mtls.c` | TLS hostname and client-certificate policy |
| `src/gateway_config.c` | Config validation |
| `tests/test_epoll_tls_proxy.py` | Basic end-to-end HTTPS behavior |
| `tests/test_mtls_rejections.py` | Proving failed client authentication never reaches upstream |

## Trade-offs

A single event loop avoids a thread per client and makes socket state visible, but long CPU work would stall every connection. Fixed buffers cap per-session queue memory but also restrict supported requests. Loopback-only binding and the deliberately limited HTTP parser make this appropriate as a networking exercise, not as a drop-in replacement for nginx or HAProxy.
