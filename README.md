# TLS Gateway

A TLS 1.3 reverse proxy written in C for Linux. It accepts HTTPS connections, decrypts requests with OpenSSL, forwards them to a local HTTP backend, and sends the responses back over TLS. Client and backend sockets run through one `epoll` event loop.

I kept the HTTP side deliberately small so I could focus on socket readiness, OpenSSL's non-blocking API, and connection cleanup. This is a loopback-only project, not a general-purpose or internet-facing proxy.

## Run it on Fedora

Install the build dependencies:

```sh
sudo dnf install gcc make openssl openssl-devel python3 curl
make
make certs
cp config/gateway.conf.example gateway.conf
./build/tls-gateway --check-config gateway.conf
```

`make certs` generates a local CA and a certificate for `localhost`. It refuses to overwrite an existing set of keys.

Start the backend and gateway in separate terminals:

```sh
python3 tests/http_backend.py
```

```sh
./build/tls-gateway --config gateway.conf
```

Make a verified request from a third terminal:

```sh
curl --noproxy '*' --cacert certs/ca.crt \
  https://localhost:18444/health
```

You should get `ok`. The example config listens on `127.0.0.1:18444` and forwards to `127.0.0.1:18081` without encrypting the backend connection.

## Features

- TLS 1.3 termination using OpenSSL; non-blocking client and backend I/O with `epoll`.
- Certificate selection for `localhost` and `api.test` using SNI.
- Optional client-certificate authentication (mTLS), enforced before opening a backend connection.
- Certificate reload on `SIGHUP`. New connections use the replacement certificates; established connections retain the old TLS context until they finish.
- Fixed-size request/response buffers, backpressure, connection timeouts, and a short shutdown drain period.
- Explicit handling of malformed requests and selected upstream failures (400, 408, 502, 504).

The main proxy implementation is in [`src/epoll_tls_proxy.c`](src/epoll_tls_proxy.c). Earlier command-line socket and TLS demos are still available in the executable, but `--config` is the normal entry point.

### Second certificate and client authentication

```sh
make certs-sni
make certs-client
```

To enable both, set the following in your local `gateway.conf`:

```ini
api_cert = certs/api.test.crt
api_key = certs/api.test.key
require_mtls = true
client_ca = certs/ca.crt
```

Restart the gateway after changing the config. Then test `api.test` with its client certificate:

```sh
curl --noproxy '*' --cacert certs/ca.crt \
  --cert certs/client.crt --key certs/client.key \
  --resolve api.test:18444:127.0.0.1 \
  https://api.test:18444/health
```

Without mTLS enabled, omit `--cert` and `--key`. To reload certificate files at the configured paths, send `SIGHUP` to the running gateway. Changing `gateway.conf` itself requires a restart.

Keep the generated CA and private keys local. `certs/` and `gateway.conf` are ignored by Git; do not include them when sharing a source archive.

## Tests and profiling

```sh
make test               # all Python integration tests
make test-edge          # malformed HTTP and early disconnects
make test-timeouts      # idle clients and backends
make test-resources     # fd cleanup under failed and concurrent sessions
make test-drain         # graceful shutdown
make asan               # AddressSanitizer build
make ubsan              # UndefinedBehaviorSanitizer build
make test-sanitize      # HTTPS smoke tests against both builds
make verify             # source hygiene + full test suite
```

Tests use temporary certificates and local ports; they don't require a globally trusted development CA. See [tests/README.md](tests/README.md) for running individual tests and diagnosing failures.

For local benchmarks, start the backend and non-mTLS gateway first, then run:

```sh
make bench
pgrep -af tls-gateway
make bench-profile PID=12345    # replace with the gateway PID
```

Both scripts create a new verified TLS connection per request, so their latency includes handshake cost. Results go into the ignored `bench_results/` directory. I haven't included machine-dependent RPS numbers in this README.

## Limits

This proxy handles one bodyless HTTP/1.1 `GET` per TLS connection. It does not implement keep-alive, request bodies, HTTP/2, WebSockets, upstream TLS, load balancing, or arbitrary host routing. The connection registry has 128 slots; request and response buffers are 8 KiB each. Both hops bind to IPv4 loopback.

The HTTP parser only accepts a restricted subset of requests. Passing the tests (including sanitizer runs) doesn't make it safe to expose publicly.

For the event flow, TLS context ownership, and design choices, see [docs/architecture.md](docs/architecture.md). The smaller networking exercises are summarized in [progress.md](progress.md).
