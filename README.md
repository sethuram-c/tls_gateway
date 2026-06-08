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
