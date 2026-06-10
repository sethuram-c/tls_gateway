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
