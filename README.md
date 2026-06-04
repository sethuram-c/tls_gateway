# TLS Gateway (learning project)

C17 + GNU Make on Fedora. The gateway is built incrementally, with Python integration tests.

## Build and test

```bash
make
make test
```

## Phase 4: TCP server

```bash
./build/tls-gateway --tcp-server
# another terminal: nc 127.0.0.1 18080
# stop with Ctrl+C
```

For now the server is loopback-only, blocking, single-client-at-a-time, and replies with plain TCP text, **not** HTTP or TLS. Backend forwarding begins in later phases.

Previous CLI options (`--help`, `--version`, `--socket-demo`) still work.
