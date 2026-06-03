# TLS Gateway

Educational TLS-terminating reverse proxy in **C17** for Fedora Linux.

## Status

**Phase 3/44:** socket lifecycle demonstration (`socket`, `bind`, `listen`, `getsockname`, `close`) on loopback. **Not yet a running server or TLS proxy.**

## Fedora prerequisites

```bash
sudo dnf install -y gcc make git openssl openssl-devel pkgconf-pkg-config gdb python3 curl
```

## Build and verify

```bash
make
make test
./build/tls-gateway --socket-demo
./build/tls-gateway --help
make clean
```

`--socket-demo` binds to `127.0.0.1` on an ephemeral port chosen by the kernel, calls `listen()`, prints the assigned port, and immediately closes the socket. It does not accept connections. The normal CLI remains intact.

## Repository layout

- `Makefile`: GCC compilation and tests
- `src/main.c`: command-line entry point
- `src/socket_demo.c`: IPv4 listening socket lifecycle demo
- `include/socket_demo.h`: demo interface
- `src/log.c`, `include/log.h`: diagnostic logging
- `tests/smoke_test.py`: Python smoke and socket demo tests
- `progress.md`: phase tracker

Phase learning PDFs are kept **outside this repository**. Do not commit build outputs or private keys.
