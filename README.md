# TLS Gateway

Educational TLS-terminating reverse proxy in **C17** for Fedora Linux.

## Current status

**Phase 2/44:** modular GNU Make build, diagnostic logging, CLI flags and Python smoke tests. Networking starts in the following phases.

## Fedora prerequisites

```bash
sudo dnf install -y gcc make git openssl openssl-devel pkgconf-pkg-config gdb python3 curl
```

## Build and verify

```bash
make
./build/tls-gateway
./build/tls-gateway --help
./build/tls-gateway --version
make test
make clean
```

GNU Make reads `Makefile`. Its `all` target compiles C17 objects and links the executable. `test` runs dependency-free Python smoke tests. `clean` removes generated files.

The default run prints an INFO diagnostic to **stderr**. `--help` and `--version` print to **stdout**. Unsupported arguments return exit status `2` and print an ERROR diagnostic to **stderr**.

## Repository layout

- `Makefile`: compile, link, test and clean
- `src/main.c`: command-line entry point
- `src/log.c`: diagnostic output
- `include/log.h`: diagnostic interface
- `tests/smoke_test.py`: Python CLI smoke tests
- `progress.md`: phase tracker

Phase learning PDFs are **outside this repository**. Never commit build outputs, local certificates or private keys.
