# TLS Gateway

A minimal, educational TLS-terminating reverse proxy in C for Linux (Fedora).

## Status

Phase 1/44: Fedora toolchain and reproducible CMake smoke build.
The program is **not yet a network server**. Networking begins in later phases.

## Prerequisites (Fedora)

```bash
sudo dnf install -y gcc cmake make git openssl openssl-devel pkgconf-pkg-config gdb python3 curl
```

## Build and run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./build/tls-gateway
```

Expected output:

```text
tls-gateway: development environment ready
```

## Phase 1 verification

```bash
gcc --version
cmake --version
openssl version
pkg-config --modversion openssl
python3 --version
git --version
./build/tls-gateway
```

The phase-specific learning PDF is distributed separately, **not tracked in this repo**.
