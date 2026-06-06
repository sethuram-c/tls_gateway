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
