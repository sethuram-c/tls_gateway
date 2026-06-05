# TLS Gateway (learning project)

C17 + GNU Make on Fedora. The gateway is built incrementally and tested using Python's standard library.

## Build and run tests

```bash
make
make test
```

## Phase 5: local HTTP backend

Start the **Python** backend in one terminal:

```bash
python3 tests/http_backend.py
```

Exercise it in another terminal:

```bash
curl -i http://127.0.0.1:18081/
curl -i http://127.0.0.1:18081/health
curl -i http://127.0.0.1:18081/unknown
```

Stop with Ctrl+C. For a custom test port, pass `--port 18082`.
The C TCP server from Phase 4 is still available as `./build/tls-gateway --tcp-server`.
**There is no connection between the C server and the Python HTTP backend yet.** That begins in Phase 6.
Everything binds to 127.0.0.1; do not expose the practice backend to external networks.
