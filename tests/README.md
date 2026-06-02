# Testing strategy

Phase 2 uses the Python standard library for command-line smoke tests:

```bash
make test
```

The test runs normal startup, `--help`, `--version`, and invalid-argument handling, checking output streams and exit codes. In future phases Python `pytest` will test actual TCP/TLS functionality.
