# Development notes

The gateway started as a blocking TCP proxy, then gained TLS termination and moved to a non-blocking `epoll` loop. The early command-line demos are still compiled for reference; the config-driven proxy is the implementation to look at now.

The main steps were:

- Built basic TCP listeners and a local Python backend to check forwarding.
- Added OpenSSL context setup, certificate validation, TLS handshakes, and HTTPS responses.
- Reworked client handling around `epoll`, per-connection state, bounded buffers, and non-blocking upstream sockets.
- Added SNI certificate selection, optional mTLS, and certificate reload without dropping established sessions.
- Tested malformed requests, timeouts, disconnects, cleanup, and graceful shutdown.
- Added Python integration tests, sanitizer builds, HTTPS benchmarks, and Linux resource profiling.

The Git history has the individual implementation steps. Current usage and known limitations are documented in `README.md`; `docs/architecture.md` covers the event loop and ownership rules.
