#!/usr/bin/env python3
"""Local-only HTTP backend for gateway development; no external dependencies."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
DEFAULT_PORT = 18081


class BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/health":
            body, status = b"ok\n", 200
        elif self.path == "/":
            body, status = b"hello from python backend\n", 200
        elif self.path == "/large":
            body, status = b"x" * (64 * 1024), 200
        else:
            body, status = b"not found\n", 404
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        # Output goes to stderr, separate from response bytes.
        super().log_message(format_string, *args)


def main():
    parser = argparse.ArgumentParser(description="Local HTTP test backend")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")
    server = ThreadingHTTPServer((HOST, args.port), BackendHandler)
    try:
        print(f"Python HTTP backend listening on http://{HOST}:{server.server_port}", flush=True)
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
