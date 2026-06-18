#include "tcp_proxy.h"
#include "backend_connect.h"
#include "log.h"
#include "nonblock_demo.h"
#include "epoll_demo.h"
#include "socket_demo.h"
#include "tcp_server.h"
#include "tls_context.h"
#include "tls_listener.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage: tls-gateway [--help | --version | --socket-demo | --nonblock-demo | --epoll-demo | --tcp-server | --backend-connect PORT | --tcp-proxy LISTEN_PORT BACKEND_PORT | --tls-check CERT KEY | --tls-listen CERT KEY PORT | --tls-proxy CERT KEY LISTEN_PORT BACKEND_PORT]\n");
}

static int parse_port(const char *text, unsigned short *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || text[0] == '\0' || *end != '\0' || value == 0 || value > 65535) return -1;
    *out = (unsigned short)value;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_usage(stdout);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("tls-gateway 0.1.0");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--socket-demo") == 0) return run_socket_demo();
    if (argc == 2 && strcmp(argv[1], "--nonblock-demo") == 0) return run_nonblock_demo();
    if (argc == 2 && strcmp(argv[1], "--epoll-demo") == 0) return run_epoll_demo();
    if (argc == 2 && strcmp(argv[1], "--tcp-server") == 0) return run_tcp_server();
    if (argc == 3 && strcmp(argv[1], "--backend-connect") == 0) {
        unsigned short port;
        if (parse_port(argv[2], &port) < 0) {
            fputs("invalid backend port (expected 1..65535)\n", stderr);
            return 2;
        }
        return run_backend_connect(port);
    }
    if (argc == 4 && strcmp(argv[1], "--tls-check") == 0) {
        return run_tls_check(argv[2], argv[3]);
    }
    if (argc == 5 && strcmp(argv[1], "--tls-listen") == 0) {
        unsigned short port;
        if (parse_port(argv[4], &port) < 0) {
            fputs("invalid TLS listener port (expected 1..65535)\n", stderr);
            return 2;
        }
        return run_tls_listener(argv[2], argv[3], port);
    }
    if (argc == 6 && strcmp(argv[1], "--tls-proxy") == 0) {
        unsigned short listen_port, backend_port;
        if (parse_port(argv[4], &listen_port) < 0 ||
            parse_port(argv[5], &backend_port) < 0 ||
            listen_port == backend_port) {
            fputs("invalid TLS proxy ports (1..65535, must differ)\n", stderr);
            return 2;
        }
        return run_tls_proxy(argv[2], argv[3], listen_port, backend_port);
    }
    if (argc == 4 && strcmp(argv[1], "--tcp-proxy") == 0) {
        unsigned short listen_port, backend_port;
        if (parse_port(argv[2], &listen_port) < 0 ||
            parse_port(argv[3], &backend_port) < 0 || listen_port == backend_port) {
            fputs("invalid proxy ports (1..65535, must differ)\n", stderr);
            return 2;
        }
        return run_tcp_proxy(listen_port, backend_port);
    }
    if (argc != 1) {
        log_message(LOG_ERROR, "unsupported arguments");
        print_usage(stderr);
        return 2;
    }
    log_message(LOG_INFO, "startup checks completed (proxy forwarding not enabled)");
    return 0;
}
