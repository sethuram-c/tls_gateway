#include "gateway_config.h"
#include "tcp_proxy.h"
#include "backend_connect.h"
#include "log.h"
#include "nonblock_demo.h"
#include "epoll_demo.h"
#include "epoll_server.h"
#include "epoll_tls.h"
#include "epoll_tls_proxy.h"
#include "socket_demo.h"
#include "tcp_server.h"
#include "tls_context.h"
#include "tls_listener.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage: tls-gateway [--help | --version | --config FILE | --check-config FILE | --socket-demo | --nonblock-demo | --epoll-demo | --epoll-server PORT | --epoll-tls CERT KEY PORT | --epoll-tls-connect CERT KEY TLS_PORT BACKEND_PORT | --epoll-tls-proxy CERT KEY TLS_PORT BACKEND_PORT [API_CERT API_KEY] | --epoll-tls-proxy-mtls CERT KEY TLS_PORT BACKEND_PORT CLIENT_CA [API_CERT API_KEY] | --tcp-server | --backend-connect PORT | --tcp-proxy LISTEN_PORT BACKEND_PORT | --tls-check CERT KEY | --tls-listen CERT KEY PORT | --tls-proxy CERT KEY LISTEN_PORT BACKEND_PORT]\n");
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
    if (argc == 3 && (strcmp(argv[1], "--config") == 0 ||
                      strcmp(argv[1], "--check-config") == 0)) {
        GatewayConfig config;
        if (gateway_config_load(argv[2], &config) < 0) return 2;
        if (strcmp(argv[1], "--check-config") == 0) {
            printf("Config OK: listener=%u backend=%u mTLS=%s SNI=%s\n",
                   (unsigned)config.listen_port, (unsigned)config.backend_port,
                   config.require_mtls ? "on" : "off",
                   config.api_cert[0] ? "localhost+api.test" : "default-only");
            return 0;
        }
        return run_epoll_tls_proxy(config.server_cert, config.server_key,
                                   config.listen_port, config.backend_port,
                                   config.api_cert[0] ? config.api_cert : NULL,
                                   config.api_key[0] ? config.api_key : NULL,
                                   config.require_mtls ? config.client_ca : NULL);
    }
    if (argc == 2 && strcmp(argv[1], "--socket-demo") == 0) return run_socket_demo();
    if (argc == 2 && strcmp(argv[1], "--nonblock-demo") == 0) return run_nonblock_demo();
    if (argc == 2 && strcmp(argv[1], "--epoll-demo") == 0) return run_epoll_demo();
    if (argc == 2 && strcmp(argv[1], "--tcp-server") == 0) return run_tcp_server();
    if (argc == 3 && strcmp(argv[1], "--epoll-server") == 0) {
        unsigned short port;
        if (parse_port(argv[2], &port) < 0) {
            fputs("invalid epoll listener port (expected 1..65535)\n", stderr);
            return 2;
        }
        return run_epoll_server(port);
    }
    if (argc == 5 && strcmp(argv[1], "--epoll-tls") == 0) {
        unsigned short port;
        if (parse_port(argv[4], &port) < 0) {
            fputs("invalid epoll TLS listener port (expected 1..65535)\n", stderr);
            return 2;
        }
        return run_epoll_tls(argv[2], argv[3], port);
    }
    if (((argc == 6 || argc == 8) && strcmp(argv[1], "--epoll-tls-proxy") == 0) ||
        ((argc == 7 || argc == 9) && strcmp(argv[1], "--epoll-tls-proxy-mtls") == 0)) {
        bool require_mtls = strcmp(argv[1], "--epoll-tls-proxy-mtls") == 0;
        unsigned short listen_port, backend_port;
        if (parse_port(argv[4], &listen_port) < 0 ||
            parse_port(argv[5], &backend_port) < 0 ||
            listen_port == backend_port) {
            fputs("invalid epoll TLS proxy ports (1..65535, must differ)\n", stderr);
            return 2;
        }
        return run_epoll_tls_proxy(argv[2], argv[3], listen_port, backend_port,
                                   argc == (require_mtls ? 9 : 8)
                                       ? argv[require_mtls ? 7 : 6] : NULL,
                                   argc == (require_mtls ? 9 : 8)
                                       ? argv[require_mtls ? 8 : 7] : NULL,
                                   require_mtls ? argv[6] : NULL);
    }
    if (argc == 6 && strcmp(argv[1], "--epoll-tls-connect") == 0) {
        unsigned short listen_port, backend_port;
        if (parse_port(argv[4], &listen_port) < 0 ||
            parse_port(argv[5], &backend_port) < 0 ||
            listen_port == backend_port) {
            fputs("invalid epoll TLS/backend ports (1..65535, must differ)\n", stderr);
            return 2;
        }
        return run_epoll_tls_with_backend(argv[2], argv[3],
                                          listen_port, backend_port);
    }
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
