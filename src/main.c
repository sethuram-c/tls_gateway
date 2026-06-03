#include "log.h"
#include "socket_demo.h"

#include <stdio.h>
#include <string.h>

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage: tls-gateway [--help | --version | --socket-demo]\n");
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

    if (argc == 2 && strcmp(argv[1], "--socket-demo") == 0) {
        return run_socket_demo();
    }

    if (argc != 1) {
        log_message(LOG_ERROR, "unsupported arguments");
        print_usage(stderr);
        return 2;
    }

    log_message(LOG_INFO, "startup checks completed (networking not enabled)");
    return 0;
}
