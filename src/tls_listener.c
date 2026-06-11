#define _POSIX_C_SOURCE 200809L
#include "tls_listener.h"
#include "tls_context.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;

static void request_stop(int signum)
{
    (void)signum;
    stop_requested = 1;
}

static int install_handlers(void)
{
    struct sigaction action = {0};
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGTERM, &action, NULL) == 0 ? 0 : -1;
}

int run_tls_listener(const char *certificate_path,
                     const char *private_key_path,
                     unsigned short port)
{
    SSL_CTX *context = tls_server_context_new(certificate_path, private_key_path);
    if (context == NULL) {
        fputs("Cannot initialize TLS listener: invalid TLS configuration\n", stderr);
        return 1;
    }

    stop_requested = 0;
    if (install_handlers() != 0) {
        perror("sigaction");
        SSL_CTX_free(context);
        return 1;
    }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        SSL_CTX_free(context);
        return 1;
    }
    const int reuse = 1;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse)) != 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 16) != 0) {
        perror("TLS listener socket setup");
        close(listener);
        SSL_CTX_free(context);
        return 1;
    }

    printf("TLS listener ready on 127.0.0.1:%u (no handshake yet)\n",
           (unsigned)port);
    fflush(stdout);

    int result = 0;
    while (!stop_requested) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;  /* Re-check shutdown flag. */
            perror("accept");
            result = 1;
            break;
        }

        /* Phase 11 ends here: attach TCP transport, do NOT call SSL_accept. */
        SSL *ssl = SSL_new(context);
        if (ssl == NULL || SSL_set_fd(ssl, client) != 1) {
            fputs("Cannot create per-client TLS object\n", stderr);
            ERR_print_errors_fp(stderr);
            result = 1;
        } else {
            puts("TCP client accepted; SSL object prepared (no handshake)");
            fflush(stdout);
        }

        /* SSL_set_fd uses a non-owning socket BIO; close fd explicitly. */
        SSL_free(ssl);
        close(client);
        if (result != 0) break;
    }

    close(listener);
    SSL_CTX_free(context);
    puts("TLS listener stopped");
    return result;
}
