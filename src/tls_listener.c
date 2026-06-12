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
#include <sys/time.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;

static void request_stop(int signum)
{
    (void)signum;
    stop_requested = 1;
}

static int install_handlers(void)
{
    struct sigaction stop_action = {0};
    struct sigaction ignore_action = {0};
    stop_action.sa_handler = request_stop;
    ignore_action.sa_handler = SIG_IGN;
    sigemptyset(&stop_action.sa_mask);
    sigemptyset(&ignore_action.sa_mask);

    /* TLS peers can disconnect mid-write; handle EPIPE instead of SIGPIPE. */
    return sigaction(SIGINT, &stop_action, NULL) == 0 &&
           sigaction(SIGTERM, &stop_action, NULL) == 0 &&
           sigaction(SIGPIPE, &ignore_action, NULL) == 0 ? 0 : -1;
}

/* Blocking SSL_accept() must not let one stalled client block us forever. */
static int set_handshake_timeout(int fd)
{
    struct timeval timeout = {.tv_sec = 3, .tv_usec = 0};
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0 &&
           setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                      &timeout, sizeof(timeout)) == 0 ? 0 : -1;
}

/* Phase 12: complete only the TLS handshake (no application data yet). */
static int handshake_one_client(SSL_CTX *context, int client)
{
    SSL *ssl = SSL_new(context);
    if (ssl == NULL) {
        fputs("Cannot allocate per-client SSL object\n", stderr);
        ERR_print_errors_fp(stderr);
        return -1; /* Fatal local resource/configuration failure. */
    }

    if (SSL_set_fd(ssl, client) != 1) {
        fputs("Cannot attach TCP socket to SSL object\n", stderr);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return -1;
    }

    int accepted = SSL_accept(ssl);
    if (accepted == 1) {
        printf("TLS handshake complete: %s / %s\n",
               SSL_get_version(ssl), SSL_get_cipher(ssl));
        fflush(stdout);

        /* Send close_notify once. Phase 13 will introduce SSL_read(). */
        (void)SSL_shutdown(ssl);
    } else {
        int ssl_error = SSL_get_error(ssl, accepted);
        if (!stop_requested) {
            fprintf(stderr, "TLS handshake rejected (SSL error %d)\n", ssl_error);
            ERR_print_errors_fp(stderr);
        }
        /* A malformed/untrusted/disconnected peer must not kill the server. */
    }

    /* SSL_set_fd uses a socket BIO with BIO_NOCLOSE: caller closes client. */
    SSL_free(ssl);
    return 0;
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

    printf("TLS listener ready on 127.0.0.1:%u (TLS 1.3 handshake enabled)\n",
           (unsigned)port);
    fflush(stdout);

    int result = 0;
    while (!stop_requested) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue; /* Re-check stop_requested. */
            perror("accept");
            result = 1;
            break;
        }

        if (set_handshake_timeout(client) != 0) {
            perror("TLS handshake socket timeout");
            close(client);
            result = 1;
            break;
        }

        int status = handshake_one_client(context, client);
        close(client);  /* Always release the accepted TCP file descriptor. */
        if (status != 0) {
            result = 1;
            break;
        }
    }

    close(listener);
    SSL_CTX_free(context);
    puts("TLS listener stopped");
    return result;
}
