#define _POSIX_C_SOURCE 200809L
#include "tls_listener.h"
#include "tls_context.h"
#include "tls_forward.h"

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

#define TLS_READ_CAPACITY 4096
#define TLS_HEX_PREVIEW_BYTES 24

/* An educational, fixed HTTP response. No request parsing or backend yet. */
static const unsigned char http_response[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Content-Length: 23\r\n"
    "Connection: close\r\n"
    "\r\n"
    "hello from tls gateway\n";

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

    /* Disconnected TLS peers should not terminate the whole process. */
    return sigaction(SIGINT, &stop_action, NULL) == 0 &&
           sigaction(SIGTERM, &stop_action, NULL) == 0 &&
           sigaction(SIGPIPE, &ignore_action, NULL) == 0 ? 0 : -1;
}

/* Blocking read and handshake must not wait forever for a silent peer. */
static int set_socket_timeout(int fd)
{
    struct timeval timeout = {.tv_sec = 3, .tv_usec = 0};
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0 &&
           setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                      &timeout, sizeof(timeout)) == 0 ? 0 : -1;
}

/* Avoid writing untrusted or binary client input directly into logs.
 * This short hexadecimal preview is for the local learning lab only. */
static void report_received_data(const unsigned char *bytes, int count)
{
    int shown = count < TLS_HEX_PREVIEW_BYTES ? count : TLS_HEX_PREVIEW_BYTES;
    printf("TLS application data read: %d bytes; first %d bytes (hex):",
           count, shown);
    for (int i = 0; i < shown; i++) {
        printf(" %02x", (unsigned)bytes[i]);
    }
    if (shown < count) printf(" ...");
    putchar('\n');
    fflush(stdout);
}

/* Phase 14: send a complete, fixed HTTP reply through the TLS channel.
 * SSL_write() can make less progress than requested; never ignore its count.
 * Blocking sockets have 3-second send/receive timeouts in this lab. */
static int write_http_response(SSL *ssl)
{
    size_t sent = 0;
    const size_t total = sizeof(http_response) - 1; /* exclude C's NUL */

    while (sent < total) {
        int remaining = (int)(total - sent); /* response is tiny */
        int written = SSL_write(ssl, http_response + sent, remaining);
        if (written <= 0) {
            int reason = SSL_get_error(ssl, written);
            fprintf(stderr, "TLS application write failed (SSL error %d)\n",
                    reason);
            ERR_print_errors_fp(stderr);
            return -1;
        }
        sent += (size_t)written;
    }

    printf("TLS HTTP response sent: %zu bytes\n", sent);
    fflush(stdout);
    return 0;
}

/* Phase 15: reuse TLS handshake and shutdown code for both lab modes.
 * Legacy listener sends a fixed reply; proxy mode calls tls_forward_request. */
static int serve_one_client(SSL_CTX *context, int client, unsigned short backend_port)
{
    SSL *ssl = SSL_new(context);
    if (ssl == NULL) {
        fputs("Cannot allocate per-client SSL object\n", stderr);
        ERR_print_errors_fp(stderr);
        return -1;
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

        if (backend_port != 0) {
            /* Phase 15: TLS ends here; the upstream leg is plain HTTP. */
            (void)tls_forward_request(ssl, backend_port);
        } else {
            unsigned char buffer[TLS_READ_CAPACITY];
            int received = SSL_read(ssl, buffer, (int)sizeof(buffer));
            if (received > 0) {
                /* SSL_read() returns decrypted APPLICATION bytes, not TLS records. */
                report_received_data(buffer, received);
                (void)write_http_response(ssl);
            } else {
                /* SSL_get_error() must receive this call's exact return value. */
                int reason = SSL_get_error(ssl, received);
                if (reason == SSL_ERROR_ZERO_RETURN) {
                    puts("TLS peer closed cleanly before sending application data");
                } else if (!stop_requested) {
                    fprintf(stderr, "TLS application read ended (SSL error %d)\n",
                            reason);
                    ERR_print_errors_fp(stderr);
                }
            }
        }
        fflush(stdout);
        /* One best-effort close_notify; never wait for the peer here. */
        (void)SSL_shutdown(ssl);
    } else {
        int reason = SSL_get_error(ssl, accepted);
        if (!stop_requested) {
            fprintf(stderr, "TLS handshake rejected (SSL error %d)\n", reason);
            ERR_print_errors_fp(stderr);
        }
    }

    /* SSL_set_fd() uses a non-owning socket BIO: caller closes client. */
    SSL_free(ssl);
    return 0;
}

static int run_tls_server(const char *certificate_path,
                          const char *private_key_path,
                          unsigned short port, unsigned short backend_port)
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

    if (backend_port == 0)
        printf("TLS listener ready on 127.0.0.1:%u (TLS 1.3 HTTPS reply lab)\n",
               (unsigned)port);
    else
        printf("TLS proxy ready on 127.0.0.1:%u -> 127.0.0.1:%u (TLS 1.3)\n",
               (unsigned)port, (unsigned)backend_port);
    fflush(stdout);

    int result = 0;
    while (!stop_requested) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            result = 1;
            break;
        }

        if (set_socket_timeout(client) != 0) {
            perror("TLS socket timeout");
            close(client);
            result = 1;
            break;
        }

        int status = serve_one_client(context, client, backend_port);
        close(client);
        if (status != 0) {
            result = 1;
            break;
        }
    }

    close(listener);
    SSL_CTX_free(context);
    puts(backend_port == 0 ? "TLS listener stopped" : "TLS proxy stopped");
    return result;
}

int run_tls_listener(const char *certificate_path,
                     const char *private_key_path, unsigned short port)
{
    return run_tls_server(certificate_path, private_key_path, port, 0);
}

int run_tls_proxy(const char *certificate_path,
                  const char *private_key_path, unsigned short port,
                  unsigned short backend_port)
{
    return run_tls_server(certificate_path, private_key_path, port, backend_port);
}
