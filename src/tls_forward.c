#define _POSIX_C_SOURCE 200809L
#include "tls_forward.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define HEADER_LIMIT 8192
#define COPY_CHUNK 4096
#define RESPONSE_LIMIT (1024 * 1024)

/* Return exactly one small HTTP error without disclosing internal details. */
static int send_error_reply(SSL *tls, const char *status, const char *body)
{
    char response[256];
    int length = snprintf(response, sizeof(response),
                          "HTTP/1.1 %s\r\n"
                          "Content-Type: text/plain\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n\r\n%s",
                          status, strlen(body), body);
    if (length < 0 || (size_t)length >= sizeof(response)) return -1;
    size_t written = 0;
    while (written < (size_t)length) {
        int n = SSL_write(tls, response + written, (int)((size_t)length - written));
        if (n <= 0) return -1;
        written += (size_t)n;
    }
    return 0;
}

/* Only GET requests with a complete header terminator are supported today.
 * Limiting the request simplifies the exercise without pretending to provide
 * HTTP/1.1 message-body parsing or general-purpose proxy behavior. */
static int read_request_headers(SSL *tls, unsigned char *data, size_t *length)
{
    *length = 0;
    while (*length < HEADER_LIMIT) {
        int n = SSL_read(tls, data + *length, (int)(HEADER_LIMIT - *length));
        if (n <= 0) return -1;
        *length += (size_t)n;
        for (size_t i = 3; i < *length; i++) {
            if (memcmp(data + i - 3, "\r\n\r\n", 4) == 0) {
                /* Reject body/pipelined input; body forwarding comes later. */
                if (i + 1 != *length) return -1;
                if (*length < 5 || memcmp(data, "GET ", 4) != 0) return -2;
                /* No request body accepted in this transport-only lesson. */
                return 0;
            }
        }
    }
    return -1;
}

static int backend_connect(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = 3, .tv_usec = 0};
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int tcp_send_all(int fd, const unsigned char *data, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        ssize_t n = send(fd, data + sent, length - sent, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int tls_write_all(SSL *tls, const unsigned char *data, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        int n = SSL_write(tls, data + sent, (int)(length - sent));
        if (n <= 0) {
            fprintf(stderr, "TLS write failed (SSL error %d)\n", SSL_get_error(tls, n));
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

int tls_forward_request(SSL *client_tls, unsigned short backend_port)
{
    unsigned char headers[HEADER_LIMIT];
    size_t request_size = 0;
    int parsed = read_request_headers(client_tls, headers, &request_size);
    if (parsed != 0) {
        (void)send_error_reply(client_tls,
                               parsed == -2 ? "405 Method Not Allowed" : "400 Bad Request",
                               parsed == -2 ? "GET only\n" : "invalid request\n");
        return -1;
    }

    int upstream = backend_connect(backend_port);
    if (upstream < 0) {
        fprintf(stderr, "Upstream unavailable on 127.0.0.1:%u\n",
                (unsigned)backend_port);
        (void)send_error_reply(client_tls, "502 Bad Gateway", "backend unavailable\n");
        return -1;
    }

    int result = -1;
    if (tcp_send_all(upstream, headers, request_size) != 0 ||
        shutdown(upstream, SHUT_WR) != 0) {
        (void)send_error_reply(client_tls, "502 Bad Gateway", "backend write failed\n");
        goto done;
    }

    /* The upstream sees EOF after the complete request headers; this stops
     * HTTP/1.1 keep-alive from making our EOF-based response relay hang. */
    unsigned char chunk[COPY_CHUNK];
    size_t total = 0;
    for (;;) {
        ssize_t n = recv(upstream, chunk, sizeof(chunk), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            if (total == 0)
                (void)send_error_reply(client_tls, "502 Bad Gateway", "backend read failed\n");
            goto done;
        }
        if (n == 0) break;
        if ((size_t)n > RESPONSE_LIMIT - total) {
            if (total == 0)
                (void)send_error_reply(client_tls, "502 Bad Gateway", "response too large\n");
            goto done;
        }
        if (tls_write_all(client_tls, chunk, (size_t)n) != 0) goto done;
        total += (size_t)n;
    }
    if (total == 0) {
        (void)send_error_reply(client_tls, "502 Bad Gateway", "empty backend response\n");
        goto done;
    }
    printf("Forwarded HTTPS GET to 127.0.0.1:%u; %zu HTTP response bytes relayed\n",
           (unsigned)backend_port, total);
    fflush(stdout);
    result = 0;

done:
    close(upstream);
    return result;
}
