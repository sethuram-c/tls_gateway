#define _GNU_SOURCE
#include "epoll_tls.h"
#include "connection.h"
#include "socket_flags.h"
#include "tls_context.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_EVENTS 32
#define LISTENER_TOKEN UINT64_C(0)
#define HANDSHAKE_TIMEOUT_SECONDS 10

/* A parallel TLS table preserves Phase 20's generic TCP registry API. */
typedef struct {
    SSL *ssl;              /* Owned here; freed before connection_release(). */
    time_t started;
} TlsSession;

static volatile sig_atomic_t stop_requested;

static void on_signal(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static int configure_signals(void)
{
    struct sigaction action = {0};
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGTERM, &action, NULL) < 0) return -1;
    /* TLS close_notify may race a peer close; never let SIGPIPE kill us. */
    struct sigaction ignore = {0};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    return sigaction(SIGPIPE, &ignore, NULL);
}

static int make_listener(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address = {0};
    int reuse = 1;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (socket_set_nonblocking(fd, true) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 ||
        bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(fd, 128) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static size_t slot_for(const Connection *connection)
{
    /* The low 8 bits encode slot + 1; see connection.c. */
    return (size_t)((connection->token & UINT64_C(255)) - 1);
}

static void close_session(int epfd, ConnectionRegistry *registry,
                          TlsSession sessions[CONNECTION_CAPACITY],
                          Connection *connection)
{
    size_t slot = slot_for(connection);
    int fd = connection->fd;
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) < 0 && errno != ENOENT) {
        perror("epoll_ctl DEL TLS client");
    }
    SSL_free(sessions[slot].ssl);
    sessions[slot].ssl = NULL;
    sessions[slot].started = 0;
    connection_release(registry, connection); /* Owns close(fd). */
}

static int change_interest(int epfd, const Connection *connection,
                           uint32_t event_mask)
{
    struct epoll_event event = {0};
    event.data.u64 = connection->token;
    event.events = event_mask | EPOLLRDHUP;
    return epoll_ctl(epfd, EPOLL_CTL_MOD, connection->fd, &event);
}

static void advance_handshake(int epfd, ConnectionRegistry *registry,
                              TlsSession sessions[CONNECTION_CAPACITY],
                              Connection *connection)
{
    TlsSession *session = &sessions[slot_for(connection)];
    /* socket is non-blocking, so SSL_accept never waits for network input. */
    int result = SSL_accept(session->ssl);
    if (result == 1) {
        printf("TLS 1.3 handshake complete: fd=%d %s / %s\n",
               connection->fd, SSL_get_version(session->ssl),
               SSL_get_cipher_name(session->ssl));
        /* Handshake-only lab: no application data handling until Phase 22. */
        (void)SSL_shutdown(session->ssl); /* Best-effort close_notify. */
        close_session(epfd, registry, sessions, connection);
        return;
    }

    /* Must inspect result immediately, before any further OpenSSL operation. */
    int ssl_error = SSL_get_error(session->ssl, result);
    uint32_t wanted;
    if (ssl_error == SSL_ERROR_WANT_READ) {
        wanted = EPOLLIN;
    } else if (ssl_error == SSL_ERROR_WANT_WRITE) {
        wanted = EPOLLOUT;
    } else {
        fprintf(stderr, "TLS handshake rejected: fd=%d ssl_error=%d\n",
                connection->fd, ssl_error);
        close_session(epfd, registry, sessions, connection);
        return;
    }
    if (change_interest(epfd, connection, wanted) < 0) {
        perror("epoll_ctl MOD TLS client");
        close_session(epfd, registry, sessions, connection);
    }
}

static void accept_ready(int epfd, int listener, SSL_CTX *context,
                         ConnectionRegistry *registry,
                         TlsSession sessions[CONNECTION_CAPACITY])
{
    for (;;) {
        struct sockaddr_in peer = {0};
        socklen_t length = sizeof(peer);
        int fd = accept4(listener, (struct sockaddr *)&peer, &length,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("accept4 TLS");
            return;
        }

        Connection *connection = connection_register(registry, fd, &peer);
        if (connection == NULL) {
            close(fd);
            continue;
        }
        TlsSession *session = &sessions[slot_for(connection)];
        session->ssl = SSL_new(context);
        session->started = time(NULL);
        if (session->ssl == NULL || SSL_set_fd(session->ssl, fd) != 1) {
            close_session(epfd, registry, sessions, connection);
            continue;
        }
        SSL_set_accept_state(session->ssl);
        struct epoll_event event = {0};
        event.events = EPOLLIN | EPOLLRDHUP;
        event.data.u64 = connection->token;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) < 0) {
            perror("epoll_ctl ADD TLS client");
            close_session(epfd, registry, sessions, connection);
            continue;
        }
        printf("TLS client accepted: fd=%d token=%llu active=%zu\n",
               fd, (unsigned long long)connection->token, registry->active);
        /* epoll_wait drives SSL_accept after socket readiness. */
    }
}

static void expire_handshakes(int epfd, ConnectionRegistry *registry,
                              TlsSession sessions[CONNECTION_CAPACITY])
{
    time_t now = time(NULL);
    if (now == (time_t)-1) return;
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
        Connection *connection = &registry->slots[i];
        if (connection->state == CONN_UNUSED) continue;
        if (sessions[i].started != (time_t)-1 &&
            now - sessions[i].started >= HANDSHAKE_TIMEOUT_SECONDS) {
            printf("TLS handshake timed out: fd=%d\n", connection->fd);
            close_session(epfd, registry, sessions, connection);
        }
    }
}

int run_epoll_tls(const char *certificate_path, const char *private_key_path,
                  unsigned short port)
{
    SSL_CTX *context = tls_server_context_new(certificate_path, private_key_path);
    if (context == NULL) {
        fputs("invalid TLS configuration\n", stderr);
        return 1;
    }
    stop_requested = 0;
    if (configure_signals() < 0) {
        perror("sigaction");
        SSL_CTX_free(context);
        return 1;
    }
    int listener = make_listener(port);
    if (listener < 0) {
        perror("TLS epoll listener socket setup");
        SSL_CTX_free(context);
        return 1;
    }
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        perror("epoll_create1 TLS");
        close(listener);
        SSL_CTX_free(context);
        return 1;
    }
    struct epoll_event event = {0};
    event.events = EPOLLIN;
    event.data.u64 = LISTENER_TOKEN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listener, &event) < 0) {
        perror("epoll_ctl ADD TLS listener");
        close(epfd);
        close(listener);
        SSL_CTX_free(context);
        return 1;
    }

    ConnectionRegistry registry;
    connection_registry_init(&registry);
    TlsSession sessions[CONNECTION_CAPACITY] = {{0}};
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("epoll TLS listener ready on 127.0.0.1:%u (TLS 1.3)\n", port);
    int status = 0;
    while (!stop_requested) {
        struct epoll_event events[MAX_EVENTS];
        int count = epoll_wait(epfd, events, MAX_EVENTS, 250);
        if (count < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait TLS");
            status = 1;
            break;
        }
        for (int i = 0; i < count && !stop_requested; ++i) {
            uint64_t token = events[i].data.u64;
            if (token == LISTENER_TOKEN) {
                accept_ready(epfd, listener, context, &registry, sessions);
            } else {
                Connection *connection = connection_lookup(&registry, token);
                if (connection == NULL) continue;
                advance_handshake(epfd, &registry, sessions, connection);
            }
        }
        expire_handshakes(epfd, &registry, sessions);
    }
    /* SSL objects are freed first, then the registry closes their sockets. */
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
        SSL_free(sessions[i].ssl);
        sessions[i].ssl = NULL;
    }
    connection_registry_close_all(&registry);
    close(listener);
    close(epfd);
    SSL_CTX_free(context);
    puts("epoll TLS listener stopped");
    return status;
}
