#define _GNU_SOURCE
#include "epoll_tls.h"
#include "connection.h"
#include "socket_flags.h"
#include "output_buffer.h"
#include "tls_context.h"
#include "tls_state.h"

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
#define TLS_READ_CHUNK OUTPUT_BUFFER_CAPACITY
/* Educational safety limit: keep a client from monopolizing this lab. */
#define TLS_READ_LIMIT (64U * 1024U)

/* The shared Phase 20 registry owns fds; TLS sessions own SSL objects. */
typedef struct {
    SSL *ssl;
    time_t started;            /* Only used while the handshake is pending. */
    TlsState state;            /* HANDSHAKING / READING / WRITING / CLOSING. */
    OutputBuffer output;       /* Echo one read chunk; pause reads until drained. */
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
    /* A disconnected client must not terminate the event loop via SIGPIPE. */
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
    /* The low eight bits encode slot+1; see connection.c. */
    return (size_t)((connection->token & UINT64_C(255)) - 1);
}

/* Report state transitions in this lab. Production code should use a
 * controlled logger rather than print every request-related transition. */
static bool transition_session(TlsSession *session, int fd, TlsState next)
{
    TlsState old = session->state;
    if (!tls_state_move(&session->state, next)) {
        fprintf(stderr, "Invalid TLS state transition: fd=%d %s -> %s\n",
                fd, tls_state_name(old), tls_state_name(next));
        return false;
    }
    printf("TLS state: fd=%d %s -> %s\n", fd,
           tls_state_name(old), tls_state_name(next));
    return true;
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
    TlsSession *session = &sessions[slot];
    if (session->state != TLS_STATE_UNUSED &&
        session->state != TLS_STATE_CLOSING) {
        (void)transition_session(session, fd, TLS_STATE_CLOSING);
    }
    SSL_free(session->ssl);
    session->ssl = NULL;
    session->started = 0;
    output_buffer_init(&session->output);
    connection_release(registry, connection); /* Also closes the fd. */
    if (session->state == TLS_STATE_CLOSING) {
        (void)transition_session(session, fd, TLS_STATE_UNUSED);
    }
}

static int change_interest(int epfd, const Connection *connection,
                           uint32_t event_mask)
{
    struct epoll_event event = {0};
    event.data.u64 = connection->token;
    event.events = event_mask | EPOLLRDHUP;
    return epoll_ctl(epfd, EPOLL_CTL_MOD, connection->fd, &event);
}

/* Print bytes as hex, NOT as a NUL-terminated C string. Diagnostic only:
 * do not log decrypted request contents in a production proxy. */
static void log_read(int fd, const unsigned char *buffer, int length,
                     uint64_t total)
{
    int sample = length < 12 ? length : 12;
    printf("TLS application data: fd=%d bytes=%d total=%llu hex=",
           fd, length, (unsigned long long)total);
    for (int i = 0; i < sample; ++i) printf("%02x", buffer[i]);
    putchar('\n');
}

/* Non-blocking TLS connection-state driver. State reflects the *operation*,
 * not epoll readiness: WRITE can request EPOLLIN and READ can request EPOLLOUT.
 * A full pending output chunk pauses reads until written. A bounded number
 * of transitions per dispatch protects event-loop fairness. */
static void advance_io(int epfd, ConnectionRegistry *registry,
                       TlsSession sessions[CONNECTION_CAPACITY],
                       Connection *connection)
{
    TlsSession *session = &sessions[slot_for(connection)];
    for (unsigned int step = 0; step < 40; ++step) {
        size_t pending = output_buffer_pending(&session->output);
        if (session->state == TLS_STATE_WRITING) {
            if (pending == 0) {
                if (!transition_session(session, connection->fd,
                                        TLS_STATE_READING)) {
                    close_session(epfd, registry, sessions, connection);
                    return;
                }
                continue;
            }
            /* OpenSSL can request EPOLLIN even for an outgoing write. Never
             * assume that WANT_WRITE is the only way a write can pause. */
            int result = SSL_write(session->ssl,
                                   output_buffer_data(&session->output),
                                   (int)pending);
            if (result > 0) {
                if (output_buffer_consume(&session->output, (size_t)result) < 0) {
                    close_session(epfd, registry, sessions, connection);
                    return;
                }
                printf("TLS echoed: fd=%d bytes=%d queued=%zu\n",
                       connection->fd, result,
                       output_buffer_pending(&session->output));
                if (output_buffer_pending(&session->output) == 0 &&
                    !transition_session(session, connection->fd,
                                        TLS_STATE_READING)) {
                    close_session(epfd, registry, sessions, connection);
                    return;
                }
                continue;
            }
            int ssl_error = SSL_get_error(session->ssl, result);
            uint32_t wanted;
            if (ssl_error == SSL_ERROR_WANT_READ) wanted = EPOLLIN;
            else if (ssl_error == SSL_ERROR_WANT_WRITE) wanted = EPOLLOUT;
            else {
                fprintf(stderr, "TLS write failed: fd=%d ssl_error=%d\n",
                        connection->fd, ssl_error);
                close_session(epfd, registry, sessions, connection);
                return;
            }
            printf("TLS output backpressure: fd=%d pending=%zu\n",
                   connection->fd, pending);
            if (change_interest(epfd, connection, wanted) < 0) {
                perror("epoll_ctl MOD TLS write");
                close_session(epfd, registry, sessions, connection);
            }
            return;
        }

        if (session->state != TLS_STATE_READING) {
            close_session(epfd, registry, sessions, connection);
            return;
        }
        if (connection->bytes_read == TLS_READ_LIMIT) {
            printf("TLS read limit reached: fd=%d total=%llu\n",
                   connection->fd, (unsigned long long)connection->bytes_read);
            close_session(epfd, registry, sessions, connection);
            return;
        }

        unsigned char buffer[TLS_READ_CHUNK];
        size_t remaining = TLS_READ_LIMIT - connection->bytes_read;
        size_t capacity = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        int result = SSL_read(session->ssl, buffer, (int)capacity);
        if (result > 0) {
            connection->bytes_read += (uint64_t)result;
            log_read(connection->fd, buffer, result, connection->bytes_read);
            /* No pending writes: safe to reuse the single-chunk buffer. */
            if (output_buffer_enqueue(&session->output, buffer, (size_t)result) < 0) {
                fputs("TLS output buffer capacity exceeded\n", stderr);
                close_session(epfd, registry, sessions, connection);
                return;
            }
            if (!transition_session(session, connection->fd,
                                    TLS_STATE_WRITING)) {
                close_session(epfd, registry, sessions, connection);
                return;
            }
            continue;
        }
        int ssl_error = SSL_get_error(session->ssl, result);
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            printf("TLS close_notify received: fd=%d total=%llu\n",
                   connection->fd, (unsigned long long)connection->bytes_read);
            (void)SSL_shutdown(session->ssl); /* Non-blocking best effort. */
            close_session(epfd, registry, sessions, connection);
            return;
        }
        uint32_t wanted;
        if (ssl_error == SSL_ERROR_WANT_READ) wanted = EPOLLIN;
        else if (ssl_error == SSL_ERROR_WANT_WRITE) wanted = EPOLLOUT;
        else {
            fprintf(stderr, "TLS application read failed: fd=%d ssl_error=%d\n",
                    connection->fd, ssl_error);
            close_session(epfd, registry, sessions, connection);
            return;
        }
        if (change_interest(epfd, connection, wanted) < 0) {
            perror("epoll_ctl MOD TLS read");
            close_session(epfd, registry, sessions, connection);
        }
        return;
    }
    /* Avoid spinning on EPOLLOUT when no work is pending. If OpenSSL
     * already holds decrypted bytes, writable readiness schedules a retry. */
    uint32_t next = EPOLLIN;
    if (session->state == TLS_STATE_WRITING ||
        SSL_pending(session->ssl) > 0) next |= EPOLLOUT;
    if (change_interest(epfd, connection, next) < 0) {
        perror("epoll_ctl MOD TLS fairness");
        close_session(epfd, registry, sessions, connection);
    }
}

static void advance_handshake(int epfd, ConnectionRegistry *registry,
                              TlsSession sessions[CONNECTION_CAPACITY],
                              Connection *connection)
{
    TlsSession *session = &sessions[slot_for(connection)];
    int result = SSL_accept(session->ssl);
    if (result == 1) {
        if (!transition_session(session, connection->fd, TLS_STATE_READING)) {
            close_session(epfd, registry, sessions, connection);
            return;
        }
        printf("TLS 1.3 handshake complete: fd=%d %s / %s\n",
               connection->fd, SSL_get_version(session->ssl),
               SSL_get_cipher_name(session->ssl));
        /* App data may already be buffered in OpenSSL after the handshake.
         * Try SSL_read now instead of relying on a new epoll notification. */
        advance_io(epfd, registry, sessions, connection);
        return;
    }
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
        output_buffer_init(&session->output);
        if (!transition_session(session, fd, TLS_STATE_HANDSHAKING)) {
            SSL_free(session->ssl);
            session->ssl = NULL;
            connection_release(registry, connection);
            continue;
        }
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
    }
}

static void expire_handshakes(int epfd, ConnectionRegistry *registry,
                              TlsSession sessions[CONNECTION_CAPACITY])
{
    time_t now = time(NULL);
    if (now == (time_t)-1) return;
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
        Connection *connection = &registry->slots[i];
        if (connection->state == CONN_UNUSED ||
            sessions[i].state != TLS_STATE_HANDSHAKING) continue;
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
                TlsSession *session = &sessions[slot_for(connection)];
                switch (session->state) {
                case TLS_STATE_HANDSHAKING:
                    advance_handshake(epfd, &registry, sessions, connection);
                    break;
                case TLS_STATE_READING:
                case TLS_STATE_WRITING:
                    advance_io(epfd, &registry, sessions, connection);
                    break;
                case TLS_STATE_CLOSING:
                case TLS_STATE_UNUSED:
                default:
                    close_session(epfd, &registry, sessions, connection);
                    break;
                }
            }
        }
        expire_handshakes(epfd, &registry, sessions);
    }
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
