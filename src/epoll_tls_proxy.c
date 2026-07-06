#define _GNU_SOURCE
#include "epoll_tls_proxy.h"
#include "backend_async.h"
#include "connection.h"
#include "socket_flags.h"
#include "sni_select.h"
#include "mtls.h"
#include "tls_credentials.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Educational constraints: HTTP/1.1 GET, one request per TLS connection.
 * Backpressure is implemented by parking the opposite socket while one
 * fixed-size buffer is in flight. Streaming responses are NOT size-limited. */
#define PROXY_BUFFER 8192U
#define PROXY_EVENTS 32
/* Milliseconds; small on purpose so Fedora labs finish quickly. */
#define HANDSHAKE_TIMEOUT_MS UINT64_C(4000)
#define REQUEST_IDLE_MS UINT64_C(5000)
#define BACKEND_CONNECT_MS UINT64_C(4000)
#define BACKEND_IDLE_MS UINT64_C(5000)
#define TLS_WRITE_IDLE_MS UINT64_C(5000)
/* Maximum time to finish already accepted requests after SIGINT/SIGTERM. */
#define SHUTDOWN_GRACE_MS UINT64_C(4000)
#define BACKEND_MARK (UINT64_C(1) << 63)

typedef enum {
    P_EMPTY, P_HANDSHAKE, P_REQUEST, P_CONNECT, P_SEND_UPSTREAM,
    P_READ_UPSTREAM, P_SEND_CLIENT
} ProxyStage;

typedef struct {
    SSL *ssl;
    TlsCredentials *credentials; /* keep SNI callback argument alive */
    int backend_fd;
    ProxyStage stage;
    uint64_t progress_at_ms; /* CLOCK_MONOTONIC, refreshed by actual I/O */
    unsigned char request[PROXY_BUFFER];
    size_t request_len, request_sent;
    unsigned char response[PROXY_BUFFER];
    size_t response_len, response_sent;
    bool upstream_eof;
    bool response_started; /* never replace a response after TLS writes */
} ProxySession;

/* A monotonic clock cannot jump backward due to wall-clock corrections. */
static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * UINT64_C(1000) +
           (uint64_t)ts.tv_nsec / UINT64_C(1000000);
}

static void made_progress(ProxySession *s)
{
    s->progress_at_ms = monotonic_ms();
}

static void change_stage(ProxySession *s, ProxyStage stage)
{
    s->stage = stage;
    made_progress(s);
}

static uint64_t stage_limit_ms(ProxyStage stage)
{
    switch (stage) {
    case P_HANDSHAKE: return HANDSHAKE_TIMEOUT_MS;
    case P_REQUEST: return REQUEST_IDLE_MS;
    case P_CONNECT: return BACKEND_CONNECT_MS;
    case P_SEND_UPSTREAM:
    case P_READ_UPSTREAM: return BACKEND_IDLE_MS;
    case P_SEND_CLIENT: return TLS_WRITE_IDLE_MS;
    case P_EMPTY: return 0;
    }
    return 0;
}

static volatile sig_atomic_t proxy_stop;
static volatile sig_atomic_t proxy_reload;

static void stop_handler(int sig)
{
    (void)sig;
    proxy_stop = 1;
}

static void reload_handler(int sig)
{
    (void)sig;
    proxy_reload = 1;
}

static int install_signals(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = stop_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0 ||
        sigaction(SIGTERM, &sa, NULL) < 0) return -1;
    sa.sa_handler = reload_handler;
    if (sigaction(SIGHUP, &sa, NULL) < 0) return -1;
    sa.sa_handler = SIG_IGN;
    return sigaction(SIGPIPE, &sa, NULL);
}

static int listener_create(unsigned short port)
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

static size_t session_slot(const Connection *connection)
{
    return (size_t)((connection->token & UINT64_C(255)) - 1);
}

static int watch_fd(int epfd, int how, int fd, uint64_t token, uint32_t mask)
{
    struct epoll_event event = {0};
    event.data.u64 = token;
    event.events = mask | EPOLLRDHUP;
    return epoll_ctl(epfd, how, fd, &event);
}

/* ProxySession owns backend_fd; unregister and close it exactly once.
 * TLS cleanup and error replies intentionally share this path. */
static void close_upstream(int epfd, ProxySession *s)
{
    if (s->backend_fd < 0) return;
    (void)epoll_ctl(epfd, EPOLL_CTL_DEL, s->backend_fd, NULL);
    (void)close(s->backend_fd);
    s->backend_fd = -1;
}

/* Ownership rules:
 * - ConnectionRegistry owns the accepted client fd.
 * - ProxySession owns its SSL object and optional upstream fd.
 * - A credential generation remains alive while sessions reference it.
 * Close the upstream, free SSL, release the generation, then close client. */
static void close_client(int epfd, ConnectionRegistry *registry,
                         ProxySession *sessions, Connection *connection)
{
    if (connection == NULL || connection->state != CONN_OPEN) return;
    ProxySession *s = &sessions[session_slot(connection)];
    (void)epoll_ctl(epfd, EPOLL_CTL_DEL, connection->fd, NULL);
    close_upstream(epfd, s);
    /* A best-effort close_notify is sufficient for this one-shot lab. */
    if (s->ssl != NULL && SSL_is_init_finished(s->ssl)) (void)SSL_shutdown(s->ssl);
    SSL_free(s->ssl);
    if (s->credentials != NULL) {
        /* A zero reference count indicates broken ownership, not EOF. */
        assert(s->credentials->users > 0);
        --s->credentials->users;
    }
    memset(s, 0, sizeof(*s));
    s->backend_fd = -1;
    connection_release(registry, connection);
}

static bool client_interest(int epfd, const Connection *c, uint32_t mask)
{
    return watch_fd(epfd, EPOLL_CTL_MOD, c->fd, c->token, mask) == 0;
}

static bool upstream_interest(int epfd, const Connection *c,
                              const ProxySession *s, uint32_t mask)
{
    return watch_fd(epfd, EPOLL_CTL_MOD, s->backend_fd,
                    c->token | BACKEND_MARK, mask) == 0;
}

/* Use an explicit Connection: close upstream so the HTTP/1.1 backend gives
 * us a reliable response boundary (EOF). This simple lab rejects methods
 * other than GET and does not support request bodies, pipelines, or upgrades. */
static int request_complete(ProxySession *s)
{
    const unsigned char *end = NULL;
    for (size_t i = 0; i + 3 < s->request_len; ++i) {
        if (memcmp(s->request + i, "\r\n\r\n", 4) == 0) {
            end = s->request + i;
            break;
        }
    }
    if (end == NULL) return 0;
    /* Reject bodies/pipelining and non-GET methods rather than risk truncation. */
    if (s->request_len != (size_t)(end - s->request) + 4 ||
        s->request_len < 14 || memcmp(s->request, "GET ", 4) != 0)
        return -1;
    size_t line_end = 0;
    while (line_end + 1 < s->request_len &&
           memcmp(s->request + line_end, "\r\n", 2) != 0) ++line_end;
    if (line_end + 1 >= s->request_len ||
        line_end < 9 || memcmp(s->request + line_end - 9, " HTTP/1.1", 9) != 0)
        return -1;
    /* Respect an explicit Connection: close. Reject other Connection
     * values (including keep-alive) instead of forwarding contradictory
     * hop-by-hop headers; adding a second header would be ambiguous. */
    for (size_t i = line_end + 2; i + 11 < s->request_len; ++i) {
        if (strncasecmp((const char *)s->request + i, "Connection:", 11) == 0 &&
            (i == line_end + 2 || (i >= 2 && memcmp(s->request + i - 2, "\r\n", 2) == 0))) {
            size_t value = i + 11;
            while (value < s->request_len &&
                   (s->request[value] == ' ' || s->request[value] == '\t')) ++value;
            if (value + 7 <= s->request_len &&
                strncasecmp((const char *)s->request + value, "close", 5) == 0 &&
                memcmp(s->request + value + 5, "\r\n", 2) == 0) return 1;
            return -1;
        }
    }
    static const char forced[] = "Connection: close\r\n";
    size_t insert = line_end + 2;
    if (s->request_len + sizeof(forced) - 1 > sizeof(s->request)) return -1;
    memmove(s->request + insert + sizeof(forced) - 1,
            s->request + insert, s->request_len - insert);
    memcpy(s->request + insert, forced, sizeof(forced) - 1);
    s->request_len += sizeof(forced) - 1;
    return 1;
}

static const unsigned char failure_reply[] =
    "HTTP/1.1 502 Bad Gateway\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 12\r\n"
    "Connection: close\r\n\r\n"
    "bad gateway\n";
static const unsigned char invalid_reply[] =
    "HTTP/1.1 400 Bad Request\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 12\r\n"
    "Connection: close\r\n\r\n"
    "bad request\n";

static const unsigned char request_timeout_reply[] =
    "HTTP/1.1 408 Request Timeout\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 16\r\n"
    "Connection: close\r\n\r\n"
    "request timeout\n";
static const unsigned char gateway_timeout_reply[] =
    "HTTP/1.1 504 Gateway Timeout\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 16\r\n"
    "Connection: close\r\n\r\n"
    "gateway timeout\n";

typedef enum {
    REPLY_BAD_GATEWAY,
    REPLY_BAD_REQUEST,
    REPLY_REQUEST_TIMEOUT,
    REPLY_GATEWAY_TIMEOUT
} ErrorReply;

static bool start_error_reply(int epfd, Connection *c, ProxySession *s,
                              ErrorReply kind)
{
    close_upstream(epfd, s);
    const unsigned char *data = failure_reply;
    size_t length = sizeof(failure_reply) - 1;
    if (kind == REPLY_BAD_REQUEST) {
        data = invalid_reply;
        length = sizeof(invalid_reply) - 1;
    } else if (kind == REPLY_REQUEST_TIMEOUT) {
        data = request_timeout_reply;
        length = sizeof(request_timeout_reply) - 1;
    } else if (kind == REPLY_GATEWAY_TIMEOUT) {
        data = gateway_timeout_reply;
        length = sizeof(gateway_timeout_reply) - 1;
    }
    memcpy(s->response, data, length);
    s->response_len = length;
    s->response_sent = 0;
    s->upstream_eof = true;
    change_stage(s, P_SEND_CLIENT);
    return client_interest(epfd, c, EPOLLOUT);
}

static bool open_upstream(int epfd, Connection *c, ProxySession *s,
                          unsigned short backend_port)
{
    int fd = -1;
    int result = backend_async_start(backend_port, &fd);
    if (result < 0) return start_error_reply(epfd, c, s, REPLY_BAD_GATEWAY);
    s->backend_fd = fd;
    change_stage(s, result == 0 ? P_CONNECT : P_SEND_UPSTREAM);
    if (watch_fd(epfd, EPOLL_CTL_ADD, fd, c->token | BACKEND_MARK,
                 EPOLLOUT) < 0) return start_error_reply(epfd, c, s, REPLY_BAD_GATEWAY);
    /* The client must not spin on buffered TLS data during upstream I/O. */
    return client_interest(epfd, c, 0);
}

/* Keep SNI logs bounded and printable; SNI is untrusted input. */
static void log_requested_sni(const SSL *ssl, const SSL_CTX *api_context)
{
    const char *raw = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (raw == NULL || *raw == '\0') {
        puts("TLS client SNI: (none)");
        return;
    }
    char safe[256];
    size_t i = 0;
    for (; raw[i] != '\0' && i < sizeof(safe) - 1; ++i) {
        unsigned char ch = (unsigned char)raw[i];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
            safe[i] = (char)ch;
        } else {
            safe[i] = '?';
        }
    }
    safe[i] = '\0';
    if (api_context == NULL) {
        printf("TLS client SNI: %s (default certificate; no SNI selection yet)\n", safe);
    } else {
        const char *selected = SSL_get_SSL_CTX(ssl) == api_context
                                   ? "api.test" : "localhost";
        printf("TLS client SNI: %s (selected %s certificate)\n", safe, selected);
    }
}

static bool tls_step(int epfd, Connection *c, ProxySession *s,
                     unsigned short backend_port,
                     bool mtls_required)
{
    if (s->stage == P_HANDSHAKE) {
        int n = SSL_accept(s->ssl);
        if (n == 1) {
            /* Defense in depth: the context MUST already reject untrusted
             * client certificates before allowing application data. */
            if (mtls_required && !mtls_peer_verified(s->ssl)) return false;
            if (mtls_required)
                printf("mTLS client certificate verified: fd=%d\n", c->fd);
            change_stage(s, P_REQUEST);
            log_requested_sni(s->ssl, s->credentials->alternate);
            printf("Non-blocking TLS handshake complete: fd=%d\n", c->fd);
        } else {
            int err = SSL_get_error(s->ssl, n);
            if (err == SSL_ERROR_WANT_READ) return client_interest(epfd, c, EPOLLIN);
            if (err == SSL_ERROR_WANT_WRITE) return client_interest(epfd, c, EPOLLOUT);
            return false;
        }
    }
    if (s->stage == P_REQUEST) {
        for (unsigned int attempt = 0; attempt < 16; ++attempt) {
            if (s->request_len == sizeof(s->request))
                return start_error_reply(epfd, c, s, REPLY_BAD_REQUEST);
            int n = SSL_read(s->ssl, s->request + s->request_len,
                             (int)(sizeof(s->request) - s->request_len));
            if (n > 0) {
                s->request_len += (size_t)n;
                made_progress(s);
                int ready = request_complete(s);
                if (ready < 0) return start_error_reply(epfd, c, s, REPLY_BAD_REQUEST);
                if (ready == 1) {
                    printf("Forwarding HTTPS GET: client_fd=%d request_bytes=%zu\n",
                           c->fd, s->request_len);
                    return open_upstream(epfd, c, s, backend_port);
                }
                continue;
            }
            int err = SSL_get_error(s->ssl, n);
            if (err == SSL_ERROR_WANT_READ) return client_interest(epfd, c, EPOLLIN);
            if (err == SSL_ERROR_WANT_WRITE) return client_interest(epfd, c, EPOLLOUT);
            return false;
        }
        /* SSL may have further decrypted bytes buffered internally. */
        return client_interest(epfd, c, EPOLLOUT);
    }
    if (s->stage == P_SEND_CLIENT) {
        for (unsigned int attempt = 0; attempt < 16; ++attempt) {
            if (s->response_sent == s->response_len) {
                if (s->upstream_eof) return false;
                change_stage(s, P_READ_UPSTREAM);
                s->response_len = s->response_sent = 0;
                if (!upstream_interest(epfd, c, s, EPOLLIN)) return false;
                return client_interest(epfd, c, 0);
            }
            int n = SSL_write(s->ssl, s->response + s->response_sent,
                              (int)(s->response_len - s->response_sent));
            if (n > 0) {
                s->response_sent += (size_t)n;
                s->response_started = true;
                made_progress(s);
                continue;
            }
            int err = SSL_get_error(s->ssl, n);
            if (err == SSL_ERROR_WANT_READ) return client_interest(epfd, c, EPOLLIN);
            if (err == SSL_ERROR_WANT_WRITE) return client_interest(epfd, c, EPOLLOUT);
            return false;
        }
        return client_interest(epfd, c, EPOLLOUT);
    }
    return true;
}

static bool backend_step(int epfd, Connection *c, ProxySession *s)
{
    if (s->stage == P_CONNECT) {
        if (backend_async_complete(s->backend_fd) < 0)
            return start_error_reply(epfd, c, s, REPLY_BAD_GATEWAY);
        change_stage(s, P_SEND_UPSTREAM);
    }
    if (s->stage == P_SEND_UPSTREAM) {
        for (unsigned int attempt = 0; attempt < 16; ++attempt) {
            if (s->request_sent == s->request_len) {
                change_stage(s, P_READ_UPSTREAM);
                return upstream_interest(epfd, c, s, EPOLLIN);
            }
            ssize_t n = send(s->backend_fd, s->request + s->request_sent,
                             s->request_len - s->request_sent, MSG_NOSIGNAL);
            if (n > 0) { s->request_sent += (size_t)n; made_progress(s); continue; }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                return upstream_interest(epfd, c, s, EPOLLOUT);
            return start_error_reply(epfd, c, s, REPLY_BAD_GATEWAY);
        }
        return upstream_interest(epfd, c, s, EPOLLOUT);
    }
    if (s->stage == P_READ_UPSTREAM) {
        ssize_t n = recv(s->backend_fd, s->response, sizeof(s->response), 0);
        if (n > 0) {
            s->response_len = (size_t)n;
            made_progress(s);
            s->response_sent = 0;
            change_stage(s, P_SEND_CLIENT);
            /* Pause backend reads until SSL_write drains this response chunk. */
            return upstream_interest(epfd, c, s, 0) &&
                   client_interest(epfd, c, EPOLLOUT);
        }
        if (n == 0) return false; /* Backend used Connection: close. */
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return true;
        return false;
    }
    return true;
}

static void accept_clients(int epfd, int listener, TlsCredentials *credentials,
                           ConnectionRegistry *registry, ProxySession *sessions)
{
    for (;;) {
        if (proxy_stop) return; /* Do not accept after a shutdown signal. */
        struct sockaddr_in peer = {0};
        socklen_t len = sizeof(peer);
        int fd = accept4(listener, (struct sockaddr *)&peer, &len,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("accept4 proxy");
            return;
        }
        Connection *c = connection_register(registry, fd, &peer);
        if (c == NULL) { close(fd); continue; }
        ProxySession *s = &sessions[session_slot(c)];
        memset(s, 0, sizeof(*s));
        s->backend_fd = -1;
        change_stage(s, P_HANDSHAKE);
        s->credentials = credentials;
        ++credentials->users;
        s->ssl = SSL_new(credentials->primary);
        if (s->ssl == NULL || SSL_set_fd(s->ssl, fd) != 1 ||
            watch_fd(epfd, EPOLL_CTL_ADD, fd, c->token, EPOLLIN) < 0) {
            close_client(epfd, registry, sessions, c);
            continue;
        }
        SSL_set_accept_state(s->ssl);
    }
}

/* Only the main event loop closes the listener.  Signal handlers only set
 * sig_atomic_t flags; epoll and close are never called from a handler. */
static void begin_shutdown(int epfd, int *listener, bool *draining,
                           uint64_t *drain_started_ms)
{
    if (!proxy_stop || *draining) return;
    *draining = true;
    *drain_started_ms = monotonic_ms();
    if (*listener >= 0) {
        (void)epoll_ctl(epfd, EPOLL_CTL_DEL, *listener, NULL);
        (void)close(*listener);
        *listener = -1;
    }
    printf("TLS proxy draining: listener closed; grace=%llu ms\n",
           (unsigned long long)SHUTDOWN_GRACE_MS);
}

static size_t active_clients(const ConnectionRegistry *registry)
{
    size_t active = 0;
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i)
        if (registry->slots[i].state == CONN_OPEN) ++active;
    return active;
}

int run_epoll_tls_proxy(const char *certificate_path, const char *private_key_path,
                        unsigned short tls_port, unsigned short backend_port,
                        const char *api_certificate_path, const char *api_key_path,
                        const char *client_ca_path)
{
    TlsCredentials *current = tls_credentials_load(
        certificate_path, private_key_path, api_certificate_path,
        api_key_path, client_ca_path);
    if (current == NULL) return 1;
    TlsCredentials *retired = NULL;
    proxy_stop = 0;
    proxy_reload = 0;
    int listener = -1, epfd = -1, status = 1;
    ProxySession *sessions = NULL;
    if (install_signals() < 0 || (listener = listener_create(tls_port)) < 0 ||
        (epfd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        perror("TLS proxy setup");
        goto cleanup;
    }
    if (watch_fd(epfd, EPOLL_CTL_ADD, listener, 0, EPOLLIN) < 0) {
        perror("epoll add listener");
        goto cleanup;
    }
    sessions = calloc(CONNECTION_CAPACITY, sizeof(*sessions));
    if (sessions == NULL) goto cleanup;
    ConnectionRegistry registry;
    connection_registry_init(&registry);
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("epoll TLS proxy ready on 127.0.0.1:%u -> 127.0.0.1:%u\n",
           tls_port, backend_port);
    if (client_ca_path != NULL) puts("mTLS mode: client certificate required");
    status = 0;
    bool draining = false;
    uint64_t drain_started_ms = 0;
    for (;;) {
        begin_shutdown(epfd, &listener, &draining, &drain_started_ms);
        /* A signal handler sets only a flag. Disk I/O and OpenSSL run here.
         * No old context is released until all its accepted clients close. */
        if (proxy_reload && !draining) {
            proxy_reload = 0;
            TlsCredentials *candidate = tls_credentials_load(
                certificate_path, private_key_path, api_certificate_path,
                api_key_path, client_ca_path);
            if (candidate != NULL) {
                TlsCredentials *old = current;
                current = candidate;
                old->next = retired;
                retired = old;
                puts("TLS credentials reloaded successfully (new clients only)");
            } else {
                fputs("TLS credential reload failed; keeping previous generation\n",
                      stderr);
            }
        }
        tls_credentials_collect(&retired);
        struct epoll_event events[PROXY_EVENTS];
        int count = epoll_wait(epfd, events, PROXY_EVENTS, 250);
        if (count < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait proxy");
            status = 1;
            break;
        }
        /* A signal may arrive during epoll_wait: disable acceptance before
         * dispatching any listener event in this batch. */
        begin_shutdown(epfd, &listener, &draining, &drain_started_ms);
        for (int i = 0; i < count; ++i) {
            uint64_t tag = events[i].data.u64;
            if (tag == 0) {
                if (!draining && !proxy_stop && listener >= 0)
                    accept_clients(epfd, listener, current, &registry, sessions);
                continue;
            }
            bool from_backend = (tag & BACKEND_MARK) != 0;
            Connection *c = connection_lookup(&registry, tag & ~BACKEND_MARK);
            if (c == NULL) continue; /* Reused slot: stale event. */
            ProxySession *s = &sessions[session_slot(c)];
            bool ok;
            if (from_backend) {
                if (s->backend_fd < 0) continue;
                ok = backend_step(epfd, c, s);
            } else if (s->stage == P_HANDSHAKE || s->stage == P_REQUEST ||
                       s->stage == P_SEND_CLIENT) {
                ok = tls_step(epfd, c, s, backend_port,
                              client_ca_path != NULL);
            } else {
                /* Parked client can still disconnect while the backend runs. */
                ok = (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) == 0;
            }
            if (!ok) close_client(epfd, &registry, sessions, c);
        }
        /* A deadline expires only when no useful I/O progress occurred;
         * a socket that repeatedly reports readiness cannot avoid it. */
        uint64_t now = monotonic_ms();
        if (now != 0) {
            for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
                Connection *c = &registry.slots[i];
                if (c->state != CONN_OPEN) continue;
                ProxySession *s = &sessions[i];
                uint64_t limit = stage_limit_ms(s->stage);
                if (limit == 0 || s->progress_at_ms == 0 ||
                    now < s->progress_at_ms ||
                    now - s->progress_at_ms < limit) continue;
                fprintf(stderr, "TLS proxy timeout: fd=%d stage=%d\n",
                        c->fd, (int)s->stage);
                bool reply = false;
                if (s->stage == P_REQUEST) {
                    reply = start_error_reply(epfd, c, s, REPLY_REQUEST_TIMEOUT);
                } else if ((s->stage == P_CONNECT ||
                            s->stage == P_SEND_UPSTREAM ||
                            s->stage == P_READ_UPSTREAM) &&
                           !s->response_started) {
                    reply = start_error_reply(epfd, c, s, REPLY_GATEWAY_TIMEOUT);
                }
                /* Handshake timeout: no HTTP possible.  Mid-response or
                 * blocked client write: closing is safer than rewriting it. */
                if (!reply) close_client(epfd, &registry, sessions, c);
            }
        }
        /* Keep servicing accepted clients, but only until the shared grace
         * deadline.  Expired sessions use the normal ownership cleanup. */
        if (draining) {
            size_t remaining = active_clients(&registry);
            if (remaining == 0) {
                puts("TLS proxy drain complete: no active clients");
                break;
            }
            uint64_t now_drain = monotonic_ms();
            if (now_drain == 0 || now_drain < drain_started_ms ||
                now_drain - drain_started_ms >= SHUTDOWN_GRACE_MS) {
                printf("TLS proxy drain deadline reached: closing %zu clients\n",
                       remaining);
                break;
            }
        }
    }
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
        if (registry.slots[i].state == CONN_OPEN)
            close_client(epfd, &registry, sessions, &registry.slots[i]);
    }
    puts("epoll TLS proxy stopped");
cleanup:
    free(sessions);
    if (epfd >= 0) close(epfd);
    if (listener >= 0) close(listener);
    tls_credentials_free(current);
    tls_credentials_collect(&retired);
    /* All sessions have been closed before cleanup. */
    return status;
}
