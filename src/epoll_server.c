#define _GNU_SOURCE
#include "epoll_server.h"
#include "connection.h"
#include "socket_flags.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_EVENTS 32
#define READ_BUDGET (64 * 1024)
#define LISTENER_TOKEN UINT64_C(0)

static volatile sig_atomic_t stop_requested;

static void request_stop(int signum)
{
    (void)signum;
    stop_requested = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction action = {0};
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGTERM, &action, NULL) < 0) {
        perror("sigaction");
        return -1;
    }
    return 0;
}

static int open_listener(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    int reuse = 1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (socket_set_nonblocking(fd, true) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 ||
        bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 128) < 0) {
        perror("prepare listener");
        close(fd);
        return -1;
    }
    return fd;
}

static void close_client(int epfd, ConnectionRegistry *registry, Connection *client)
{
    int fd = client->fd;
    uint64_t total = client->bytes_read;
    /* DEL before close: an old queued event can no longer target this fd. */
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        perror("epoll_ctl DEL client");
    }
    connection_release(registry, client);
    printf("Client fd=%d total received=%llu bytes; active=%zu\n", fd,
           (unsigned long long)total, registry->active);
    printf("Client fd=%d closed\n", fd);
}

static int accept_ready_clients(int epfd, int listener, ConnectionRegistry *registry)
{
    for (;;) {
        struct sockaddr_in peer = {0};
        socklen_t length = sizeof(peer);
        int fd = accept4(listener, (struct sockaddr *)&peer, &length,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            perror("accept4");
            return -1;
        }
        Connection *client = connection_register(registry, fd, &peer);
        if (client == NULL) {
            fputs("Client rejected: connection limit reached\n", stderr);
            close(fd); /* Ownership was never transferred. */
            continue;
        }
        struct epoll_event interest = {0};
        interest.events = EPOLLIN | EPOLLRDHUP; /* Level-triggered. */
        interest.data.u64 = client->token;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &interest) < 0) {
            perror("epoll_ctl ADD client");
            connection_release(registry, client);
            return -1;
        }
        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip)) == NULL) {
            snprintf(ip, sizeof(ip), "unknown");
        }
        printf("Client accepted: %s:%u (fd=%d)\n", ip,
               (unsigned)ntohs(peer.sin_port), fd);
        printf("Connection token=%llu; active=%zu\n",
               (unsigned long long)client->token, registry->active);
    }
}

static void read_ready_client(int epfd, ConnectionRegistry *registry,
                              Connection *client)
{
    char buffer[4096];
    size_t received = 0;
    bool should_close = false;
    while (received < READ_BUDGET) {
        ssize_t n = recv(client->fd, buffer, sizeof(buffer), 0);
        if (n > 0) {
            received += (size_t)n;
            client->bytes_read += (uint64_t)n;
        } else if (n == 0) {
            should_close = true; /* EOF, not EAGAIN. */
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            perror("recv client");
            should_close = true;
            break;
        }
    }
    if (received != 0) {
        printf("Client fd=%d received %zu bytes\n", client->fd, received);
    }
    if (should_close) close_client(epfd, registry, client);
}

int run_epoll_server(unsigned short port)
{
    ConnectionRegistry registry;
    connection_registry_init(&registry);
    stop_requested = 0;
    if (install_signal_handlers() < 0) return 1;

    int listener = open_listener(port);
    if (listener < 0) return 1;
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        perror("epoll_create1");
        close(listener);
        return 1;
    }
    struct epoll_event interest = {0};
    interest.events = EPOLLIN;
    interest.data.u64 = LISTENER_TOKEN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listener, &interest) < 0) {
        perror("epoll_ctl ADD listener");
        close(epfd);
        close(listener);
        return 1;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("epoll TCP server listening on 127.0.0.1:%u\n", (unsigned)port);
    int rc = 0;
    while (!stop_requested) {
        struct epoll_event events[MAX_EVENTS];
        int count = epoll_wait(epfd, events, MAX_EVENTS, 250);
        if (count < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            rc = 1;
            break;
        }
        for (int i = 0; i < count && !stop_requested; ++i) {
            uint64_t token = events[i].data.u64;
            if (token == LISTENER_TOKEN) {
                if (accept_ready_clients(epfd, listener, &registry) < 0) {
                    rc = 1;
                    stop_requested = 1;
                    break;
                }
            } else {
                Connection *client = connection_lookup(&registry, token);
                if (client != NULL) {
                    /* Old tokens cannot refer to a reused slot or fd. */
                    read_ready_client(epfd, &registry, client);
                }
            }
        }
    }

    connection_registry_close_all(&registry);
    close(listener);
    close(epfd);
    puts("epoll TCP server stopped");
    return rc;
}
