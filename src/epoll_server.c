#define _GNU_SOURCE
#include "epoll_server.h"
#include "socket_flags.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_CLIENTS 128
#define MAX_EVENTS 32
#define READ_BUDGET (64 * 1024)

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

static int find_slot(const int clients[MAX_CLIENTS])
{
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == -1) return i;
    }
    return -1;
}

static void close_client(int epfd, int clients[MAX_CLIENTS], int fd)
{
    /* EPOLL_CTL_DEL is explicit for clarity; close() also removes the
     * registration when the last reference to this fd is closed. */
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        perror("epoll_ctl DEL client");
    }
    close(fd);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == fd) {
            clients[i] = -1;
            break;
        }
    }
    printf("Client fd=%d closed\n", fd);
}

static int accept_ready_clients(int epfd, int listener, int clients[MAX_CLIENTS])
{
    for (;;) {
        struct sockaddr_in peer = {0};
        socklen_t length = sizeof(peer);
        /* accept4 atomically sets non-blocking + close-on-exec. */
        int fd = accept4(listener, (struct sockaddr *)&peer, &length,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            perror("accept4");
            return -1;
        }

        int slot = find_slot(clients);
        if (slot < 0) {
            fputs("Client rejected: connection limit reached\n", stderr);
            close(fd);
            continue;
        }
        struct epoll_event interest = {0};
        interest.events = EPOLLIN | EPOLLRDHUP; /* Level-triggered. */
        interest.data.fd = fd;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &interest) < 0) {
            perror("epoll_ctl ADD client");
            close(fd);
            return -1;
        }
        clients[slot] = fd;
        char ip[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip)) == NULL) {
            strncpy(ip, "unknown", sizeof(ip) - 1);
        }
        printf("Client accepted: %s:%u (fd=%d)\n", ip,
               (unsigned)ntohs(peer.sin_port), fd);
    }
}

static void read_ready_client(int epfd, int clients[MAX_CLIENTS], int fd)
{
    char buffer[4096];
    size_t received = 0;
    bool should_close = false;
    while (received < READ_BUDGET) {
        ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
        if (n > 0) {
            received += (size_t)n;
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
    if (received != 0) printf("Client fd=%d received %zu bytes\n", fd, received);
    if (should_close) close_client(epfd, clients, fd);
}

int run_epoll_server(unsigned short port)
{
    int clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; ++i) clients[i] = -1;
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
    interest.data.fd = listener;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listener, &interest) < 0) {
        perror("epoll_ctl ADD listener");
        close(epfd);
        close(listener);
        return 1;
    }

    /* Flush lines so a second terminal and the Python integration test can
     * observe acceptance/readiness without waiting for process exit. */
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
            int fd = events[i].data.fd;
            if (fd == listener) {
                if (accept_ready_clients(epfd, listener, clients) < 0) {
                    rc = 1;
                    stop_requested = 1;
                    break;
                }
            } else {
                /* A readable client may also carry RDHUP; recv() drains
                 * any remaining data and detects EOF correctly. */
                read_ready_client(epfd, clients, fd);
            }
        }
    }

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] != -1) close(clients[i]);
    }
    close(listener);
    close(epfd);
    puts("epoll TCP server stopped");
    return rc;
}
