#define _POSIX_C_SOURCE 200809L
#include "tcp_proxy.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Educational blocking proxy: one client at a time. Phase 7 is not yet TLS. */
static volatile sig_atomic_t stop_requested = 0;
static void on_stop(int signum) { (void)signum; stop_requested = 1; }

static int connect_backend(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Preserve unsent bytes if send() only accepts part of a buffer. */
static int send_all(int fd, const unsigned char *buf, size_t len)
{
    size_t used = 0;
    while (used < len) {
        ssize_t n = send(fd, buf + used, len - used, MSG_NOSIGNAL);
        if (n > 0) used += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else return -1;
    }
    return 0;
}

/* select() monitors two directions. shutdown() propagates TCP half-closes. */
static int relay(int client, int backend)
{
    int client_read_open = 1, backend_read_open = 1;
    unsigned char buf[8192];
    while ((client_read_open || backend_read_open) && !stop_requested) {
        fd_set reads;
        FD_ZERO(&reads);
        if (client_read_open) FD_SET(client, &reads);
        if (backend_read_open) FD_SET(backend, &reads);
        int highest = client > backend ? client : backend;
        struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
        int ready = select(highest + 1, &reads, NULL, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("select");
            return -1;
        }
        if (ready == 0) continue;
        if (client_read_open && FD_ISSET(client, &reads)) {
            ssize_t n = recv(client, buf, sizeof(buf), 0);
            if (n > 0 && send_all(backend, buf, (size_t)n) != 0) return -1;
            if (n == 0) { client_read_open = 0; shutdown(backend, SHUT_WR); }
            if (n < 0 && errno != EINTR) return -1;
        }
        if (backend_read_open && FD_ISSET(backend, &reads)) {
            ssize_t n = recv(backend, buf, sizeof(buf), 0);
            if (n > 0 && send_all(client, buf, (size_t)n) != 0) return -1;
            if (n == 0) { backend_read_open = 0; shutdown(client, SHUT_WR); }
            if (n < 0 && errno != EINTR) return -1;
        }
    }
    return 0;
}

int run_tcp_proxy(unsigned short listen_port, unsigned short backend_port)
{
    struct sigaction action = {0};
    action.sa_handler = on_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) { perror("sigaction"); return 1; }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return 1; }
    int reuse = 1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(listen_port);
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 16) != 0) {
        perror("proxy listen"); close(listener); return 1;
    }
    printf("TCP proxy listening on 127.0.0.1:%u -> 127.0.0.1:%u\n",
           (unsigned)listen_port, (unsigned)backend_port);
    fflush(stdout);
    while (!stop_requested) {
        fd_set reads;
        FD_ZERO(&reads); FD_SET(listener, &reads);
        struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
        int ready = select(listener + 1, &reads, NULL, NULL, &timeout);
        if (ready < 0) { if (errno == EINTR) continue; perror("select"); break; }
        if (ready == 0) continue;
        int client = accept(listener, NULL, NULL);
        if (client < 0) { if (errno == EINTR) continue; perror("accept"); break; }
        int backend = connect_backend(backend_port);
        if (backend < 0) { perror("connect backend"); close(client); continue; }
        if (relay(client, backend) != 0) perror("relay");
        close(backend);
        close(client);
    }
    close(listener);
    puts("TCP proxy stopped");
    return 0;
}
