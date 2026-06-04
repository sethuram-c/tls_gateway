#define _POSIX_C_SOURCE 200809L
#include "tcp_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Loopback-only teaching server. One connection at a time. */
static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signum)
{
    (void)signum;
    stop_requested = 1;
}

static int send_all(int fd, const char *data, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        ssize_t n = send(fd, data + sent, length - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

int run_tcp_server(void)
{
    struct sigaction action = {0};
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        perror("sigaction");
        return 1;
    }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == -1) {
        perror("socket");
        return 1;
    }
    int reuse = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        close(listener);
        return 1;
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(18080);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1 ||
        bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(listener, 16) < 0) {
        perror("bind/listen");
        close(listener);
        return 1;
    }
    puts("TCP server listening on 127.0.0.1:18080");
    fflush(stdout);

    static const char reply[] = "Hello from the C TCP server!\n";
    while (!stop_requested) {
        struct sockaddr_in peer = {0};
        socklen_t peer_len = sizeof(peer);
        int client = accept(listener, (struct sockaddr *)&peer, &peer_len);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            close(listener);
            return 1;
        }
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        printf("Client connected: %s:%u\n", ip, (unsigned)ntohs(peer.sin_port));
        fflush(stdout);
        if (send_all(client, reply, sizeof(reply) - 1) < 0) perror("send");
        if (close(client) < 0) perror("close(client)");
    }
    if (close(listener) < 0) {
        perror("close(listener)");
        return 1;
    }
    puts("TCP server stopped");
    return 0;
}
