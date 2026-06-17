#include "nonblock_demo.h"
#include "socket_flags.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int is_would_block(int error)
{
    return error == EAGAIN || error == EWOULDBLOCK;
}

int run_nonblock_demo(void)
{
    int sockets[2] = {-1, -1};
    int status = 1;
    char input[8];
    static const char message[] = "hello";
    char block[4096];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
        perror("socketpair");
        return status;
    }
    if (socket_set_nonblocking(sockets[0], true) == -1) {
        perror("fcntl(O_NONBLOCK)");
        goto cleanup;
    }
    if (socket_is_nonblocking(sockets[0]) != 1 ||
        socket_is_nonblocking(sockets[1]) != 0) {
        fputs("unexpected socket flag state\n", stderr);
        goto cleanup;
    }
    puts("Non-blocking enabled on one socketpair endpoint");
    puts("Flag helper: endpoint 0 non-blocking; endpoint 1 blocking");

    /* 1. No data is available, but the peer is still connected. */
    ssize_t n = recv(sockets[0], input, sizeof input, 0);
    if (n != -1 || !is_would_block(errno)) {
        fputs("expected EAGAIN on empty non-blocking receive\n", stderr);
        goto cleanup;
    }
    puts("Empty recv: EAGAIN (not EOF)");

    /* 2. Send five bytes and deliberately read in smaller pieces. */
    n = send(sockets[1], message, sizeof message - 1, 0);
    if (n != (ssize_t)(sizeof message - 1)) {
        perror("send test payload");
        goto cleanup;
    }
    n = recv(sockets[0], input, 2, 0);
    if (n != 2 || memcmp(input, "he", 2) != 0) {
        fputs("expected a two-byte partial read\n", stderr);
        goto cleanup;
    }
    printf("First recv: %zd bytes (he)\n", n);
    n = recv(sockets[0], input, sizeof message - 1 - 2, 0);
    if (n != 3 || memcmp(input, "llo", 3) != 0) {
        fputs("expected the remaining three bytes\n", stderr);
        goto cleanup;
    }
    printf("Second recv: %zd bytes (llo)\n", n);

    /* 3. A TCP-style half-close is different from a temporarily empty buffer. */
    if (shutdown(sockets[1], SHUT_WR) == -1) {
        perror("shutdown");
        goto cleanup;
    }
    n = recv(sockets[0], input, sizeof input, 0);
    if (n != 0) {
        fputs("expected EOF (recv == 0) after peer write shutdown\n", stderr);
        goto cleanup;
    }
    puts("After peer SHUT_WR: recv returned 0 (EOF)");

    /* 4. Fill the sender's kernel buffer without reading from the peer. */
    int send_buffer = 4096;
    if (setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF,
                   &send_buffer, sizeof send_buffer) == -1) {
        perror("setsockopt(SO_SNDBUF)");
        goto cleanup;
    }
    memset(block, 'x', sizeof block);
    size_t bytes_sent = 0;
    size_t short_sends = 0;
    int saw_would_block = 0;
    for (int attempt = 0; attempt < 4096; ++attempt) {
        n = send(sockets[0], block, sizeof block, 0);
        if (n > 0) {
            bytes_sent += (size_t)n;
            if ((size_t)n < sizeof block) ++short_sends;
            continue;
        }
        if (n == -1 && errno == EINTR) continue;
        if (n == -1 && is_would_block(errno)) {
            saw_would_block = 1;
            break;
        }
        if (n == -1) perror("send fill buffer");
        else fputs("unexpected zero-byte send\n", stderr);
        goto cleanup;
    }
    if (!saw_would_block || bytes_sent == 0) {
        fputs("send buffer did not reach EAGAIN within safety limit\n", stderr);
        goto cleanup;
    }
    printf("Full send buffer: EAGAIN after %zu bytes (short sends: %zu)\n",
           bytes_sent, short_sends);
    if (socket_set_nonblocking(sockets[0], false) == -1 ||
        socket_is_nonblocking(sockets[0]) != 0) {
        fputs("failed to restore blocking mode\n", stderr);
        goto cleanup;
    }
    puts("Flag helper: restored endpoint 0 to blocking");
    puts("Demo complete: EAGAIN != EOF; reads and writes may be partial");
    status = 0;

cleanup:
    close(sockets[0]);
    close(sockets[1]);
    return status;
}
