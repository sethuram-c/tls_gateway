/* Tiny C fixture driven by test_socket_flags.py. Not part of the gateway. */
#include "socket_flags.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define REQUIRE(expr) do {                                                \
    if (!(expr)) {                                                        \
        fprintf(stderr, "FAIL at line %d: %s\n", __LINE__, #expr);       \
        return 1;                                                         \
    }                                                                     \
} while (0)

int main(void)
{
    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    REQUIRE(socket_is_nonblocking(pair[0]) == 0);
    REQUIRE(socket_is_nonblocking(pair[1]) == 0);

    int initial = fcntl(pair[0], F_GETFL);
    REQUIRE(initial >= 0);
    REQUIRE(socket_set_nonblocking(pair[0], true) == 0);
    REQUIRE(socket_set_nonblocking(pair[0], true) == 0); /* idempotent */
    REQUIRE(socket_is_nonblocking(pair[0]) == 1);
    REQUIRE(socket_is_nonblocking(pair[1]) == 0); /* independent peers */
    REQUIRE((fcntl(pair[0], F_GETFL) & ~O_NONBLOCK) == (initial & ~O_NONBLOCK));

    int duplicate = dup(pair[0]);
    REQUIRE(duplicate >= 0);
    REQUIRE(socket_is_nonblocking(duplicate) == 1);
    REQUIRE(socket_set_nonblocking(duplicate, false) == 0);
    REQUIRE(socket_is_nonblocking(pair[0]) == 0); /* shared description */
    REQUIRE(socket_is_nonblocking(pair[1]) == 0);

    REQUIRE(socket_set_nonblocking(pair[1], true) == 0);
    REQUIRE(socket_is_nonblocking(pair[1]) == 1);
    REQUIRE(socket_is_nonblocking(pair[0]) == 0);

    errno = 0;
    REQUIRE(socket_is_nonblocking(-1) == -1 && errno == EBADF);
    errno = 0;
    REQUIRE(socket_set_nonblocking(-1, true) == -1 && errno == EBADF);

    REQUIRE(close(duplicate) == 0);
    REQUIRE(close(pair[0]) == 0);
    REQUIRE(close(pair[1]) == 0);
    puts("PASS: toggle, idempotence, preserved flags, dup sharing, invalid FD");
    return 0;
}
