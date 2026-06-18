#include "epoll_demo.h"
#include "socket_flags.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

/* -1 indicates an error; 0 means timeout; 1 means one event. */
static int wait_one(int epfd, int timeout_ms, struct epoll_event *event)
{
    for (;;) {
        int count = epoll_wait(epfd, event, 1, timeout_ms);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return count;
    }
}

static int expect_event(int epfd, uint32_t required, const char *step)
{
    struct epoll_event event;
    int count = wait_one(epfd, 1000, &event);
    if (count < 0) {
        perror("epoll_wait");
        return -1;
    }
    if (count != 1 || (event.events & required) != required ||
        event.data.u64 != UINT64_C(0xE9011)) {
        fprintf(stderr, "%s: expected readiness mask 0x%x\n", step, required);
        return -1;
    }
    return 0;
}

static int expect_timeout(int epfd, const char *step)
{
    struct epoll_event event;
    int count = wait_one(epfd, 0, &event);
    if (count < 0) {
        perror("epoll_wait");
        return -1;
    }
    if (count != 0) {
        fprintf(stderr, "%s: unexpectedly ready\n", step);
        return -1;
    }
    return 0;
}

int run_epoll_demo(void)
{
    int sockets[2] = {-1, -1};
    int epfd = -1;
    int rc = 1;
    char received[5];
    struct epoll_event interest = {0};

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        perror("socketpair");
        goto done;
    }
    if (socket_set_nonblocking(sockets[0], true) < 0) {
        perror("socket_set_nonblocking");
        goto done;
    }

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        perror("epoll_create1");
        goto done;
    }

    interest.events = EPOLLIN; /* Level-triggered by default. */
    interest.data.u64 = UINT64_C(0xE9011); /* Application-defined identity. */
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockets[0], &interest) < 0) {
        perror("epoll_ctl ADD");
        goto done;
    }
    puts("Registered reader: EPOLL_CTL_ADD / EPOLLIN (level-triggered)");

    if (expect_timeout(epfd, "initially empty") < 0) goto done;
    puts("Initially: no readable data, epoll_wait returned 0");

    if (send(sockets[1], "hello", 5, 0) != 5) {
        perror("send hello");
        goto done;
    }
    if (expect_event(epfd, EPOLLIN, "after send") < 0) goto done;
    puts("After send: EPOLLIN ready");

    ssize_t count = recv(sockets[0], received, 2, 0);
    if (count != 2 || memcmp(received, "he", 2) != 0) {
        fputs("partial recv did not return 'he'\n", stderr);
        goto done;
    }
    puts("Partial read: he (2 bytes)");

    if (expect_event(epfd, EPOLLIN, "data remains") < 0) goto done;
    puts("Level-triggered: EPOLLIN is still ready (3 bytes remain)");

    count = recv(sockets[0], received, sizeof(received), 0);
    if (count != 3 || memcmp(received, "llo", 3) != 0) {
        fputs("drain recv did not return 'llo'\n", stderr);
        goto done;
    }
    if (expect_timeout(epfd, "drained") < 0) goto done;
    puts("After drain: no EPOLLIN, epoll_wait returned 0");

    interest.events = EPOLLIN | EPOLLRDHUP;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, sockets[0], &interest) < 0) {
        perror("epoll_ctl MOD");
        goto done;
    }
    puts("Modified interest: EPOLL_CTL_MOD / EPOLLIN | EPOLLRDHUP");

    if (shutdown(sockets[1], SHUT_WR) < 0) {
        perror("shutdown SHUT_WR");
        goto done;
    }
    if (expect_event(epfd, EPOLLRDHUP, "peer half-close") < 0) goto done;
    puts("Peer half-close: EPOLLRDHUP ready");

    count = recv(sockets[0], received, sizeof(received), 0);
    if (count != 0) {
        fputs("expected recv == 0 after peer write half-close\n", stderr);
        goto done;
    }
    puts("At EOF: recv returned 0 (not EAGAIN)");

    if (epoll_ctl(epfd, EPOLL_CTL_DEL, sockets[0], NULL) < 0) {
        perror("epoll_ctl DEL");
        goto done;
    }
    if (expect_timeout(epfd, "after DEL") < 0) goto done;
    puts("After DEL: no more events for the removed fd");
    puts("Demo complete: epoll_create1 -> ADD -> wait -> MOD -> DEL");
    rc = 0;

done:
    if (epfd >= 0) close(epfd);
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
    return rc;
}
