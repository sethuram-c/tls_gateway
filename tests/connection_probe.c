/* Direct unit tests for Phase 20 connection registry. */
#include "connection.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    ConnectionRegistry registry;
    connection_registry_init(&registry);
    assert(registry.active == 0);
    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(42000);

    int first_fd = open("/dev/null", O_RDONLY);
    assert(first_fd >= 0);
    Connection *first = connection_register(&registry, first_fd, &peer);
    assert(first != NULL && first->state == CONN_OPEN);
    assert(registry.active == 1 && first->fd == first_fd);
    assert(first->peer.sin_port == htons(42000));
    uint64_t old_token = first->token;
    assert(connection_lookup(&registry, old_token) == first);
    assert(connection_lookup(&registry, 0) == NULL);
    assert(connection_lookup(&registry, UINT64_MAX) == NULL);
    assert(connection_register(&registry, -1, &peer) == NULL);
    assert(connection_register(&registry, first_fd, NULL) == NULL);
    first->bytes_read = 42;
    connection_release(&registry, first);
    assert(registry.active == 0 && first->state == CONN_UNUSED);
    assert(connection_lookup(&registry, old_token) == NULL);
    assert(fcntl(first_fd, F_GETFD) == -1 && errno == EBADF);
    connection_release(&registry, first); /* Idempotent. */
    assert(registry.active == 0);

    int second_fd = open("/dev/null", O_RDONLY);
    assert(second_fd >= 0);
    Connection *second = connection_register(&registry, second_fd, &peer);
    assert(second == first); /* Reuses slot 0. */
    assert(second->token != old_token);
    assert(connection_lookup(&registry, old_token) == NULL);
    assert(second->bytes_read == 0);
    connection_release(&registry, second);

    int fds[CONNECTION_CAPACITY];
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
        fds[i] = open("/dev/null", O_RDONLY);
        assert(fds[i] >= 0);
        assert(connection_register(&registry, fds[i], &peer) != NULL);
    }
    assert(registry.active == CONNECTION_CAPACITY);
    int rejected_fd = open("/dev/null", O_RDONLY);
    assert(rejected_fd >= 0);
    assert(connection_register(&registry, rejected_fd, &peer) == NULL);
    assert(fcntl(rejected_fd, F_GETFD) >= 0); /* Caller retains it. */
    close(rejected_fd);
    connection_registry_close_all(&registry);
    assert(registry.active == 0);
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
        assert(fcntl(fds[i], F_GETFD) == -1 && errno == EBADF);
    }
    connection_registry_close_all(&registry);
    puts("PASS: registry allocation, ownership, old tokens, capacity, cleanup");
    return 0;
}
