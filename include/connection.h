#ifndef CONNECTION_H
#define CONNECTION_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#define CONNECTION_CAPACITY 128

/* Phase 20: only tracking a TCP client's lifetime; TLS states come later. */
typedef enum {
    CONN_UNUSED = 0,
    CONN_OPEN
} ConnectionState;

typedef struct {
    int fd;
    ConnectionState state;
    uint64_t token;      /* Slot + generation; avoids stale epoll events. */
    uint64_t bytes_read;
    struct sockaddr_in peer;
} Connection;

typedef struct {
    Connection slots[CONNECTION_CAPACITY];
    uint64_t next_generation;
    size_t active;
} ConnectionRegistry;

void connection_registry_init(ConnectionRegistry *registry);
/* Takes ownership of fd only on success; NULL leaves fd owned by caller. */
Connection *connection_register(ConnectionRegistry *registry, int fd,
                                const struct sockaddr_in *peer);
/* Returns NULL for a closed connection or an old/stale event token. */
Connection *connection_lookup(ConnectionRegistry *registry, uint64_t token);
/* Closes the owned fd and makes the slot reusable; does not call epoll_ctl. */
void connection_release(ConnectionRegistry *registry, Connection *connection);
void connection_registry_close_all(ConnectionRegistry *registry);

#endif
