#include "connection.h"

#include <limits.h>
#include <string.h>
#include <unistd.h>

/* 8 bits store slot number + 1 (1..128); 0 is the listener token. */
#define SLOT_BITS 8
#define SLOT_MASK UINT64_C(255)

void connection_registry_init(ConnectionRegistry *registry)
{
    memset(registry, 0, sizeof(*registry));
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
        registry->slots[i].fd = -1;
    }
    registry->next_generation = 1;
}

Connection *connection_register(ConnectionRegistry *registry, int fd,
                                const struct sockaddr_in *peer)
{
    if (fd < 0 || peer == NULL || registry->next_generation == 0 ||
        registry->next_generation > (UINT64_MAX >> (SLOT_BITS + 1))) {
        return NULL;
    }
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
        Connection *c = &registry->slots[i];
        if (c->state != CONN_UNUSED) continue;
        c->fd = fd;
        c->state = CONN_OPEN;
        c->token = (registry->next_generation++ << SLOT_BITS) | (i + 1);
        c->bytes_read = 0;
        c->peer = *peer;
        ++registry->active;
        return c;
    }
    return NULL;
}

Connection *connection_lookup(ConnectionRegistry *registry, uint64_t token)
{
    uint64_t encoded_slot = token & SLOT_MASK;
    if (encoded_slot == 0 || encoded_slot > CONNECTION_CAPACITY) return NULL;
    Connection *c = &registry->slots[encoded_slot - 1];
    if (c->state != CONN_OPEN || c->token != token) return NULL;
    return c;
}

void connection_release(ConnectionRegistry *registry, Connection *connection)
{
    if (connection == NULL || connection->state != CONN_OPEN) return;
    close(connection->fd);
    connection->fd = -1;
    connection->state = CONN_UNUSED;
    connection->token = 0;
    connection->bytes_read = 0;
    memset(&connection->peer, 0, sizeof(connection->peer));
    --registry->active;
}

void connection_registry_close_all(ConnectionRegistry *registry)
{
    for (size_t i = 0; i < CONNECTION_CAPACITY; ++i) {
        connection_release(registry, &registry->slots[i]);
    }
}
