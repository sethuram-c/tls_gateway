#ifndef SOCKET_FLAGS_H
#define SOCKET_FLAGS_H

#include <stdbool.h>

/* Set or clear O_NONBLOCK without disturbing the descriptor's other status
 * flags. Returns 0 on success, -1 on error (errno is set). */
int socket_set_nonblocking(int fd, bool enabled);

/* Returns 1 when O_NONBLOCK is set, 0 when unset, -1 on error (errno set). */
int socket_is_nonblocking(int fd);

#endif
