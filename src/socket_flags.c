#include "socket_flags.h"

#include <errno.h>
#include <fcntl.h>

/* Both calls operate on file status flags, not file-descriptor flags.
 * Retry interruption but preserve any other failure for the caller. */
static int get_status_flags(int fd)
{
    int flags;
    do {
        flags = fcntl(fd, F_GETFL);
    } while (flags == -1 && errno == EINTR);
    return flags;
}

int socket_set_nonblocking(int fd, bool enabled)
{
    int flags = get_status_flags(fd);
    if (flags == -1) return -1;

    int updated = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    if (updated == flags) return 0;  /* Repeating a request is harmless. */

    int result;
    do {
        result = fcntl(fd, F_SETFL, updated);
    } while (result == -1 && errno == EINTR);
    return result;
}

int socket_is_nonblocking(int fd)
{
    int flags = get_status_flags(fd);
    if (flags == -1) return -1;
    return (flags & O_NONBLOCK) != 0;
}
