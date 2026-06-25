#define _GNU_SOURCE
#include "backend_async.h"

#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

int backend_async_start(unsigned short port, int *fd_out)
{
    if (fd_out == NULL || port == 0) {
        errno = EINVAL;
        return -1;
    }
    *fd_out = -1;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_in backend = {0};
    backend.sin_family = AF_INET;
    backend.sin_port = htons(port);
    backend.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int result = connect(fd, (const struct sockaddr *)&backend, sizeof(backend));
    if (result == 0) {
        *fd_out = fd;
        return 1;
    }
    if (errno == EINPROGRESS) {
        *fd_out = fd;
        return 0;
    }
    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

int backend_async_complete(int fd)
{
    int error = 0;
    socklen_t size = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0) return -1;
    if (error != 0) {
        errno = error;
        return -1;
    }
    return 0;
}
