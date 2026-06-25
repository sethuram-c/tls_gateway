#ifndef BACKEND_ASYNC_H
#define BACKEND_ASYNC_H

/* Open non-blocking TCP connection to loopback:port. Owns fd on success.
 * Returns 1 if connected immediately, 0 if EINPROGRESS, -1 on failure.
 * On failure, *fd_out remains -1 and errno describes the error. */
int backend_async_start(unsigned short port, int *fd_out);

/* On EPOLLOUT/EPOLLERR, query SO_ERROR. 0 means connected; -1 sets errno
 * to the pending socket error. Caller always closes the backend fd. */
int backend_async_complete(int fd);

#endif
