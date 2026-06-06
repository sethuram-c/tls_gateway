#ifndef BACKEND_CONNECT_H
#define BACKEND_CONNECT_H

/* Attempts one TCP connection to localhost:port, then closes it.
 * Returns 0 on success, 1 on error. Does not forward traffic. */
int run_backend_connect(unsigned short port);

#endif
