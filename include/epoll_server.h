#ifndef EPOLL_SERVER_H
#define EPOLL_SERVER_H

/* Loopback-only educational epoll TCP listener. Receives and discards bytes;
 * no echo, HTTP, TLS or backend forwarding in this phase. */
int run_epoll_server(unsigned short port);

#endif
