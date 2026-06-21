#ifndef EPOLL_TLS_H
#define EPOLL_TLS_H

/* Phase 21: loopback-only, event-driven TLS handshake diagnostic. */
int run_epoll_tls(const char *certificate_path, const char *private_key_path,
                  unsigned short port);

#endif
