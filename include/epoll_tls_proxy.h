#ifndef EPOLL_TLS_PROXY_H
#define EPOLL_TLS_PROXY_H

/* Phase 26: one HTTP GET request/response per TLS 1.3 client. Both TLS
 * and upstream TCP sockets are non-blocking, driven by one epoll loop. */
int run_epoll_tls_proxy(const char *certificate_path, const char *private_key_path,
                        unsigned short tls_port, unsigned short backend_port);

#endif
