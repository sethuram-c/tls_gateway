#ifndef EPOLL_TLS_PROXY_H
#define EPOLL_TLS_PROXY_H

/* One HTTP/1.1 GET per TLS 1.3 connection; asynchronous upstream and TLS.
 * Optional Phase 28 SNI certificate for api.test; NULL pair = default-only. */
int run_epoll_tls_proxy(const char *certificate_path, const char *private_key_path,
                        unsigned short tls_port, unsigned short backend_port,
                        const char *api_certificate_path, const char *api_key_path);

#endif
