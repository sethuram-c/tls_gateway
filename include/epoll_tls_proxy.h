#ifndef EPOLL_TLS_PROXY_H
#define EPOLL_TLS_PROXY_H

/* One HTTP/1.1 GET per TLS 1.3 connection; asynchronous upstream and TLS.
 * Optional SNI cert for api.test. NULL client_ca = original one-way TLS.
 * Non-NULL client_ca = mandatory, verified mTLS on both hostnames. */
int run_epoll_tls_proxy(const char *certificate_path, const char *private_key_path,
                        unsigned short tls_port, unsigned short backend_port,
                        const char *api_certificate_path, const char *api_key_path,
                        const char *client_ca_path);

#endif
