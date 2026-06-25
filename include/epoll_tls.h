#ifndef EPOLL_TLS_H
#define EPOLL_TLS_H

/* Phase 25: loopback TLS 1.3 echo lab. Explicit connection states,
 * non-blocking SSL_read/SSL_write,
 * bounded output buffering, and read suspension under output backpressure.
 * This diagnostic is not the HTTP reverse proxy (--tls-proxy). */
int run_epoll_tls(const char *certificate_path, const char *private_key_path,
                  unsigned short port);

/* Phase 25: a separate TLS echo lab that initiates a non-blocking outbound
 * connection upon the first TLS application record; it does not forward HTTP. */
int run_epoll_tls_with_backend(const char *certificate_path,
                               const char *private_key_path,
                               unsigned short port, unsigned short backend_port);

#endif
