#ifndef EPOLL_TLS_H
#define EPOLL_TLS_H

/* Phase 24: loopback TLS 1.3 echo lab. Explicit connection states,
 * non-blocking SSL_read/SSL_write,
 * bounded output buffering, and read suspension under output backpressure.
 * This diagnostic is not the HTTP reverse proxy (--tls-proxy). */
int run_epoll_tls(const char *certificate_path, const char *private_key_path,
                  unsigned short port);

#endif
