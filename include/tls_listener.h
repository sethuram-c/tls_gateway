#ifndef TLS_LISTENER_H
#define TLS_LISTENER_H

/* Phase 14: accept TLS 1.3 connections, read one bounded block,
 * and send a fixed HTTP response with SSL_write(). Blocking, sequential. */
int run_tls_listener(const char *certificate_path,
                     const char *private_key_path,
                     unsigned short port);

/* Phase 15: TLS-terminating loopback reverse proxy. */
int run_tls_proxy(const char *certificate_path,
                  const char *private_key_path, unsigned short port,
                  unsigned short backend_port);

#endif
