#ifndef TLS_LISTENER_H
#define TLS_LISTENER_H

/* Phase 13: accept TLS 1.3 handshakes, then decrypt one bounded block
 * with SSL_read(). No TLS application response is sent yet. */
int run_tls_listener(const char *certificate_path,
                     const char *private_key_path,
                     unsigned short port);

#endif
