#ifndef TLS_LISTENER_H
#define TLS_LISTENER_H

/* Phase 12: accept TCP clients and perform a TLS 1.3 handshake with
 * SSL_accept(); application data I/O begins in later phases. */
int run_tls_listener(const char *certificate_path,
                     const char *private_key_path,
                     unsigned short port);

#endif
