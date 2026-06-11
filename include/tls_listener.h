#ifndef TLS_LISTENER_H
#define TLS_LISTENER_H

/* Phase 11: accept TCP sockets, prepare SSL objects, do not handshake yet. */
int run_tls_listener(const char *certificate_path,
                     const char *private_key_path,
                     unsigned short port);

#endif
