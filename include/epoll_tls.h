#ifndef EPOLL_TLS_H
#define EPOLL_TLS_H

/* Phase 22: loopback-only TLS 1.3 handshakes and non-blocking SSL_read.
 * This mode logs small hex previews, but does not send replies or proxy HTTP. */
int run_epoll_tls(const char *certificate_path, const char *private_key_path,
                  unsigned short port);

#endif
