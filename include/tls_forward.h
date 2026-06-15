#ifndef TLS_FORWARD_H
#define TLS_FORWARD_H

#include <openssl/ssl.h>

/* Phase 15: one bounded HTTP GET over TLS to one loopback HTTP backend.
 * Blocking/sequential educational transport; no HTTP body or keep-alive. */
int tls_forward_request(SSL *client_tls, unsigned short backend_port);

#endif
