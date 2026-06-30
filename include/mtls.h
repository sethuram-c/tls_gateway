#ifndef MTLS_H
#define MTLS_H

#include <openssl/ssl.h>

/* Configure mandatory client certificates, validated against a CA bundle.
 * Call on EVERY virtual-host SSL_CTX before exposing the listener. Missing,
 * invalid, or unsuitable CA files fail startup rather than weaken security.
 * Returns 0 on success, -1 on failure (with OpenSSL diagnostics on stderr). */
int mtls_require_client_cert(SSL_CTX *context, const char *ca_path);

/* After SSL_accept returns 1, confirm the peer certificate exists and was
 * successfully verified. The handshake policy does the actual enforcement. */
int mtls_peer_verified(SSL *connection);

#endif
