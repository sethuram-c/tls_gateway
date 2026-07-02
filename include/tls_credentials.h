#ifndef TLS_CREDENTIALS_H
#define TLS_CREDENTIALS_H

#include <openssl/ssl.h>
#include <stddef.h>

/* One immutable generation of server-side TLS configuration.  An in-flight
 * handshake holds its generation alive, including the SNI callback argument. */
typedef struct TlsCredentials {
    SSL_CTX *primary;
    SSL_CTX *alternate;
    size_t users;
    struct TlsCredentials *next;
} TlsCredentials;

TlsCredentials *tls_credentials_load(const char *cert, const char *key,
                                     const char *alternate_cert,
                                     const char *alternate_key,
                                     const char *client_ca);
void tls_credentials_free(TlsCredentials *credentials);
/* Free only retired generations with zero active SSL sessions. */
void tls_credentials_collect(TlsCredentials **retired);

#endif
