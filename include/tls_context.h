#ifndef TLS_CONTEXT_H
#define TLS_CONTEXT_H

#include <openssl/ssl.h>

/* Caller owns the returned SSL_CTX and must release it with SSL_CTX_free. */
SSL_CTX *tls_server_context_new(const char *certificate_path,
                                const char *private_key_path);

/* Phase 10: inspect OpenSSL object setup without network traffic. */
int run_tls_check(const char *certificate_path, const char *private_key_path);

#endif
