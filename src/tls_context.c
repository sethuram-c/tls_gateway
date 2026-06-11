#include "tls_context.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>

/* One shared, server-side TLS configuration for later client connections. */
SSL_CTX *tls_server_context_new(const char *certificate_path,
                                const char *private_key_path)
{
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    if (context == NULL) goto openssl_error;

    if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_use_certificate_chain_file(context, certificate_path) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, private_key_path,
                                    SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1) {
        goto openssl_error;
    }
    return context;

openssl_error:
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(context);
    return NULL;
}

int run_tls_check(const char *certificate_path, const char *private_key_path)
{
    SSL_CTX *context = NULL;
    SSL *connection = NULL;
    BIO *incoming = NULL;
    BIO *outgoing = NULL;
    int result = 1;

    context = tls_server_context_new(certificate_path, private_key_path);
    if (context == NULL) goto error;

    /* SSL is per-connection state; no socket or handshake exists yet. */
    connection = SSL_new(context);
    if (connection == NULL) goto error;

    /* Memory BIOs illustrate OpenSSL's pluggable I/O abstraction. */
    incoming = BIO_new(BIO_s_mem());
    outgoing = BIO_new(BIO_s_mem());
    if (incoming == NULL || outgoing == NULL) goto error;

    /* SSL_set_bio takes ownership of both distinct BIO objects. */
    SSL_set_bio(connection, incoming, outgoing);
    incoming = NULL;
    outgoing = NULL;

    puts("TLS context OK (TLS 1.3 only)");
    puts("Server certificate and private key match");
    puts("SSL object and memory BIOs ready (no handshake performed)");
    result = 0;
    goto cleanup;

error:
    fputs("TLS configuration check failed\n", stderr);
    /* tls_server_context_new has already printed errors if it failed. */
    if (context != NULL) ERR_print_errors_fp(stderr);
cleanup:
    /* Unattached BIOs are ours. Attached BIOs belong to SSL. */
    BIO_free(incoming);
    BIO_free(outgoing);
    SSL_free(connection);
    SSL_CTX_free(context);
    return result;
}
