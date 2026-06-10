#include "tls_context.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>

int run_tls_check(const char *certificate_path, const char *private_key_path)
{
    SSL_CTX *context = NULL;
    SSL *connection = NULL;
    BIO *incoming = NULL;
    BIO *outgoing = NULL;
    int result = 1;

    /* An SSL_CTX holds configuration shared by future TLS connections. */
    context = SSL_CTX_new(TLS_server_method());
    if (context == NULL) goto openssl_error;

    if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1) {
        goto openssl_error;
    }

    if (SSL_CTX_use_certificate_chain_file(context, certificate_path) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, private_key_path,
                                    SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1) {
        goto openssl_error;
    }

    /* SSL is per-connection state; no socket or handshake exists yet. */
    connection = SSL_new(context);
    if (connection == NULL) goto openssl_error;

    /* Memory BIOs illustrate OpenSSL's pluggable I/O abstraction. */
    incoming = BIO_new(BIO_s_mem());
    outgoing = BIO_new(BIO_s_mem());
    if (incoming == NULL || outgoing == NULL) goto openssl_error;

    /* SSL_set_bio takes ownership of both distinct BIO objects. */
    SSL_set_bio(connection, incoming, outgoing);
    incoming = NULL;
    outgoing = NULL;

    puts("TLS context OK (TLS 1.3 only)");
    puts("Server certificate and private key match");
    puts("SSL object and memory BIOs ready (no handshake performed)");
    result = 0;
    goto cleanup;

openssl_error:
    fputs("TLS configuration check failed\n", stderr);
    ERR_print_errors_fp(stderr);
cleanup:
    /* Unattached BIOs are ours. Attached BIOs belong to SSL. */
    BIO_free(incoming);
    BIO_free(outgoing);
    SSL_free(connection);
    SSL_CTX_free(context);
    return result;
}
