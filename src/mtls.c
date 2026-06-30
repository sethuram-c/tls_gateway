#include "mtls.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdio.h>

int mtls_require_client_cert(SSL_CTX *context, const char *ca_path)
{
    if (context == NULL || ca_path == NULL || *ca_path == '\0') return -1;

    /* File is a trusted CA bundle. This does NOT authorize arbitrary peers:
     * verify_callback=NULL retains OpenSSL's default verification policy,
     * including clientAuth Extended Key Usage checks. */
    if (SSL_CTX_load_verify_locations(context, ca_path, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Hint which CA the client should use to select its certificate.
     * The returned list is transferred to the context by set_client_CA_list.
     * This is not the trust store; load_verify_locations sets trust. */
    STACK_OF(X509_NAME) *names = SSL_load_client_CA_file(ca_path);
    if (names == NULL) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    SSL_CTX_set_client_CA_list(context, names);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
    return 0;
}

int mtls_peer_verified(SSL *connection)
{
    if (connection == NULL || SSL_get_verify_result(connection) != X509_V_OK)
        return 0;
    X509 *peer = SSL_get1_peer_certificate(connection);
    if (peer == NULL) return 0;
    X509_free(peer);
    return 1;
}
