#include "sni_select.h"

#include <openssl/ssl.h>
#include <strings.h>

/* SNI is a client-supplied routing hint, not proof of identity. A successful
 * certificate verification on the client side is still required. */
static int choose_certificate(SSL *ssl, int *alert, void *argument)
{
    SSL_CTX *api_context = argument;
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    /* Legacy clients without SNI, and requests for localhost, use default. */
    if (name == NULL || strcasecmp(name, "localhost") == 0)
        return SSL_TLSEXT_ERR_OK;

    if (strcasecmp(name, "api.test") == 0) {
        if (SSL_set_SSL_CTX(ssl, api_context) != api_context) {
            *alert = SSL_AD_INTERNAL_ERROR;
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        return SSL_TLSEXT_ERR_OK;
    }

    /* Never silently use the wrong identity in two-hostname mode. */
    *alert = SSL_AD_UNRECOGNIZED_NAME;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int sni_install_api_test(SSL_CTX *default_context, SSL_CTX *api_context)
{
    if (default_context == NULL || api_context == NULL ||
        default_context == api_context) return -1;
    SSL_CTX_set_tlsext_servername_callback(default_context, choose_certificate);
    SSL_CTX_set_tlsext_servername_arg(default_context, api_context);
    return 0;
}
