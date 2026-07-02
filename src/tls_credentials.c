#include "tls_credentials.h"
#include "mtls.h"
#include "sni_select.h"
#include "tls_context.h"

#include <stdio.h>
#include <stdlib.h>

TlsCredentials *tls_credentials_load(const char *cert, const char *key,
                                     const char *alternate_cert,
                                     const char *alternate_key,
                                     const char *client_ca)
{
    if ((alternate_cert == NULL) != (alternate_key == NULL)) {
        fputs("SNI requires both certificate and key\n", stderr);
        return NULL;
    }
    TlsCredentials *bundle = calloc(1, sizeof(*bundle));
    if (bundle == NULL) return NULL;
    bundle->primary = tls_server_context_new(cert, key);
    if (bundle->primary == NULL) goto fail;
    if (alternate_cert != NULL) {
        bundle->alternate = tls_server_context_new(alternate_cert, alternate_key);
        if (bundle->alternate == NULL ||
            sni_install_api_test(bundle->primary, bundle->alternate) < 0)
            goto fail;
    }
    /* Trust settings belong to the generation, so SNI cannot bypass mTLS. */
    if (client_ca != NULL &&
        (mtls_require_client_cert(bundle->primary, client_ca) < 0 ||
         (bundle->alternate != NULL &&
          mtls_require_client_cert(bundle->alternate, client_ca) < 0)))
        goto fail;
    return bundle;
fail:
    tls_credentials_free(bundle);
    return NULL;
}

void tls_credentials_free(TlsCredentials *bundle)
{
    if (bundle == NULL) return;
    SSL_CTX_free(bundle->alternate);
    SSL_CTX_free(bundle->primary);
    free(bundle);
}

void tls_credentials_collect(TlsCredentials **retired)
{
    while (*retired != NULL) {
        TlsCredentials *bundle = *retired;
        if (bundle->users != 0) {
            retired = &bundle->next;
            continue;
        }
        *retired = bundle->next;
        tls_credentials_free(bundle);
    }
}
