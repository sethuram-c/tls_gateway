#ifndef SNI_SELECT_H
#define SNI_SELECT_H

#include <openssl/ssl.h>

/* Install a simple two-hostname SNI selector on the default TLS context.
 * The caller owns both contexts and must keep them alive until every SSL
 * session has been released. Returns 0 on success, -1 on invalid arguments.
 *
 * No SNI or localhost => default context; api.test => alternate context.
 * Unknown SNI => TLS unrecognized_name alert (only when selector enabled).
 */
int sni_install_api_test(SSL_CTX *default_context, SSL_CTX *api_context);

#endif
