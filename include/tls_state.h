#ifndef TLS_STATE_H
#define TLS_STATE_H

#include <stdbool.h>

/* A TLS connection has exactly one application-level phase at a time.
 * Socket readiness (EPOLLIN/EPOLLOUT) is independent of this phase: OpenSSL
 * may need either kind of readiness for any TLS operation. */
typedef enum {
    TLS_STATE_UNUSED = 0,
    TLS_STATE_HANDSHAKING,
    TLS_STATE_READING,
    TLS_STATE_WRITING,
    TLS_STATE_CLOSING
} TlsState;

const char *tls_state_name(TlsState state);
/* Return false without changing *state if the transition is forbidden. */
bool tls_state_move(TlsState *state, TlsState next);

#endif
