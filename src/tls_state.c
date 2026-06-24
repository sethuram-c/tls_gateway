#include "tls_state.h"
#include <stddef.h>

const char *tls_state_name(TlsState state)
{
    switch (state) {
    case TLS_STATE_UNUSED: return "UNUSED";
    case TLS_STATE_HANDSHAKING: return "HANDSHAKING";
    case TLS_STATE_READING: return "READING";
    case TLS_STATE_WRITING: return "WRITING";
    case TLS_STATE_CLOSING: return "CLOSING";
    default: return "INVALID";
    }
}

bool tls_state_move(TlsState *state, TlsState next)
{
    if (state == NULL) return false;
    bool allowed = false;
    switch (*state) {
    case TLS_STATE_UNUSED:
        allowed = next == TLS_STATE_HANDSHAKING;
        break;
    case TLS_STATE_HANDSHAKING:
        allowed = next == TLS_STATE_READING || next == TLS_STATE_CLOSING;
        break;
    case TLS_STATE_READING:
        allowed = next == TLS_STATE_WRITING || next == TLS_STATE_CLOSING;
        break;
    case TLS_STATE_WRITING:
        allowed = next == TLS_STATE_READING || next == TLS_STATE_CLOSING;
        break;
    case TLS_STATE_CLOSING:
        allowed = next == TLS_STATE_UNUSED;
        break;
    default:
        break;
    }
    if (allowed) *state = next;
    return allowed;
}
