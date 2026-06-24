#include "tls_state.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    TlsState state = TLS_STATE_UNUSED;
    assert(strcmp(tls_state_name(state), "UNUSED") == 0);
    assert(!tls_state_move(NULL, TLS_STATE_READING));
    assert(!tls_state_move(&state, TLS_STATE_READING));
    assert(state == TLS_STATE_UNUSED);
    assert(tls_state_move(&state, TLS_STATE_HANDSHAKING));
    assert(!tls_state_move(&state, TLS_STATE_WRITING));
    assert(tls_state_move(&state, TLS_STATE_READING));
    assert(!tls_state_move(&state, TLS_STATE_HANDSHAKING));
    assert(tls_state_move(&state, TLS_STATE_WRITING));
    assert(tls_state_move(&state, TLS_STATE_READING));
    assert(tls_state_move(&state, TLS_STATE_CLOSING));
    assert(!tls_state_move(&state, TLS_STATE_WRITING));
    assert(tls_state_move(&state, TLS_STATE_UNUSED));
    assert(tls_state_move(&state, TLS_STATE_HANDSHAKING));
    assert(tls_state_move(&state, TLS_STATE_CLOSING));
    assert(tls_state_move(&state, TLS_STATE_UNUSED));
    assert(strcmp(tls_state_name((TlsState)99), "INVALID") == 0);
    puts("PASS: TLS transitions, invalid edges, and cleanup");
    return 0;
}
