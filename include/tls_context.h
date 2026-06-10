#ifndef TLS_CONTEXT_H
#define TLS_CONTEXT_H

/* Phase 10: inspect OpenSSL server-side object setup (no network traffic). */
int run_tls_check(const char *certificate_path, const char *private_key_path);

#endif
