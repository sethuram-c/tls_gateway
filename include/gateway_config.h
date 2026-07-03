#ifndef GATEWAY_CONFIG_H
#define GATEWAY_CONFIG_H

#include <stdbool.h>

/* The config contains paths, never private-key contents. Paths are resolved
 * relative to the process's current working directory (like the old CLI). */
#define GATEWAY_CONFIG_PATH_MAX 512

typedef struct {
    unsigned short listen_port;
    unsigned short backend_port;
    char server_cert[GATEWAY_CONFIG_PATH_MAX];
    char server_key[GATEWAY_CONFIG_PATH_MAX];
    char api_cert[GATEWAY_CONFIG_PATH_MAX];
    char api_key[GATEWAY_CONFIG_PATH_MAX];
    char client_ca[GATEWAY_CONFIG_PATH_MAX];
    bool require_mtls;
} GatewayConfig;

/* Returns 0 on success, -1 on any I/O, syntax or semantic error.
 * Prints the first error with filename + line where possible. */
int gateway_config_load(const char *filename, GatewayConfig *out);

#endif
