#define _POSIX_C_SOURCE 200809L
#include "gateway_config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deliberately small: no includes, interpolation, quoted values or sections. */
enum ConfigKey {
    CFG_LISTEN, CFG_BACKEND, CFG_SERVER_CERT, CFG_SERVER_KEY,
    CFG_API_CERT, CFG_API_KEY, CFG_REQUIRE_MTLS, CFG_CLIENT_CA, CFG_COUNT
};

static const char *const key_names[CFG_COUNT] = {
    "listen_port", "backend_port", "server_cert", "server_key",
    "api_cert", "api_key", "require_mtls", "client_ca"
};

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) ++s;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    return s;
}

static int parse_port(const char *text, unsigned short *port)
{
    if (*text == '\0') return -1;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (!isdigit(*p)) return -1;
    }
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value == 0 || value > 65535) return -1;
    *port = (unsigned short)value;
    return 0;
}

static int copy_path(char dst[GATEWAY_CONFIG_PATH_MAX], const char *value)
{
    size_t n = strlen(value);
    if (n == 0 || n >= GATEWAY_CONFIG_PATH_MAX) return -1;
    for (size_t i = 0; i < n; ++i) {
        if (iscntrl((unsigned char)value[i])) return -1;
    }
    memcpy(dst, value, n + 1);
    return 0;
}

static int set_value(GatewayConfig *cfg, int key, const char *value)
{
    switch (key) {
    case CFG_LISTEN: return parse_port(value, &cfg->listen_port);
    case CFG_BACKEND: return parse_port(value, &cfg->backend_port);
    case CFG_SERVER_CERT: return copy_path(cfg->server_cert, value);
    case CFG_SERVER_KEY: return copy_path(cfg->server_key, value);
    case CFG_API_CERT: return copy_path(cfg->api_cert, value);
    case CFG_API_KEY: return copy_path(cfg->api_key, value);
    case CFG_CLIENT_CA: return copy_path(cfg->client_ca, value);
    case CFG_REQUIRE_MTLS:
        if (strcmp(value, "true") == 0) cfg->require_mtls = true;
        else if (strcmp(value, "false") == 0) cfg->require_mtls = false;
        else return -1;
        return 0;
    default: return -1;
    }
}

int gateway_config_load(const char *filename, GatewayConfig *out)
{
    if (filename == NULL || out == NULL) return -1;
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "%s: %s\n", filename, strerror(errno));
        return -1;
    }

    GatewayConfig cfg = {0};
    char *line = NULL;
    size_t capacity = 0, number = 0;
    unsigned seen = 0;
    int result = -1;
    ssize_t length;

    while ((length = getline(&line, &capacity, file)) >= 0) {
        ++number;
        if (length > 1024 || memchr(line, '\0', (size_t)length) != NULL) {
            fprintf(stderr, "%s:%zu: invalid or oversized line\n", filename, number);
            goto end;
        }
        char *text = trim(line);
        if (*text == '\0' || *text == '#') continue;
        char *equal = strchr(text, '=');
        if (equal == NULL) {
            fprintf(stderr, "%s:%zu: expected key = value\n", filename, number);
            goto end;
        }
        *equal = '\0';
        char *key_text = trim(text);
        char *value = trim(equal + 1);
        int key;
        for (key = 0; key < CFG_COUNT; ++key) {
            if (strcmp(key_text, key_names[key]) == 0) break;
        }
        if (key == CFG_COUNT) {
            fprintf(stderr, "%s:%zu: unknown setting '%s'\n", filename, number, key_text);
            goto end;
        }
        if (seen & (1U << key)) {
            fprintf(stderr, "%s:%zu: duplicate setting '%s'\n", filename, number, key_text);
            goto end;
        }
        if (set_value(&cfg, key, value) < 0) {
            fprintf(stderr, "%s:%zu: invalid value for '%s'\n", filename, number, key_text);
            goto end;
        }
        seen |= 1U << key;
    }
    if (ferror(file)) {
        fprintf(stderr, "%s: read error\n", filename);
        goto end;
    }

    const unsigned required = (1U << CFG_LISTEN) | (1U << CFG_BACKEND) |
                              (1U << CFG_SERVER_CERT) | (1U << CFG_SERVER_KEY);
    if ((seen & required) != required) {
        fprintf(stderr, "%s: missing required setting (listen_port, backend_port, server_cert, server_key)\n",
                filename);
        goto end;
    }
    if (cfg.listen_port == cfg.backend_port) {
        fprintf(stderr, "%s: listener and backend ports must differ\n", filename);
        goto end;
    }
    if ((cfg.api_cert[0] == '\0') != (cfg.api_key[0] == '\0')) {
        fprintf(stderr, "%s: api_cert and api_key must appear together\n", filename);
        goto end;
    }
    if (cfg.require_mtls != (cfg.client_ca[0] != '\0')) {
        fprintf(stderr, "%s: require_mtls=true needs client_ca; client_ca is invalid when mTLS is false\n",
                filename);
        goto end;
    }
    *out = cfg;
    result = 0;
end:
    free(line);
    fclose(file);
    return result;
}
