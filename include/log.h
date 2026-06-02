#ifndef TLS_GATEWAY_LOG_H
#define TLS_GATEWAY_LOG_H

typedef enum {
    LOG_INFO,
    LOG_ERROR
} log_level_t;

void log_message(log_level_t level, const char *message);

#endif
