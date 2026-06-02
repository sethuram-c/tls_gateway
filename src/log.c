#include "log.h"

#include <stdio.h>

void log_message(log_level_t level, const char *message)
{
    const char *name = level == LOG_ERROR ? "ERROR" : "INFO";
    fprintf(stderr, "[tls-gateway] [%s] %s\n", name, message);
}
