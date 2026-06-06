#include "backend_connect.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int run_backend_connect(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in backend = {0};
    backend.sin_family = AF_INET;
    backend.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &backend.sin_addr) != 1) {
        fputs("invalid backend address\n", stderr);
        close(fd);
        return 1;
    }

    printf("Connecting to 127.0.0.1:%u...\n", (unsigned)port);
    fflush(stdout);
    int result;
    do {
        result = connect(fd, (struct sockaddr *)&backend, sizeof(backend));
    } while (result < 0 && errno == EINTR);

    if (result < 0) {
        perror("connect");
        close(fd);
        return 1;
    }
    puts("Backend TCP connection established");
    if (close(fd) < 0) {
        perror("close");
        return 1;
    }
    puts("Backend connection closed (no HTTP forwarded in Phase 6)");
    return 0;
}
