#include "socket_demo.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int run_socket_demo(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(0); /* Ask the kernel for an unused port. */
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
        fputs("inet_pton failed\n", stderr);
        close(fd);
        return 1;
    }

    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("bind");
        close(fd);
        return 1;
    }

    socklen_t length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length) == -1) {
        perror("getsockname");
        close(fd);
        return 1;
    }

    if (listen(fd, 8) == -1) {
        perror("listen");
        close(fd);
        return 1;
    }

    printf("Listening briefly on 127.0.0.1:%u\n", (unsigned)ntohs(address.sin_port));
    puts("Socket lifecycle: socket -> bind -> listen -> close");
    if (close(fd) == -1) {
        perror("close");
        return 1;
    }
    return 0;
}
