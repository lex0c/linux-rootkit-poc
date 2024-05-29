#pragma once

#include <limits.h>

#include "const.h"

#define _STAT_VER 1

static void init (void) __attribute__ ((constructor));

int is_invisible(const char *path) __attribute__((visibility("hidden")));
int is_owner(void) __attribute__((visibility("hidden")));

typedef struct struct_syscalls {
    char syscall_name[51];    // buffer for syscall name (50 characters + 1 null terminator)
    void *(*syscall_func)();  // pointer to the original syscall function
} s_syscalls;

s_syscalls syscall_list[SYSCALL_SIZE];

static int is_loaded = 0;
static int owner = 0;

