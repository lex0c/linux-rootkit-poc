#include <string.h>
#include <stdlib.h>

void xor(char *x_str) {
    int i, key=0xFE;

    for (i = 0; i < strlen(x_str); i++) {
        x_str[i] ^= key;
    }
}

void cleanup(void *var, int len) {
    memset(var, 0x00, len);
    free(var);
}

int extract_pid(const char *path) {
    char path_copy[256];
    strncpy(path_copy, path, sizeof(path_copy));
    path_copy[sizeof(path_copy) - 1] = '\0'; // Ensure null-termination

    // Split the path by '/'
    char *token = strtok(path_copy, "/");
    int token_count = 0;

    while (token != NULL) {
        token_count++;

        // The second token is the PID
        if (token_count == 2) {
            return atoi(token);
        }

        token = strtok(NULL, "/");
    }

    return -1;
}

