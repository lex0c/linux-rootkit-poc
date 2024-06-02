#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>

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

// Calculate the hash of the binary
void calculate_sha256(const char *path, unsigned char output[EVP_MAX_MD_SIZE], unsigned int *output_length) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror("fopen");
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        perror("EVP_MD_CTX_new");
        fclose(file);
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        perror("EVP_DigestInit_ex");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    const int bufSize = 32768;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;
    if (!buffer) {
        perror("malloc");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    while ((bytesRead=fread(buffer, 1, bufSize, file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            perror("EVP_DigestUpdate");
            free(buffer);
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return;
        }
    }

    if (EVP_DigestFinal_ex(mdctx, output, output_length) != 1) {
        perror("EVP_DigestFinal_ex");
    }

    EVP_MD_CTX_free(mdctx);
    free(buffer);
    fclose(file);
}

void hash_to_string(unsigned char *hash, unsigned int length, char outputBuffer[65]) {
    for (unsigned int i = 0; i < length; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[length * 2] = 0;
}

int is_hash_in_db(const char *hash, FILE *file) {
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char stored_hash[65];

        if (sscanf(line, "%64s %*s", stored_hash) == 1) {
            if (strcmp(stored_hash, hash) == 0) {
                return 1;
            }
        }
    }

    return 0;
}

