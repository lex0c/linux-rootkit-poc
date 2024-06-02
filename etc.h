#pragma once

#include <openssl/evp.h>

void xor(char *x_str);
void cleanup(void *var, int len) __attribute__((visibility("hidden")));
int extract_pid(const char *path) __attribute__((visibility("hidden")));
void calculate_sha256(const char *path, unsigned char output[EVP_MAX_MD_SIZE], unsigned int *output_length) __attribute__((visibility("hidden")));
void hash_to_string(unsigned char *hash, unsigned int length, char outputBuffer[65]) __attribute__((visibility("hidden")));
int is_hash_in_db(const char *hash, FILE *file) __attribute__((visibility("hidden")));
