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

