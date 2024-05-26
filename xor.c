#include <string.h>
#include "xor.h"

void xor(char *x_str) {
    int i, key=0xFE;

    for (i = 0; i < strlen(x_str); i++) {
        x_str[i] ^= key;
    }
}

