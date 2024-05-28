#pragma once

void xor(char *x_str);
void cleanup(void *var, int len) __attribute__((visibility("hidden")));
int extract_pid(const char *path) __attribute__((visibility("hidden")));
