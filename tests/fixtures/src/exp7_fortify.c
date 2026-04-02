// Experiment 7: FORTIFY_SOURCE
// Build with: -D_FORTIFY_SOURCE=2 -O1
// Expected: __strcpy_chk, __memcpy_chk etc. in imports
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

__attribute__((noinline))
void copy_string(char *dst, const char *src, size_t n) {
    strncpy(dst, src, n);
}

__attribute__((noinline))
void copy_mem(void *dst, const void *src, size_t n) {
    memcpy(dst, src, n);
}

__attribute__((noinline))
void format_str(char *buf, size_t sz, const char *fmt, int val) {
    snprintf(buf, sz, fmt, val);
}

int main(int argc, char **argv) {
    char buf[64];
    copy_string(buf, argv[0], sizeof(buf));
    printf("%s\n", buf);
    char buf2[64];
    copy_mem(buf2, buf, sizeof(buf2));
    format_str(buf2, sizeof(buf2), "arg=%d", argc);
    printf("%s\n", buf2);
    return 0;
}
