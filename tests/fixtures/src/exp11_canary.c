// Experiment 11: Stack canary
// Build with: -fstack-protector-all vs -fno-stack-protector
// Expected: ___stack_chk_fail in imports when protected
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
void vulnerable(const char *input) {
    char buf[32];
    strcpy(buf, input);  // deliberate overflow target
    printf("%s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1)
        vulnerable(argv[1]);
    return 0;
}
