// Experiment 10: __RESTRICT segment
// Build with: -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null
// Expected: __RESTRICT/__restrict segment present
#include <stdio.h>

int main(int argc, char **argv) {
    printf("restricted binary: argc=%d\n", argc);
    return 0;
}
