#include <stdlib.h>

int main(int argc, char **argv) {
    int *p = (int *)malloc(sizeof(int) * 10);
    p[argc] = 42;
    int result = p[0] + argc;
    free(p);
    return result;
}
