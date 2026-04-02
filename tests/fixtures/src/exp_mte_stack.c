#include <stdio.h>
#include <string.h>

__attribute__((noinline))
void process_buffer(const char *input) {
    char buf[128];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("processed: %s\n", buf);
}

__attribute__((noinline))
int compute(int a, int b) {
    int results[16];
    for (int i = 0; i < 16; i++) {
        results[i] = a * i + b;
    }
    int sum = 0;
    for (int i = 0; i < 16; i++) {
        sum += results[i];
    }
    return sum;
}

int main(void) {
    process_buffer("hello MTE");
    printf("result: %d\n", compute(3, 7));
    return 0;
}
