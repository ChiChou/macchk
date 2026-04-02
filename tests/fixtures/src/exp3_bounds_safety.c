// Experiment 3: C Bounds Safety (-fbounds-safety)
// Test: arrays with __counted_by annotations get runtime bounds checks

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A function that takes a counted buffer — bounds safety will insert checks
__attribute__((noinline))
int sum_array(int *__counted_by(count) arr, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        total += arr[i];
    }
    return total;
}

// A function that takes a sized buffer
__attribute__((noinline))
void fill_buffer(char *__sized_by(size) buf, int size) {
    for (int i = 0; i < size; i++) {
        buf[i] = (char)(i & 0xFF);
    }
}

// Single-pointer access (default: treated as pointing to one element)
__attribute__((noinline))
int read_single(int *p) {
    return *p;
}

int main(int argc, char *argv[__counted_by(argc)]) {
    int arr[] = {1, 2, 3, 4, 5};
    printf("sum: %d\n", sum_array(arr, 5));

    char buf[32];
    fill_buffer(buf, 32);
    printf("buf[31]: %d\n", buf[31]);

    int val = 42;
    printf("single: %d\n", read_single(&val));
    return 0;
}
