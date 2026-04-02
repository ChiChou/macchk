// Experiment 1: Stack Zero Initialization
// Compile with/without -ftrivial-auto-var-init=zero
// Test: uninitialized stack variables should be zero-filled when flag is enabled

#include <stdio.h>
#include <string.h>

// Prevent inlining so we can see the stack frame clearly
__attribute__((noinline))
int use_uninitialized_int(void) {
    int x;           // uninitialized local
    return x;        // read before write
}

__attribute__((noinline))
void use_uninitialized_array(char *out) {
    char buf[64];    // uninitialized stack buffer
    memcpy(out, buf, 64);  // copy uninitialized data out
}

typedef struct {
    int a;
    int b;
    char name[32];
    double value;
} Record;

__attribute__((noinline))
Record use_uninitialized_struct(void) {
    Record r;        // uninitialized struct on stack
    return r;        // return without initialization
}

__attribute__((noinline))
int use_uninitialized_pointer(void) {
    int *p;          // uninitialized pointer
    int arr[16];     // uninitialized array
    // Use arr[0] to prevent optimization
    arr[0] = 42;
    return arr[0];
}

int main(int argc, char *argv[]) {
    printf("int: %d\n", use_uninitialized_int());

    char out[64];
    use_uninitialized_array(out);
    printf("buf[0]: %d\n", out[0]);

    Record r = use_uninitialized_struct();
    printf("record.a: %d\n", r.a);

    printf("arr: %d\n", use_uninitialized_pointer());
    return 0;
}
