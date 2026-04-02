// Experiment 2: Pointer Authentication (arm64e / PAC)
// Compile arm64 vs arm64e to observe PAC instructions

#include <stdio.h>

typedef int (*operation_t)(int, int);

__attribute__((noinline))
int add(int a, int b) { return a + b; }

__attribute__((noinline))
int multiply(int a, int b) { return a * b; }

// Indirect call through function pointer — PAC should sign/authenticate
__attribute__((noinline))
int apply_op(operation_t op, int a, int b) {
    return op(a, b);
}

// Array of function pointers — PAC should protect stored pointers
static operation_t ops[] = { add, multiply };

__attribute__((noinline))
int dispatch(int idx, int a, int b) {
    return ops[idx](a, b);
}

// Recursive call to exercise return address signing
__attribute__((noinline))
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int main(int argc, char *argv[]) {
    printf("add: %d\n", apply_op(add, 3, 4));
    printf("mul: %d\n", apply_op(multiply, 3, 4));
    printf("dispatch: %d\n", dispatch(0, 5, 6));
    printf("fact: %d\n", factorial(10));
    return 0;
}
