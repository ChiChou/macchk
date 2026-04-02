// Experiment 5: Security Compiler Warnings
// Each function triggers a specific warning from ENABLE_SECURITY_COMPILER_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 1. -Wbuiltin-memcpy-chk-size: destination smaller than copy size
void warn_memcpy_chk(void) {
    char dst[4];
    char src[16] = "hello world!!!!";
    memcpy(dst, src, 16);  // dst is only 4 bytes
    printf("%s\n", dst);
}

// 2. -Wformat-nonliteral: format string is not a string literal
void warn_format_nonliteral(const char *fmt) {
    printf(fmt, 42);  // format string not a literal
}

// 3. -Warray-bounds: out-of-bounds array index
int warn_array_bounds(void) {
    int arr[4] = {1, 2, 3, 4};
    return arr[10];  // index past end
}

// 4. -Warray-bounds-pointer-arithmetic: pointer arithmetic past bounds
int warn_pointer_arith(void) {
    int arr[4] = {1, 2, 3, 4};
    int *p = arr + 10;  // pointer past end
    return *p;
}

// 5. -Wsizeof-array-div: incorrect sizeof for element count
int warn_sizeof_div(void) {
    int arr[16];
    short dummy = 0;
    // Wrong: dividing by sizeof(short) instead of sizeof(int)
    int count = sizeof(arr) / sizeof(dummy);
    return count;
}

// 6. -Wsizeof-pointer-div: sizeof pointer instead of array
int warn_sizeof_pointer(int *p) {
    // Wrong: sizeof(p) is pointer size, not array size
    return sizeof(p) / sizeof(p[0]);
}

// 7. -Wreturn-stack-address: returning address of local variable
int *warn_return_stack(void) {
    int local = 42;
    return &local;  // dangling pointer
}

// 8. -Wshadow: variable shadows another
int warn_shadow(int x) {
    if (x > 0) {
        int x = 10;  // shadows parameter x
        return x;
    }
    return x;
}

// 9. -Wempty-body: empty body in control flow
int warn_empty_body(int x) {
    if (x > 0);      // empty body — likely a bug
        return x + 1;
    return x;
}

int main(void) {
    return 0;
}
