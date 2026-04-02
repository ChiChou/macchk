// Experiment 4: C++ Bounds Safe Buffers (libc++ hardening)
// Compile with/without _LIBCPP_HARDENING_MODE_FAST

#include <vector>
#include <span>
#include <string>
#include <cstdio>

// Vector element access — hardening adds bounds check to operator[]
__attribute__((noinline))
int vector_access(const std::vector<int>& v, size_t idx) {
    return v[idx];
}

// Span element access
__attribute__((noinline))
int span_access(std::span<const int> s, size_t idx) {
    return s[idx];
}

// String character access
__attribute__((noinline))
char string_access(const std::string& s, size_t idx) {
    return s[idx];
}

// Vector front/back — hardening checks for empty
__attribute__((noinline))
int vector_front(const std::vector<int>& v) {
    return v.front();
}

int main() {
    std::vector<int> v = {10, 20, 30, 40, 50};
    printf("v[2]: %d\n", vector_access(v, 2));
    printf("front: %d\n", vector_front(v));

    std::span<const int> sp(v);
    printf("span[3]: %d\n", span_access(sp, 3));

    std::string str = "hello";
    printf("str[1]: %c\n", string_access(str, 1));

    return 0;
}
