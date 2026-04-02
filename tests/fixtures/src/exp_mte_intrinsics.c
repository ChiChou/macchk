#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Use MTE intrinsics directly
#include <arm_acle.h>

__attribute__((noinline))
void *tagged_alloc(size_t size) {
    void *p = malloc(size);
    if (!p) return NULL;
    // Insert random tag into pointer
    p = __arm_mte_create_random_tag(p, 0);
    // Store tag to memory (tag the allocation)
    __arm_mte_set_tag(p);
    return p;
}

__attribute__((noinline))
int tagged_read(int *p) {
    return *p;
}

__attribute__((noinline))
void tagged_free(void *p) {
    // Clear tag before freeing
    p = __arm_mte_increment_tag(p, 0);
    free(p);
}

int main(void) {
    int *p = (int *)tagged_alloc(sizeof(int));
    if (p) {
        *p = 42;
        printf("val: %d\n", tagged_read(p));
        tagged_free(p);
    }
    return 0;
}
