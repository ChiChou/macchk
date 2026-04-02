// Experiment 6: Typed Allocators
// Compile with/without -ftyped-memory-operations-experimental
// Test: malloc/calloc usage with different types

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    double value;
    char name[32];
} Record;

typedef struct {
    int x, y, z;
} Point;

__attribute__((noinline))
Record *create_record(int id, double value, const char *name) {
    Record *r = (Record *)malloc(sizeof(Record));
    if (r) {
        r->id = id;
        r->value = value;
        strncpy(r->name, name, 31);
        r->name[31] = '\0';
    }
    return r;
}

__attribute__((noinline))
Point *create_points(int count) {
    Point *pts = (Point *)calloc(count, sizeof(Point));
    return pts;
}

__attribute__((noinline))
void free_record(Record *r) {
    free(r);
}

int main(void) {
    Record *r = create_record(1, 3.14, "test");
    Point *pts = create_points(10);

    if (r) printf("id: %d\n", r->id);
    free_record(r);
    free(pts);
    return 0;
}
