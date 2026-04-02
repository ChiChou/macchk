extern int a(int), b(int), c(int), d(int), e(int);
extern int f(int), g(int), h(int), i(int), j(int);

/* Force a jump table by calling different external functions per case. */
int dispatch(int x) {
    switch (x) {
        case 0: return a(x);
        case 1: return b(x);
        case 2: return c(x);
        case 3: return d(x);
        case 4: return e(x);
        case 5: return f(x);
        case 6: return g(x);
        case 7: return h(x);
        case 8: return i(x);
        case 9: return j(x);
        default: return -1;
    }
}
