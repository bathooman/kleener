#include "klee/klee.h"
int main(int argc, char *argv[]) {
    int x;
    klee_make_symbolic(&x, sizeof(x), "x");
    int b, c;
    if (x > 5)
    {
        b = x + 10;
        klee_print_expr("b", b);
    }
    else
    {
        c = x * x;
        klee_print_expr("c", c);
    }
    
 }