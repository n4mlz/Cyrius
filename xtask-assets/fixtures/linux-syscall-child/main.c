#include "libsyscall.h"

void _start(void) {
    sys_write(1, "EXEC:CHILD\n", 11);
    sys_exit(42);
}
