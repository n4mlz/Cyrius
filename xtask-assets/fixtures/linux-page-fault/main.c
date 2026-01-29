#include <stdint.h>

__attribute__((noreturn)) void _start(void) {
    volatile uint64_t *ptr = (uint64_t *)0xdeadbeef000ULL;
    (void)*ptr;
    for (;;) {
        __asm__ __volatile__("pause");
    }
}
