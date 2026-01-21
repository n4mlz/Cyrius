#include "libsyscall.h"

isize sys_call3(isize num, isize arg1, isize arg2, isize arg3) {
    isize ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory");
    return ret;
}

isize sys_write(int fd, const void *buf, usize len) {
    return sys_call3(SYS_write, fd, (isize)buf, (isize)len);
}

__attribute__((noreturn)) void sys_exit(int code) {
    sys_call3(SYS_exit, code, 0, 0);
    for (;;) {
    }
}
