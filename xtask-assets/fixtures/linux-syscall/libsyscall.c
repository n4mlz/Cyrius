#include "libsyscall.h"

isize sys_call(isize num, isize arg1, isize arg2, isize arg3) {
    isize ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory");
    return ret;
}

isize sys_read(int fd, void *buf, usize len) {
    return sys_call(SYS_read, fd, (isize)buf, (isize)len);
}

isize sys_write(int fd, const void *buf, usize len) {
    return sys_call(SYS_write, fd, (isize)buf, (isize)len);
}

isize sys_open(const char *path, int flags, int mode) {
    return sys_call(SYS_open, (isize)path, flags, mode);
}

isize sys_close(int fd) {
    return sys_call(SYS_close, fd, 0, 0);
}

__attribute__((noreturn)) void sys_exit(int code) {
    sys_call(SYS_exit, code, 0, 0);
    for (;;) {
    }
}
