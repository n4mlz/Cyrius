#include "libsyscall.h"

isize sys_call1(isize num, isize arg1) {
    isize ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1)
        : "rcx", "r11", "memory");
    return ret;
}

isize sys_call3(isize num, isize arg1, isize arg2, isize arg3) {
    isize ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory");
    return ret;
}

isize sys_read(int fd, void *buf, usize len) {
    return sys_call3(SYS_read, fd, (isize)buf, (isize)len);
}

isize sys_write(int fd, const void *buf, usize len) {
    return sys_call3(SYS_write, fd, (isize)buf, (isize)len);
}

isize sys_close(int fd) {
    return sys_call1(SYS_close, fd);
}

isize sys_socket(int domain, int type, int protocol) {
    return sys_call3(SYS_socket, domain, type, protocol);
}

isize sys_bind(int fd, const struct sockaddr_in *addr, usize len) {
    return sys_call3(SYS_bind, fd, (isize)addr, (isize)len);
}

isize sys_listen(int fd, int backlog) {
    return sys_call3(SYS_listen, fd, backlog, 0);
}

isize sys_accept(int fd, struct sockaddr_in *addr, u32 *addrlen) {
    return sys_call3(SYS_accept, fd, (isize)addr, (isize)addrlen);
}

__attribute__((noreturn)) void sys_exit(int code) {
    sys_call1(SYS_exit, code);
    for (;;) {
    }
}
