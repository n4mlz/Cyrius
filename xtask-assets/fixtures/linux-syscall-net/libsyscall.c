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

isize sys_call6(isize num, isize arg1, isize arg2, isize arg3, isize arg4, isize arg5, isize arg6) {
    isize ret;
    register isize r10 __asm__("r10") = arg4;
    register isize r8 __asm__("r8") = arg5;
    register isize r9 __asm__("r9") = arg6;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
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

isize sys_setsockopt(int fd, int level, int optname, const void *optval, usize optlen) {
    return sys_call6(SYS_setsockopt, fd, level, optname, (isize)optval, (isize)optlen, 0);
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

isize sys_accept4(int fd, struct sockaddr_in *addr, u32 *addrlen, int flags) {
    return sys_call6(SYS_accept4, fd, (isize)addr, (isize)addrlen, flags, 0, 0);
}

isize sys_sendto(int fd, const void *buf, usize len, int flags, const void *addr, usize addrlen) {
    return sys_call6(SYS_sendto, fd, (isize)buf, (isize)len, flags, (isize)addr, (isize)addrlen);
}

__attribute__((noreturn)) void sys_exit(int code) {
    sys_call1(SYS_exit, code);
    for (;;) {
    }
}
