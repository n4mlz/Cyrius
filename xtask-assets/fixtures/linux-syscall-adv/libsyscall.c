#include "libsyscall.h"

isize sys_call0(isize num) {
    isize ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num)
        : "rcx", "r11", "memory");
    return ret;
}

isize sys_call1(isize num, isize arg1) {
    isize ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1)
        : "rcx", "r11", "memory");
    return ret;
}

isize sys_call2(isize num, isize arg1, isize arg2) {
    isize ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2)
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

isize sys_call4(isize num, isize arg1, isize arg2, isize arg3, isize arg4) {
    isize ret;
    register isize r10 __asm__("r10") = arg4;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10)
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

isize sys_write(int fd, const void *buf, usize len) {
    return sys_call3(SYS_write, fd, (isize)buf, (isize)len);
}

isize sys_writev(int fd, const struct iovec *iov, int iovcnt) {
    return sys_call3(SYS_writev, fd, (isize)iov, iovcnt);
}

isize sys_open(const char *path, int flags, int mode) {
    return sys_call3(SYS_open, (isize)path, flags, mode);
}

isize sys_openat(int dirfd, const char *path, int flags, int mode) {
    return sys_call4(SYS_openat, dirfd, (isize)path, flags, mode);
}

isize sys_close(int fd) {
    return sys_call1(SYS_close, fd);
}

isize sys_stat(const char *path, struct linux_stat *statbuf) {
    return sys_call3(SYS_stat, (isize)path, (isize)statbuf, 0);
}

isize sys_lstat(const char *path, struct linux_stat *statbuf) {
    return sys_call3(SYS_lstat, (isize)path, (isize)statbuf, 0);
}

isize sys_newfstatat(int dirfd, const char *path, struct linux_stat *statbuf, int flags) {
    return sys_call4(SYS_newfstatat, dirfd, (isize)path, (isize)statbuf, flags);
}

isize sys_ioctl(int fd, isize request, void *argp) {
    return sys_call3(SYS_ioctl, fd, request, (isize)argp);
}

isize sys_mmap(void *addr, usize len, int prot, int flags, int fd, isize offset) {
    return sys_call6(SYS_mmap, (isize)addr, (isize)len, prot, flags, fd, offset);
}

isize sys_munmap(void *addr, usize len) {
    return sys_call2(SYS_munmap, (isize)addr, (isize)len);
}

isize sys_brk(void *addr) {
    return sys_call1(SYS_brk, (isize)addr);
}

isize sys_arch_prctl(isize code, isize addr) {
    return sys_call2(SYS_arch_prctl, code, addr);
}

isize sys_fork(void) {
    return sys_call0(SYS_fork);
}

isize sys_execve(const char *path, const char *const *argv, const char *const *envp) {
    return sys_call3(SYS_execve, (isize)path, (isize)argv, (isize)envp);
}

isize sys_wait4(isize pid, int *status, int options, void *rusage) {
    return sys_call4(SYS_wait4, pid, (isize)status, options, (isize)rusage);
}

isize sys_getdents64(int fd, void *dirp, usize count) {
    return sys_call3(SYS_getdents64, fd, (isize)dirp, (isize)count);
}

__attribute__((noreturn)) void sys_exit(int code) {
    sys_call1(SYS_exit, code);
    for (;;) {
    }
}
