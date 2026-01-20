#ifndef CYRIUS_LIBSYSCALL_H
#define CYRIUS_LIBSYSCALL_H

typedef unsigned long usize;
typedef long isize;

enum {
    SYS_read = 0,
    SYS_write = 1,
    SYS_open = 2,
    SYS_close = 3,
    SYS_exit = 60,
};

isize sys_call(isize num, isize arg1, isize arg2, isize arg3);
isize sys_read(int fd, void *buf, usize len);
isize sys_write(int fd, const void *buf, usize len);
isize sys_open(const char *path, int flags, int mode);
isize sys_close(int fd);
__attribute__((noreturn)) void sys_exit(int code);

#endif
