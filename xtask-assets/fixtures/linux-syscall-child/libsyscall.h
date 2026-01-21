#ifndef CYRIUS_LIBSYSCALL_CHILD_H
#define CYRIUS_LIBSYSCALL_CHILD_H

typedef unsigned long usize;
typedef long isize;

enum {
    SYS_write = 1,
    SYS_exit = 60,
};

isize sys_call3(isize num, isize arg1, isize arg2, isize arg3);
isize sys_write(int fd, const void *buf, usize len);
__attribute__((noreturn)) void sys_exit(int code);

#endif
