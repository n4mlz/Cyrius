#ifndef CYRIUS_LIBSYSCALL_NET_H
#define CYRIUS_LIBSYSCALL_NET_H

typedef unsigned long usize;
typedef long isize;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned char u8;

enum {
    SYS_read = 0,
    SYS_write = 1,
    SYS_close = 3,
    SYS_socket = 41,
    SYS_accept = 43,
    SYS_bind = 49,
    SYS_listen = 50,
    SYS_exit = 60,
};

enum {
    AF_INET = 2,
    SOCK_STREAM = 1,
};

struct sockaddr_in {
    u16 sin_family;
    u16 sin_port;
    u32 sin_addr;
    u8 sin_zero[8];
};

isize sys_call1(isize num, isize arg1);
isize sys_call3(isize num, isize arg1, isize arg2, isize arg3);

isize sys_read(int fd, void *buf, usize len);
isize sys_write(int fd, const void *buf, usize len);
isize sys_close(int fd);
isize sys_socket(int domain, int type, int protocol);
isize sys_bind(int fd, const struct sockaddr_in *addr, usize len);
isize sys_listen(int fd, int backlog);
isize sys_accept(int fd, struct sockaddr_in *addr, u32 *addrlen);
__attribute__((noreturn)) void sys_exit(int code);

#endif
