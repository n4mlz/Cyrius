#ifndef CYRIUS_LIBSYSCALL_ADV_H
#define CYRIUS_LIBSYSCALL_ADV_H

typedef unsigned long usize;
typedef long isize;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned long long u64;
typedef long long i64;

enum {
    SYS_read = 0,
    SYS_write = 1,
    SYS_open = 2,
    SYS_close = 3,
    SYS_stat = 4,
    SYS_lstat = 6,
    SYS_openat = 257,
    SYS_newfstatat = 262,
    SYS_mmap = 9,
    SYS_munmap = 11,
    SYS_brk = 12,
    SYS_ioctl = 16,
    SYS_writev = 20,
    SYS_fork = 57,
    SYS_execve = 59,
    SYS_exit = 60,
    SYS_wait4 = 61,
    SYS_arch_prctl = 158,
    SYS_getdents64 = 217,
};

enum {
    ARCH_SET_FS = 0x1002,
};

enum {
    AT_FDCWD = -100,
    AT_SYMLINK_NOFOLLOW = 0x100,
};

struct iovec {
    void *iov_base;
    usize iov_len;
};

struct linux_stat {
    u64 st_dev;
    u64 st_ino;
    u64 st_nlink;
    u32 st_mode;
    u32 st_uid;
    u32 st_gid;
    u32 __pad0;
    u64 st_rdev;
    i64 st_size;
    i64 st_blksize;
    i64 st_blocks;
    i64 st_atime;
    i64 st_atime_nsec;
    i64 st_mtime;
    i64 st_mtime_nsec;
    i64 st_ctime;
    i64 st_ctime_nsec;
    i64 __reserved[3];
};

isize sys_call0(isize num);
isize sys_call1(isize num, isize arg1);
isize sys_call2(isize num, isize arg1, isize arg2);
isize sys_call3(isize num, isize arg1, isize arg2, isize arg3);
isize sys_call4(isize num, isize arg1, isize arg2, isize arg3, isize arg4);
isize sys_call6(isize num, isize arg1, isize arg2, isize arg3, isize arg4, isize arg5, isize arg6);

isize sys_write(int fd, const void *buf, usize len);
isize sys_writev(int fd, const struct iovec *iov, int iovcnt);
isize sys_open(const char *path, int flags, int mode);
isize sys_openat(int dirfd, const char *path, int flags, int mode);
isize sys_close(int fd);
isize sys_stat(const char *path, struct linux_stat *statbuf);
isize sys_lstat(const char *path, struct linux_stat *statbuf);
isize sys_newfstatat(int dirfd, const char *path, struct linux_stat *statbuf, int flags);
isize sys_ioctl(int fd, isize request, void *argp);
isize sys_mmap(void *addr, usize len, int prot, int flags, int fd, isize offset);
isize sys_munmap(void *addr, usize len);
isize sys_brk(void *addr);
isize sys_arch_prctl(isize code, isize addr);
isize sys_fork(void);
isize sys_execve(const char *path, const char *const *argv, const char *const *envp);
isize sys_wait4(isize pid, int *status, int options, void *rusage);
isize sys_getdents64(int fd, void *dirp, usize count);
__attribute__((noreturn)) void sys_exit(int code);

#endif
