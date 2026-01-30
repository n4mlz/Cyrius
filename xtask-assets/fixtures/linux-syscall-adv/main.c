#include "libsyscall.h"

static const char stat_path[] = "stat.txt";
static const char lstat_path[] = "stat-link";
static const char child_path[] = "/child";
static const usize page_size = 4096;

static usize str_len(const char *s) {
    usize n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}

static void write_str(const char *s) {
    sys_write(1, s, str_len(s));
}

static void write_u32(u32 value) {
    char buf[16];
    int i = 0;
    if (value == 0) {
        char zero = '0';
        sys_write(1, &zero, 1);
        return;
    }
    while (value > 0) {
        buf[i++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (i > 0) {
        char ch = buf[--i];
        sys_write(1, &ch, 1);
    }
}

static int str_eq(const char *a, const char *b) {
    usize i = 0;
    while (a[i] || b[i]) {
        if (a[i] != b[i]) {
            return 0;
        }
        i++;
    }
    return 1;
}

struct linux_dirent64 {
    u64 d_ino;
    u64 d_off;
    u16 d_reclen;
    unsigned char d_type;
    char d_name[];
} __attribute__((packed));

static int scan_dirents(const char *buf, usize len, const char *target) {
    usize off = 0;
    int found = 0;
    while (off + 19 <= len) {
        const struct linux_dirent64 *ent = (const struct linux_dirent64 *)(buf + off);
        if (ent->d_reclen < 19 || off + ent->d_reclen > len) {
            break;
        }
        if (str_eq(ent->d_name, target)) {
            found = 1;
        }
        off += ent->d_reclen;
    }
    return found;
}

void _start(void) {
    enum {
        PROT_READ = 0x1,
        PROT_WRITE = 0x2,
        MAP_PRIVATE = 0x02,
        MAP_ANON = 0x20,
    };

    struct iovec iov[2];
    iov[0].iov_base = (void *)"WRITE";
    iov[0].iov_len = 5;
    iov[1].iov_base = (void *)"V\n";
    iov[1].iov_len = 2;
    if (sys_writev(1, iov, 2) != 7) {
        write_str("WRITEV:BAD\n");
    }

    struct linux_stat st;
    if (sys_stat(stat_path, &st) == 0 && st.st_size == 8 && st.st_mode != 0) {
        write_str("STAT:OK\n");
    } else {
        write_str("STAT:BAD\n");
    }

    if (sys_lstat(lstat_path, &st) == 0 && (st.st_mode & 0170000) == 0120000) {
        write_str("LSTAT:OK\n");
    } else {
        write_str("LSTAT:BAD\n");
    }

    int at_fd = (int)sys_openat(AT_FDCWD, stat_path, 0, 0);
    if (at_fd >= 0) {
        sys_close(at_fd);
        write_str("OPENAT:OK\n");
    } else {
        write_str("OPENAT:BAD\n");
    }

    int fstat_ok = 0;
    if (sys_newfstatat(AT_FDCWD, stat_path, &st, 0) == 0 && st.st_size == 8) {
        if (sys_newfstatat(AT_FDCWD, lstat_path, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
            (st.st_mode & 0170000) == 0120000) {
            fstat_ok = 1;
        }
    }
    if (fstat_ok) {
        write_str("FSTATAT:OK\n");
    } else {
        write_str("FSTATAT:BAD\n");
    }

    int dir_fd = (int)sys_open("/", 0, 0);
    if (dir_fd < 0) {
        write_str("DENTS:BAD\n");
    } else {
        char dents[512];
        int found = 0;
        int ok = 1;
        for (int i = 0; i < 8; i++) {
            isize read = sys_getdents64(dir_fd, dents, sizeof(dents));
            if (read == 0) {
                break;
            }
            if (read < 0) {
                ok = 0;
                break;
            }
            if (scan_dirents(dents, (usize)read, stat_path)) {
                found = 1;
            }
        }
        sys_close(dir_fd);
        if (ok && found) {
            write_str("DENTS:OK\n");
        } else {
            write_str("DENTS:BAD\n");
        }
    }

    struct {
        u16 ws_row;
        u16 ws_col;
        u16 ws_xpixel;
        u16 ws_ypixel;
    } winsz;
    if (sys_ioctl(0, 0x5413, &winsz) == 0 && winsz.ws_row > 0 && winsz.ws_col > 0) {
        write_str("IOCTL:OK\n");
    } else {
        write_str("IOCTL:BAD\n");
    }

    void *map = (void *)sys_mmap(0, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if ((isize)map < 0) {
        write_str("MMAP:BAD\n");
    } else {
        volatile char *ptr = (volatile char *)map;
        ptr[0] = 'O';
        ptr[1] = 'K';
        if (ptr[0] == 'O' && ptr[1] == 'K' && sys_munmap(map, page_size) == 0) {
            write_str("MMAP:OK\n");
        } else {
            write_str("MMAP:BAD\n");
        }
    }

    void *cur = (void *)sys_brk(0);
    void *target = (void *)((usize)cur + 0x2000);
    void *res = (void *)sys_brk(target);
    if (res == target) {
        write_str("BRK:OK\n");
    } else {
        write_str("BRK:BAD\n");
    }

    if (sys_arch_prctl(ARCH_SET_FS, 0) == 0) {
        write_str("ARCH:OK\n");
    } else {
        write_str("ARCH:BAD\n");
    }

    isize pid = sys_fork();
    if (pid == 0) {
        write_str("FORK:CHILD\n");
        const char *argv[] = {"child", 0};
        sys_execve(child_path, argv, 0);
        write_str("EXEC:FAIL\n");
        sys_exit(1);
    }

    if (pid < 0) {
        write_str("FORK:FAIL\n");
        sys_exit(1);
    }

    int status = 0;
    for (;;) {
        isize waited = sys_wait4(pid, &status, 1, 0);
        if (waited == pid) {
            break;
        }
    }
    write_str("WAIT:");
    write_u32((u32)((status >> 8) & 0xff));
    write_str("\n");

    sys_exit(0);
}
