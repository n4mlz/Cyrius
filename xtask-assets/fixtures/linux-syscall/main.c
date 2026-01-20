#include "libsyscall.h"

static char stdin_buf[32];
static char file_buf[64];
static const char path[] = "msg.txt";

void _start(void) {
    isize n = sys_read(0, stdin_buf, sizeof(stdin_buf));
    if (n > 0) {
        sys_write(1, stdin_buf, (usize)n);
    }

    isize fd = sys_open(path, 0, 0);
    if (fd >= 0) {
        isize r = sys_read((int)fd, file_buf, sizeof(file_buf));
        if (r > 0) {
            sys_write(1, file_buf, (usize)r);
        }
        sys_close((int)fd);
    }

    sys_exit(0);
}
