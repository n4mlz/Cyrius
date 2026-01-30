#include "libsyscall.h"

static u16 to_be16(u16 value) {
    return (u16)((value << 8) | (value >> 8));
}

static u32 to_be32(u32 value) {
    return ((value & 0x000000ffU) << 24) |
           ((value & 0x0000ff00U) << 8) |
           ((value & 0x00ff0000U) >> 8) |
           ((value & 0xff000000U) >> 24);
}

static const char ok_msg[] = "NET:OK\n";
static const char pong_msg[] = "PONG";

void _start(void) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = to_be16(12346);
    addr.sin_addr = to_be32(0);
    for (int i = 0; i < 8; ++i) {
        addr.sin_zero[i] = 0;
    }

    int fd = (int)sys_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        sys_exit(1);
    }

    if (sys_bind(fd, &addr, sizeof(addr)) < 0) {
        sys_exit(2);
    }

    if (sys_listen(fd, 1) < 0) {
        sys_exit(3);
    }

    u32 addrlen = sizeof(addr);
    int client = (int)sys_accept(fd, &addr, &addrlen);
    if (client < 0) {
        sys_exit(4);
    }

    char buf[16];
    isize n = sys_read(client, buf, sizeof(buf));
    if (n > 0) {
        sys_write(client, pong_msg, sizeof(pong_msg) - 1);
    }

    sys_close(client);
    sys_close(fd);
    sys_write(1, ok_msg, sizeof(ok_msg) - 1);
    sys_exit(0);
}
