# linux-syscall-net Fixture

## Role
- Validates the minimal TCP socket syscalls (`socket`, `bind`, `listen`, `accept`) from a
  libc-free Linux ELF.
- Reads one payload from the accepted connection, replies with `PONG`, then writes `NET:OK`
  to stdout for the kernel test to assert.

## Notes
- Uses a fixed TCP port (12346) and binds `0.0.0.0` so the kernel-side test client can connect.
- Built via `xtask-assets` into `target/xtask-assets/linux-syscall-net.elf`.
