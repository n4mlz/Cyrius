# Linux Syscall Fixture Design Notes

## Role and Scope
- Defines a minimal Linux userspace program that exercises `read`/`write`/`open`/`close`/`exit`.
- Used to compare host Linux behavior with Cyrius behavior for the same binary.

## Build
- Built by `xtask-assets` using the host C toolchain (`cc`/`gcc`/`clang`).
- Compiled as static, no-PIE, and libc-free; syscalls are issued directly via `syscall`.
- Output is written to `target/xtask-assets/linux-syscall.elf`.

## I/O Contract
- Reads from stdin, writes stdin back to stdout.
- Opens `msg.txt` in the working directory, reads it, and writes contents to stdout.
