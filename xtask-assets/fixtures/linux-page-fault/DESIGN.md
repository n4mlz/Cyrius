# Linux Page Fault Fixture Design Notes

## Role and Scope
- Defines a minimal Linux userspace program that intentionally triggers a user-mode page fault.
- Used by kernel tests to validate trap-frame decoding for error-code exceptions.

## Build
- Built by `xtask-assets` using the host C toolchain (`cc`/`gcc`/`clang`).
- Compiled as static, no-PIE, and libc-free; no syscalls are issued.
- Output is written to `target/xtask-assets/linux-page-fault.elf`.

## Fault Contract
- Reads from an unmapped canonical address (`0xdeadbeef000`), which should raise #PF in ring 3.
- No normal exit path is required because the kernel terminates the faulting thread.
