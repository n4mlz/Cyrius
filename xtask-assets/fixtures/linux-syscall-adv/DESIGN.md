# linux-syscall-adv

## Purpose
- Exercise Linux-compatible syscalls beyond the minimal read/write/open/close path.
- Cover `writev`, `stat`, `brk`, `arch_prctl`, `fork`, `execve`, and `wait4` in one deterministic run.

## Notes
- Built as a static, non-PIE ELF with no libc dependency.
- Output is a fixed sequence of lines so the kernel integration test can compare stdout.
- The test expects an additional `/child` executable to exist in the VFS.
