# linux-syscall-child

## Purpose
- Minimal execve target for `linux-syscall-adv`.
- Writes a single line and exits with a non-zero status for wait4 validation.

## Notes
- Built as a static, non-PIE ELF with no libc dependency.
