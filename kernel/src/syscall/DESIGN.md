# Syscall Subsystem Design Notes

## Role and Scope
- Provide ABI-aware syscall dispatch for host and Linux guests.
- Offer a minimal, table-driven entry point that can be reused across architectures once additional vectors or `SYSCALL/SYSRET` wiring is added. Architecture glue (interrupt vector registration) resides under `arch/` so this module stays generic.

## Entry and Dispatch
- x86-64 currently enters via `int 0x80` (vector `0x80`, DPL=3). The vector is registered in `arch/x86_64/syscall.rs`, which hands control to the generic dispatcher here.
- Calling convention follows the Linux `syscall` layout even though we use `int 0x80`: `rax` carries the syscall number; `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` carry arguments 0–5. Results are written back into `rax`.
- `Abi` is tracked per-process; on every context switch the scheduler looks up the process ABI and programs the active value into a global atomic so syscall handling is O(1) and does not require scheduler locks.
- Dispatch returns a `DispatchResult`, distinguishing a normal return value from requests to terminate the current thread (used by Linux `_exit`).

## Error Mapping
- `SysError` abstracts common error kinds; each ABI module owns its numeric mapping via ABI-specific enums (`LinuxErrno`, `HostErrno`). Linux maps to negative errno (e.g., `NoSys=38`, `InvalidArgument=22`) while host returns positive codes with a minimal private numbering. Success paths write the raw return value unchanged.

## Tables
- Host dispatch implements `container_create`, which reads bundle metadata from the global VFS and
  registers a new container entry, and `container_start`, which launches the container init
  process using the container VFS. Host pointers are treated as kernel-mapped addresses until
  userland separation exists.
- Linux dispatch implements a minimal set of process/syscall plumbing needed by static busybox:
  `read`, `write`, `open`, `close`, `writev`, `stat`, `brk`, `fork`, `execve`, `wait4`, `arch_prctl`,
  plus stubbed signal/ioctl calls. Unsupported numbers map to `ENOSYS`.

## Extension Points / TODO
- Add architecture-specific fast paths (`syscall`/`sysret`) once MSR programming is available.
- Expand the Linux table and introduce per-process policy hooks (seccomp-like filters).
- Align the host ABI with native kernel services once those syscalls are specified.
