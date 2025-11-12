# Syscall Layer Design Notes

## Scope
- Centralise ABI-related enums (`AbiFlavor`, `SyscallPolicy`) so both process/thread subsystems can declare intent without duplicating definitions.
- Provide the foundation for future syscall table dispatch (Host vs Linux) without committing to the full implementation yet.

## Concepts
- `AbiFlavor` chooses between Host-native and Linux-compatible syscall tables. Scheduler/context-switch logic will look at this flag when configuring hardware entry points.
- `SyscallPolicy` mimics a seccomp filter for demos: `Minimal` allows only `write`/`exit`, while `Full` will eventually unlock the whole Linux subset.

## Next Steps
- Introduce `SyscallTable` and dispatcher glue as soon as syscall entry plumbing is ready.
- Extend policies to enumerate allowed opcodes explicitly and log denials for the Linux Box demo.
- Document any architecture-specific dependencies (e.g., MSR configuration) once syscall instructions are wired up.
