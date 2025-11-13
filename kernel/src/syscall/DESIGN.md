# Syscall Layer Design Notes

## Scope
- Provide a single entry point for all syscall traps (legacy `int 0x80` as well as the fast-path `SYSCALL` MSR) and route them to ABI-specific tables.
- Expose `AbiFlavor`/`SyscallPolicy` so the process/thread subsystems can describe how each container should be treated.
- Supply a thin policy mechanism that mimics seccomp for the Linux Box demo without constraining the long-term design.

## Dispatcher
- `syscall::init()` registers a dedicated interrupt handler with the generic interrupt controller using `ArchInterrupt::syscall_vector()` and, in parallel, asks the architecture layer to arm the `SYSCALL` MSRs so either entry path funnels into the same dispatcher. It must run after interrupts are initialised.
- `ThreadControl::apply_syscall_profile()` calls `syscall::activate_thread`, binding the currently scheduled thread to a concrete syscall table plus policy metadata. The scheduler refreshes that binding on every context switch.
- `SyscallDispatcher` stores the active binding behind a `SpinLock` and, when invoked, builds a `SyscallContext` around the current trap frame, forwarding the call to the bound table.
- Errors are reported via `SyscallError` and mapped to simple exit codes; unsupported or denied syscalls forcibly terminate the offending thread so the shell can recover.

## Tables
- `SyscallTable` is a trait implemented by the Host and Linux tables. Dispatch returns `SyscallOutcome`, allowing a table to request termination after handling (e.g., `_exit`).
- The Host table is a stub for now and always returns `Unsupported`, while `LinuxSyscallTable` implements `write`, `getpid`, and `_exit`.
- Linux syscall decoding currently matches the x86-64 numbering (`write=1`, `getpid=39`, `exit=60`). Policy validation is performed before any handler executes so the denial path cannot leak partial state.
- Architecture-specific register shuffling lives behind `ArchSyscall`; the generic dispatcher never references concrete register names and therefore remains portable once other architectures implement the trait.

## Policies
- `SyscallPolicy::Minimal` permits only `write`/`exit`, while `Full` allows every implemented Linux syscall. The enum exposes `as_str()` for logging so CLI output (`policy=full`) stays consistent with the docs.
- Policy choices live on the `Process` object and are copied into `ThreadControl` as threads are spawned. Dynamically switching policy is as simple as updating the process entry before the next context switch.

## Error Handling / Exit
- `SyscallDispatcher` converts fatal/unsupported/denied calls into calls to `SCHEDULER.terminate_current`, ensuring the kernel never returns to user mode with an inconsistent frame.
- Cleanup of kernel stacks happens asynchronously via the scheduler's zombie list, so syscall handlers can request termination without worrying about which stack they are currently executing on.

## Future Work
- Tighten the `SYSCALL` path with per-CPU state (e.g., `swapgs`-backed TLS) and consider returning via `sysret` once the scheduling model dictates.
- Expand the Linux table with the minimum set required by the demo binaries (e.g., `rt_sigreturn`) and plumb proper errno semantics instead of hard-coded exit codes.
- Allow host ABI implementations to register their own tables so the kernel can surface management syscalls without going through the Linux compatibility layer.
