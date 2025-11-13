# x86_64 Trap Layer Design Notes

## Role and Scope
- Initialise and maintain the privileged execution environment required for exception and interrupt handling on x86-64.
- Own the GDT/TSS, IDT, and the hand-written trap stubs that translate hardware events into the architecture-neutral trap dispatcher.

## Descriptor Tables
- `gdt` installs both ring-0 and ring-3 segment descriptors alongside the TSS entry, allocating three IST stacks (NMI, double-fault, machine-check) from a statically mapped buffer.
- `set_privilege_stack` updates `TSS.rsp0` on every context switch so user→kernel transitions enter on the scheduled thread's kernel stack, while a fallback ring-0 stack remains available for bootstrap paths.
- `idt` populates exception vectors with dedicated stubs and assigns IST indices where architectural guidance recommends hardened stacks.
- Vector `0x80` remains present with DPL=3 for legacy `int 0x80` traps, while the MSR-backed `SYSCALL` path (see below) now carries the hot path for Linux guests.
- `syscall::init` registers an interrupt-service routine for vector `0x80` **and** asks the architecture layer to arm the `SYSCALL` MSRs so either entry mechanism hits the same dispatcher.
- `init()` loads both tables during early boot and must run per-CPU prior to enabling interrupts.

## Trap Stubs
- Naked assembly routines in `stubs` save general-purpose registers, normalise error codes, maintain stack alignment for `call`, and end with `iretq`.
- The dedicated `syscall_entry` stub mirrors the IDT stubs but synthesises the hardware frame manually: it snapshots the user stack pointer before swapping to the kernel stack, pushes `SS/RSP/RFLAGS/CS/RIP` in the order `iretq` expects, and then reuses the common prologue/epilogue before returning.
- Each stub invokes `dispatch_trap`, which constructs a `TrapInfo` (vector, origin, description) and hands control to `crate::trap::dispatch`.
- Timer interrupts reuse the same mechanism, so the scheduler observes consistent metadata regardless of source.

## Trap Frame Representation
- `context::TrapFrame` mirrors the pushed register layout, exposing helpers to inspect privilege level transitions (stack pointer/segment).
- Implements `TrapFrame` trait so the generic trap subsystem can log or introspect frames without peeking into architecture details.
- `GeneralRegisters` offers zero-initialisation and mirrors the register order used by the stubs to simplify context save/restore.

## Integration Points
- `ArchTrap::Frame` is aliased to this trap frame, enabling scheduler and process code to downcast without `cfg` checks.
- `thread::Context` derives from a trap frame after interrupts, allowing seamless handoff between interrupt context and scheduled threads.

## Exception Handlers
- `handlers` provides the architecture-specific fast path for #PF/#GP/#DF, decoding hardware error codes and emitting structured diagnostics before panicking.
- The dispatcher in `mod.rs` delegates to these helpers via `ArchTrap::handle_exception`; returning `true` suppresses the generic logging path.
- Page-fault handling records the CR2 fault address and access type bits so future user-mode recovery logic has the required context.

- Incorporate per-CPU IST buffers to support SMP and avoid contention on the global static region.
- Harden stubs against invalid stack scenarios by adding guard pages or double-fault recovery strategies.
