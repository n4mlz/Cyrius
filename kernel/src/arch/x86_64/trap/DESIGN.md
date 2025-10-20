# x86_64 Trap Layer Design Notes

## Role and Scope
- Initialise and maintain the privileged execution environment required for exception and interrupt handling on x86-64.
- Own the GDT/TSS, IDT, and the hand-written trap stubs that translate hardware events into the architecture-neutral trap dispatcher.

## Descriptor Tables
- `gdt` builds a kernel-only GDT plus TSS entries, allocating three IST stacks (NMI, double-fault, machine-check) from a statically mapped buffer.
- `idt` populates exception vectors with dedicated stubs and assigns IST indices where architectural guidance recommends hardened stacks.
- `init()` loads both tables during early boot and must run per-CPU prior to enabling interrupts.

## Trap Stubs
- Naked assembly routines in `stubs` save general-purpose registers, normalise error codes, maintain stack alignment for `call`, and end with `iretq`.
- Each stub invokes `dispatch_trap`, which constructs a `TrapInfo` (vector, origin, description) and hands control to `crate::trap::dispatch`.
- Timer interrupts reuse the same mechanism, so the scheduler observes consistent metadata regardless of source.

## Trap Frame Representation
- `context::TrapFrame` mirrors the pushed register layout, exposing helpers to inspect privilege level transitions (stack pointer/segment).
- Implements `TrapFrame` trait so the generic trap subsystem can log or introspect frames without peeking into architecture details.
- `GeneralRegisters` offers zero-initialisation and mirrors the register order used by the stubs to simplify context save/restore.

## Integration Points
- `ArchTrap::Frame` is aliased to this trap frame, enabling scheduler and process code to downcast without `cfg` checks.
- `thread::Context` derives from a trap frame after interrupts, allowing seamless handoff between interrupt context and scheduled threads.

## Future Work
- Add support for user-mode traps once ring transitions are introduced (IST stack allocation, syscall/sysret setup).
- Incorporate per-CPU IST buffers to support SMP and avoid contention on the global static region.
- Harden stubs against invalid stack scenarios by adding guard pages or double-fault recovery strategies.
