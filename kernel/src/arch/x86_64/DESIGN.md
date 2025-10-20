# x86_64 Architecture Design Notes

## Role and Scope
- Concrete implementation of the architecture trait bundle exposed via `Arch`.
- Bridges the generic kernel subsystems to x86-64-specific hardware primitives (APIC, GDT/IDT, CR3, port I/O).
- Organised into focused modules: `bus` (port I/O), `interrupt` (local APIC + timer), `mem` (heap discovery and paging), `thread` (context/cr3 handling), `trap` (descriptor tables and hand-written stubs).

## Boot-Time Responsibilities
- Instantiate a lazily-initialised global `Ns16550` UART on the standard COM1 port, backing the early console.
- Install trap infrastructure by loading GDT/IDT and wiring naked assembly stubs that bridge into the generic trap dispatcher.
- Locate the kernel heap by scanning the bootloader memory map for the largest aligned usable region, then translating it via the physical memory offset.

## Interrupt Path
- `interrupt::LOCAL_APIC` initialises the LAPIC MMIO window, masks legacy PICs, and programmes timer state.
- Timer events are surfaced through `LocalApicTimer`, implementing the generic `TimerDriver` contract; the scheduler obtains the vector via `ArchInterrupt::timer_vector()`.
- Interrupt enable/disable operations defer to x86_64 instructions (`sti`/`cli`), and end-of-interrupt writes to the LAPIC EOI register.

## Thread and Address Space Management
- `thread::Context` captures general-purpose registers and segment state directly from the trap frame, enabling round-tripping between trap handler and scheduler.
- Kernel threads are bootstrapped by aligning stack tops, seeding RIP, and copying the current CS/SS selectors; this keeps threads executing in ring 0.
- `thread::AddressSpace` wraps CR3 and its flags; activation writes CR3, expecting callers to guard with interrupt masking.

## Memory Management
- `mem::paging::X86PageTable` implements the generic `PageTableOps` using an injected `PhysMapper` to safely touch page table pages.
- Supports 4K pages today, with code structured to extend toward 5-level paging and huge pages; permission propagation updates intermediate tables to satisfy x86-64 semantics.
- TLB invalidation conservatively flushes affected entries (or the full TLB) whenever mappings or intermediate permissions change.

## Trap Handling
- Hand-written naked stubs in `trap::stubs` preserve register state, synthesise error codes, and call back into `crate::trap::dispatch` with vector metadata.
- `trap::gdt` builds a TSS with dedicated IST stacks for NMI, double-fault, and machine-check handling, ensuring resilience against stack corruption.
- `trap::idt` registers exception vectors and the LAPIC timer vector, assigning IST stacks where needed for fault tolerance.

## Future Work
- Detect and enable 5-level paging (LA57) when available, including CR4/CPUID probing.
- Support x2APIC mode and calibrate the LAPIC timer to wall-clock frequencies.
- Integrate with multi-core startup sequences (AP bring-up, per-CPU GDT/IDT/TSS) once SMP is introduced.
