# Interrupt Subsystem Design Notes

## Role and Scope
- Bridge architecture-provided interrupt facilities with higher-level kernel services.
- Manage global handler registration, trap routing, and the system timer facade shared by the scheduler and other subsystems.

## Initialisation Flow
- `InterruptController::init` ensures traps are initialised, delegates hardware setup to `ArchInterrupt::init_interrupts`, and registers itself as the global trap handler.
- Guards against double-initialisation via atomic state and returns detailed `InterruptInitError` variants from the architecture layer.

## Handler Dispatch
- Maintains a fixed-size table (`handlers[256]`) protected by a `SpinLock`; vector 0–31 remain reserved for exceptions.
- Exceptions and NMIs fall back to the default `TrapLogger`, while external interrupts invoke registered `InterruptServiceRoutine`s and automatically issue end-of-interrupt acknowledgements.
- Vectors `0x60..0x6F` are dedicated to devices. Drivers call `allocate_vector`/`release_vector` instead of hard-coding IDs, letting the controller enforce exclusivity before the architecture-specific entry point (IDT) hands control to the driver handler.

## Timer Integration
- `SystemTimer` wraps the architecture timer driver, ensuring a dispatch handler is registered before programming hardware.
- Supports observed tick counting, delegate chaining, and safe start/stop operations guarded by `InterruptController::ensure_initialised`.
- Delegates must be `Sync` and are invoked after bookkeeping, enabling the scheduler to attach itself without replacing core logic.

## Concurrency Guarantees
- All public APIs are thread-safe via atomics and spin locks under the assumption that calls occur with interrupts masked or for very short critical sections.
- Vector registration fails fast if a handler already exists, preventing accidental overwrites.

## Future Work
- Add support for nested interrupt prioritisation and vector allocation policies.
- Track per-CPU interrupt state when SMP arrives, including per-core handler tables.
- Extend the new MSI-X plumbing with richer policies (vector pinning, per-CPU affinity) and generalise the interface so non-PCI transports can surface equivalent message-signalled mechanisms.
