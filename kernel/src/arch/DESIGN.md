# Architecture Layer Design Notes

## Role and Scope
- Define architecture-neutral traits (`ArchPlatform`, `ArchDevice`, `ArchTrap`, `ArchMemory`, `ArchThread`, `ArchInterrupt`) that the rest of the kernel depends on for platform services.
- Provide the `Arch` type alias bound to the active architecture implementation at compile time (currently `x86_64`).
- Expose thin wrappers that allow higher-level subsystems (scheduler, interrupts, traps, console) to remain generic and testable.

## Trait Surfaces
- **ArchPlatform**: static metadata (e.g. architecture name) used for logging and capability reporting, plus hooks (`init_cpu_features`) for early CPU configuration before other subsystems start.
- **ArchDevice**: ties into the device layer by exposing a console UART instance used by the global `println!` macros.
- **ArchTrap**: hands back the concrete trap frame type and initialises GDT/IDT state.
- **ArchMemory**: discovers the kernel heap virtual range based on bootloader-provided memory maps.
- **ArchThread**: supplies context save/restore, address-space activation, and kernel-thread bootstrap scaffolding.
- **ArchInterrupt**: bootstraps the interrupt controllers, exposes the architecture timer driver, and installs end-of-interrupt hooks.

## Error Contracts
- Dedicated error enums (`HeapRegionError`, `InterruptInitError`, `TimerError`) encode hardware and firmware preconditions that call sites must handle.
- `TimerTicks` abstracts architecture-specific tick units while hiding register encoding details.

## Extensibility
- Additional architectures implement the trait set alongside an `Arch` alias guarded by `cfg(target_arch = ...)`.
- Shared code is encouraged to remain architecture-agnostic by programming against the traits; concrete modules live under `arch/<target>`.
- Future multi-architecture support will introduce feature detection during early boot, but the trait surfaces are designed to remain stable.
