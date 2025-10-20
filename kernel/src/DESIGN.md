# Kernel Module Design Notes

## Role and Scope
- Entry point for the kernel crate, housing core subsystems (`arch`, `device`, `interrupt`, `mem`, `process`, `thread`, `trap`, `util`).
- Ensures the crate remains `no_std`, highly modular, and architecture-agnostic wherever possible.

## Subsystem Overview
- **arch**: architecture-specific adapters behind trait-based abstractions.
- **device**: pluggable drivers and bus traits for kernel-managed hardware.
- **interrupt**: vector registration, trap dispatch, and timer orchestration.
- **mem**: address wrappers, heap allocator, and paging interfaces.
- **process/thread**: execution and scheduling primitives built atop architecture contexts.
- **trap**: global trap dispatcher and logging with architecture-specific frames.
- **util**: shared primitives (spin locks, lazy init, stream helpers) leveraged across modules.

## Design Principles
- Keep subsystem boundaries explicit; cross-module dependencies must be routed through trait contracts to simplify future architecture additions.
- Prioritise determinism and clarity over premature optimisation; most components use `SpinLock` for now with clear extension points for finer-grained concurrency.
- Provide kernel tests under `#[cfg(test)]` wherever feasible to validate invariants without full system boot.

## Future Direction
- Introduce userland support by extending memory/process/thread subsystems while maintaining the documented contracts.
- Layer container orchestration primitives atop process/thread abstractions once core kernel services stabilise.
