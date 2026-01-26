# Utility Module Design Notes

## Role and Scope
- Collect small, architecture-agnostic helpers and synchronisation primitives used across the kernel.
- House formatting helpers (`print!`, `println!`), lazy initialisation (`LazyLock`), and spin locks suitable for `no_std` environments.

## Synchronisation Primitives
- `SpinLock` offers a simple, non-reentrant lock with exponential back-off via `spin_loop`; designed for short critical sections with interrupts masked.
- `LazyLock` combines a spin lock and atomic flag to provide once-only initialisation without relying on `std::sync`.
- Both types are `Send`/`Sync` when their contents allow, ensuring safe use in multi-core contexts once SMP arrives.

## I/O Helpers
- `stream` defines generic read/write traits and a `StreamError` enum to standardise transport-layer errors.
- `ControlOps`/`ControlRequest` live alongside the stream traits to model ioctl-style control paths and user-memory access.
- `Writer` adapts the active `ArchDevice::Console` into `core::fmt::Write`, backing the global `print!`/`println!` macros for logging.

## Conventions
- `cast!` macro delegates to `num_traits::cast` to perform checked numeric conversions, panicking on failure to surface logic errors early.
- Utilities avoid heap allocations and remain `no_std` friendly, making them safe during early boot and interrupt contexts.

## Future Work
- Introduce additional concurrency primitives (mutexes with priority inheritance, wait queues) as scheduling sophistication increases.
- Provide instrumentation hooks (lock contention counters, logging) to trace hot paths in low-level code.
