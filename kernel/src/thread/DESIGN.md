# Thread Subsystem Design Notes

## Role and Scope
- Provide kernel-resident scheduling primitives for cooperative management of kernel threads.
- Own the global `SCHEDULER` instance, which orchestrates timer-driven context switches across CPUs (currently a single core).
- Expose APIs to bootstrap the kernel, spawn kernel threads, and integrate with timer interrupts.

## Scheduler Architecture
- `Scheduler` wraps `SchedulerInner` behind a `SpinLock`, with additional `AtomicBool` flags for `started` state tracking.
- `init` creates the kernel bootstrap thread (`ThreadControl::bootstrap`) and an idle thread, and registers them with the process subsystem using PID0.
- `start` installs `SchedulerDispatch` on the system timer and enables interrupts through the architecture layer; repeated invocations return `AlreadyStarted`.
- Timer ticks call `on_timer_tick`, which saves the current thread context, requeues non-idle threads, selects the next runnable thread, activates its address space, and restores CPU context.
- Shutdown stops the timer and re-disables interrupts. Multiprocessor support and per-CPU schedulers remain future work.

## Thread Model
- `ThreadControl` encapsulates `ThreadId`, name, owning `ProcessId`, CPU context, an address-space handle, optional kernel stack, and scheduling state (`Ready`, `Running`, `Idle`).
- Kernel threads receive dedicated stacks allocated via `KernelStack`; the bootstrap thread represents the boot CPU and reuses its existing stack.
- Address spaces are reference-counted handles cloned from the owning process; the scheduler switches CR3 via `ArchThread::activate_address_space` using these handles.
- Thread creation uses `ArchThread::bootstrap_kernel_context` to seed an architecture-specific context that returns into Rust when first scheduled.

## Interaction with Other Subsystems
- Requires the process subsystem to be initialised first; `Scheduler::init` calls `PROCESS_TABLE.init_kernel()` and records the kernel PID.
- Thread registration/deregistration is delegated to `PROCESS_TABLE.attach_thread` / `detach_thread` to keep per-process thread lists in sync.
- `Scheduler::init` captures the kernel process's address space once and shares it with bootstrap/idle threads; additional kernel threads acquire the same handle through `ProcessTable::address_space`.
- Depends on the architecture abstraction to save/restore CPU context and manipulate interrupt state, keeping the scheduler generic over CPU implementations.
- Timer integration occurs through `SYSTEM_TIMER.install_handler`, making the scheduler the consumer of periodic ticks.

## Error Handling and Concurrency
- Dedicated error enums (`SchedulerError`, `SpawnError`) surface precondition failures such as missing initialisation, timer failures, or alloc errors.
- Internal data is protected with a single spin lock; the design assumes short critical sections and that interrupts stay masked while holding the lock. Per-CPU or lock-free queues are deferred until concurrency requirements increase.
- Thread IDs use monotonically increasing `u64`. Overflow triggers a panic by design to signal unexpected churn.

## Future Directions
- Extend to support blocking primitives (sleep queues, I/O wait) and richer thread states beyond idle/ready/running.
- Introduce per-CPU schedulers and load balancing once Symmetric Multi-Processing is implemented.
- Attach scheduling policies (priorities, time slices) configurable per process/container.
- Track and reclaim thread kernel stacks when threads exit, including integration with process shutdown semantics.
- Add instrumentation hooks for tracing and profiling context switches across a distributed cluster.
