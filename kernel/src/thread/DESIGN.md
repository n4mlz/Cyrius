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
- Synchronous exits (e.g., Linux `_exit`) reuse the same scheduling path via `terminate_current`, which saves context, marks the thread `Terminated`, detaches it from the owning process, and immediately switches to the next runnable thread.
- Shutdown stops the timer and re-disables interrupts. Multiprocessor support and per-CPU schedulers remain future work.

## Thread Model
- `ThreadControl` encapsulates `ThreadId`, name, owning `ProcessId`, CPU context, an address-space handle, optional kernel stack, and scheduling state (`Ready`, `Running`, `Idle`, `Terminated`).
- Each `ThreadControl` captures the owning process's ABI at creation time; the scheduler uses this snapshot to update the syscall dispatcher on context switches without touching the process table.
- Kernel threads receive dedicated stacks allocated via `KernelStack`; the bootstrap thread represents the boot CPU and reuses its existing stack.
- User threads layer a lazily allocated `UserStack` (via `ArchThread::UserStack`) on top of the kernel stack so ring transitions land on a thread-private stack while user-mode execution stays in the lower half of the address space.
- User threads can also be seeded with a pre-built user stack pointer (used by the Linux ELF loader) via `spawn_user_thread_with_stack`; this bypasses the default top-of-stack calculation and honours the loader’s prepared layout.
- Context restoration calls `ArchThread::update_privilege_stack` when the next thread is user-mode, keeping `TSS.rsp0` in sync with the scheduled kernel stack.
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
