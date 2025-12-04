# Process Subsystem Design Notes

## Role and Scope
- Manage the set of threads and minimal metadata associated with each process.
- Currently limited to kernel-space execution; the structure is intentionally skeletal so it can expand once userland support arrives.
- Exposed as a single global instance (`PROCESS_TABLE`), which higher-level orchestration (at present the scheduler) manipulates through its API.

## Entities
### ProcessTable
- Uses `SpinLock<ProcessTableInner>` plus an `AtomicBool` to coordinate initialization and concurrency.
- `init_kernel` creates the PID 0 kernel process exactly once; subsequent calls simply return the existing PID.
- PIDs are `u64`, allocated monotonically; overflow is treated as a logic bug that panics.
- Process lookup is linear today. If the number of processes grows, we plan to swap in a different structure (e.g. `BTreeMap`).

### Process
- Stores `id`, `_name`, `address_space`, `_state`, and a `threads` list.
- `address_space` holds an `ArchThread::AddressSpace` (currently an `Arc` handle) so processes share explicit address-space state.
- `ProcessState` currently exposes only `Active`. Expanded lifecycle states (e.g. `Sleeping`, `Zombie`) are still future work.
- Fields prefixed with `_` are reserved for upcoming functionality, so they remain even if unused today.
- `Process::user` mirrors kernel setup for now, provisioning a PID for user-mode threads while still sharing the kernel address space until proper duplication arrives.

## Initialization and Invariants
- During boot the scheduler init sequence calls `init_kernel`.
- `init_kernel` is idempotent: after the first run it returns PID 0 without side effects.
- `create_kernel_process` adds additional kernel-only worker processes after initialization; userland will eventually share the PID space.
- `kernel_pid` stays `Some` immediately after initialization and is considered an invariant.

## Cooperation with Threads
- The scheduler invokes `attach_thread` / `detach_thread` whenever threads are created or torn down so the mapping between processes and `ThreadId`s stays in sync.
- Duplicate attachment for the same thread is rejected via `ProcessError::DuplicateThread`, catching misuse early.
- `thread_count` is a lightweight helper for statistics and debugging.
- `address_space(pid)` clones the stored handle so scheduling and memory management components can operate on the same CR3 state.
- Process lifetime management (e.g. reclaiming a process when its thread list becomes empty) is intentionally deferred.
- ABI selection for syscall dispatch is stored per-process; on context switch the scheduler looks up the next thread's owning process and programs the syscall dispatcher accordingly.

## Address Space and ABI Considerations
- For now every kernel process shares the same kernel address space.
- `ArchThread::current_address_space()` seeds the stored address space. Future plans include:
  - cloning / isolating address spaces when we spawn userland processes;
  - letting the scheduler reactivate a process-specific address space on context switches.
- User-process creation already allocates a distinct PID and thread list but continues to reference the shared kernel mappings until the paging layer exposes copy-on-write cloning.
- When Linux compatibility arrives, each `Process` will also discriminate between host ABI and Linux ABI execution to drive syscall routing.

## Error Model and Synchronization
- `ProcessError` signals precondition violations and internal consistency issues to callers such as the scheduler.
- Internal synchronization relies on a spin lock, assuming interrupts are masked or the critical section is brief.
- Finer-grained locking (for example per-process locks) is a topic reserved for later scalability work.

## Future Extensions
- Introduce a richer process state machine (`Ready`, `Sleeping`, `Zombie`, etc.) and lifecycle management.
- Manage userland `AddressSpace` duplication, plus ABI selection data for host vs. Linux guests.
- Attach per-process resources such as file descriptor tables, privileges, and cgroup-like metadata.
- Plan for cluster-wide PID uniqueness and the synchronization mechanisms required when the OS spans multiple nodes.
