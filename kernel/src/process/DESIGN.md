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
- Stored as `Arc<Process>` so threads can hold a direct reference to their owning process without touching the global table.
- Stores `id`, `name`, `address_space`, `state`, `threads`, `fs`, `parent`, `exit_code`, `reaped`, `brk`, `abi`, and a `ProcessDomain`.
- `address_space` holds an `ArchThread::AddressSpace` (currently an `Arc` handle) so processes share explicit address-space state.
- `ProcessState` now spans `Created`, `Ready`, `Running`, `Waiting`, `Terminated`; transitions are simple and primarily driven by thread attach/detach and scheduler ticks.
- `ProcessDomain` decides both the ABI and the VFS binding at creation time.
- `brk` tracks the user-mode heap break (base/current), seeded by Linux ELF loading and advanced by the `brk` syscall.
- `parent`/`exit_code`/`reaped` provide minimal wait4 support: fork assigns a parent, exit writes a code, and wait4 marks the child as reaped.
- If a process is created for a container, it retains the container handle and filesystem operations route through the container VFS.

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
- The scheduler reads the ABI directly from the thread's `Process` reference during context switches, avoiding global table locks in interrupt context.

## Address Space and ABI Considerations
- Kernel processes share the same kernel address space.
- `ArchThread::current_address_space()` seeds the stored address space. Future plans include:
  - cloning / isolating address spaces when we spawn userland processes;
  - letting the scheduler reactivate a process-specific address space on context switches.
- User processes allocate a dedicated address space seeded with the kernel mappings; fork clones the user portion by copying pages (no COW yet).
- Linux compatibility is handled via the per-process ABI chosen by `ProcessDomain`.

## Domain Contract (Explicit)
- Container processes always use the container VFS.
- Host processes never access the container VFS.
- Container processes currently require Linux ABI.
- Process domains are immutable after creation.
- HostLinux uses Linux ABI while still bound to the host VFS (used for linux-box tests).

## Temporary Nature
- The `ProcessDomain` split is temporary. Once container functionality is complete, the domain will
  collapse into ABI selection: host ABI implies non-container process, Linux ABI implies container
  process. At that point, `ProcessDomain` will be removed in favor of `Abi`-only selection.

## Error Model and Synchronization
- `ProcessError` signals precondition violations and internal consistency issues to callers such as the scheduler.
- The process table is guarded by a spin lock, while per-process state (`threads`, `cwd`) uses dedicated spin locks inside `Process`.
- Path resolution and process-facing filesystem operations live in the `process::fs` helper module; reusable filesystem utilities live in `fs::ops`.
- Standard file descriptors (0/1/2) are installed from the global tty device via `devfs` nodes and
  `Node::open` when `ProcessFs` is created.
- Locks are expected to be held briefly; interrupt handlers should avoid taking process-table locks.

## Future Extensions
- Expand the `ProcessState` machine to capture blocking semantics (`Sleeping`, `Zombie`) and integrate with wait queues.
- Manage userland `AddressSpace` duplication, plus ABI selection data for host vs. Linux guests.
- Attach per-process resources such as file descriptor tables, privileges, and cgroup-like metadata.
- Plan for cluster-wide PID uniqueness and the synchronization mechanisms required when the OS spans multiple nodes.
