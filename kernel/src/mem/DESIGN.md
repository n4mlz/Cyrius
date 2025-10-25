# Memory Subsystem Design Notes

## Role and Scope
- Provide core abstractions for physical/virtual addressing, kernel heap allocation, and page table interaction.
- Serve as a façade over architecture-specific memory management while exposing architecture-neutral traits and types.
- Current focus is kernel-space management; userland paging policies and distributed memory pooling are future work.

## Addressing Primitives (`addr.rs`)
- Defines the `Addr` trait plus concrete `PhysAddr` and `VirtAddr` wrappers to enforce type safety around address calculations.
- Provides alignment helpers (`align_up`, `is_aligned`, `checked_add`) and conversion helpers (`VirtIntoPtr`) for safe use with raw pointers.
- `AddrRange` captures half-open address intervals with basic validation, used by the heap initialisation path.
- `PageSize`, `Page`, and `MemPerm` model common paging concepts; size constants cover 4K/2M/1G pages, and permissions reflect kernel/user read/write/execute flags.

## Kernel Heap (`allocator.rs`)
- Wraps `linked_list_allocator::Heap` inside a `SpinLock`, exposed through the `LockedHeap` type.
- Initialised exactly once via `init_heap`, which requires a pre-mapped, exclusive virtual address range; attempts to reinitialise return `HeapInitError::AlreadyInitialized`.
- Registered as the global allocator (`#[global_allocator]`) so all `alloc` crate usage routes through it.
- Allocation uses first-fit strategy; failures return null pointers, which upstream callers must handle (currently panics via the global alloc error handler).
- Includes kernel tests that fake an aligned heap region to validate initialisation and the double-initialisation guard.

## Paging Interfaces (`paging.rs`)
- Abstracts frame allocation via the `FrameAllocator` trait, leaving concrete policies to architecture-specific backends.
- `PhysMapper` offers temporary mappings between physical and virtual addresses, enabling page table code to mutate frames without assuming identity mapping.
- `PageTableOps` encapsulates map/unmap/translate/update operations plus root frame retrieval, forming the contract between high-level memory management and architecture-specific paging implementations.
- Error enums (`MapError`, `UnmapError`, `TranslationError`) separate common failure modes such as non-canonical addresses, unsupported huge pages, or frame allocation failure.

## Physical Frame Manager (`frame.rs`, `manager.rs`)
- `BootInfoFrameAllocator` consumes the bootloader-provided memory map, aligns usable regions to 4 KiB and excludes reserved spans (e.g. the kernel heap) before handing out frames.
- Freed frames are recycled lazily; callers interact with the allocator through `mem::manager::frame_allocator()`, which returns a guard implementing `FrameAllocator`.
- `mem::manager::init` initialises both the frame allocator and an offset-based `PhysMapper`; it must run during early boot before any address space manipulation.

## Address Space Handles
- Architecture-specific address spaces are surfaced as reference-counted handles (currently via `arch::x86_64::mem::address_space`). Callers use `with_table` to mutate mappings under a spin lock while borrowing the global frame allocator.
- The scheduler and process layer clone these handles so CR3 switches operate on concrete state instead of raw control-register snapshots.
- Dropping an owned address space releases the root frame back to the allocator, ensuring tests can provision and tear down isolated spaces safely.

## Synchronisation and Safety
- Spin locks protect mutable kernel heap state; callers are expected to keep critical sections minimal and respect no_std constraints (no blocking locks).
- Address manipulation functions assert power-of-two alignment and panic on arithmetic overflow to catch programmer errors early.
- Traits document safety contracts explicitly (e.g. `PhysMapper::phys_to_virt` requires exclusive use of the mapping), guiding implementers.

## Future Directions
- Introduce physical frame allocators backed by actual memory maps and integrate with bootloader-provided descriptors.
- Expand paging support to handle userland address spaces, copy-on-write, and per-process permission setups.
- Add large-page awareness to higher-level code paths, with dynamic selection based on workload characteristics.
- Provide instrumentation/telemetry for memory usage, fragmentation, and cluster-wide resource pooling consistent with the overall OS vision.
