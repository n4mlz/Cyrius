# x86_64 Memory Design Notes

## Role and Scope
- Provide x86-64 specific memory management helpers layered under the generic memory subsystem.
- Discover boot-time heap regions (`locate_kernel_heap`) based on the bootloader memory map and implement page table mechanics via `paging::X86PageTable`.

## Kernel Heap Discovery
- Scans all `Usable` memory regions from `BootInfo`, aligning them to 4 KiB boundaries.
- Chooses the largest aligned range and translates it into the higher-half using the bootloader-supplied `physical_memory_offset`.
- Returns the range as `AddrRange<VirtAddr>`; upstream code (heap allocator) assumes this region is identity-mapped and exclusively owned by the heap.

## Page Table Implementation
- `X86PageTable` implements `PageTableOps` with an injected `PhysMapper`, ensuring temporary mappings honour the active virtual memory layout.
- Currently supports 4-level paging/4 KiB pages; the design includes hooks for LA57 (5-level) detection and extension.
- Permission updates propagate writable/user bits through intermediate tables, matching x86-64's AND-semantics for access checks.
- TLB invalidation is conservative: leaf changes flush the affected page, while intermediate updates flush the entire TLB to avoid stale permission caches.

## Safety Contracts
- Constructors are `unsafe`: callers must ensure exclusive ownership of the root frame and provide a mapper that yields non-aliased access to page tables.
- `is_table_empty` and related helpers assume the `PhysMapper` remains valid for the duration of the inspection.

## Testing Strategy
- Kernel tests allocate dummy frames via a mock `FrameAllocator` and validate map/unmap/translate flows, error handling, and permission propagation.
- Tests also exercise TLB-related permission updates by observing flag changes through the mapper.

## Future Work
- Implement LA57 detection and huge page support, including propagation of 1 GiB/2 MiB mappings.
- Hook into a real physical frame allocator to recycle empty intermediate tables.
- Surface copy-on-write and user-space mappings atop this implementation once userland support is introduced.
