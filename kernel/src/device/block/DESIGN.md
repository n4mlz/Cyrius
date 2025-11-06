# Block Device Layer Design Notes

## Role and Scope
- Provide the traits and supporting types required to interact with block-oriented storage devices in a transport-agnostic manner.
- Host the initial `virtio-blk` driver, while keeping the surface general enough for future SATA/NVMe backends or mock implementations.
- Offer synchronous request primitives first; async/multi-queue paths will be layered on later once the scheduler primitives mature.

## VirtIO-blk Overview
- Target the VirtIO 1.1 specification, using the split virtqueue layout (descriptor table, available ring, used ring) and modern feature negotiation (`VIRTIO_F_VERSION_1`).
- Treat feature flags such as `VIRTIO_BLK_F_SIZE_MAX` and `VIRTIO_BLK_F_SEG_MAX` as advisory; enable the writeback cache (`VIRTIO_BLK_F_WCE`) by default and surface explicit flush support.
- Device configuration registers to surface: capacity (in 512-byte sectors), block size (if `VIRTIO_BLK_F_BLK_SIZE`), topology hints, and status.
- Legacy (0.9) transport quirks are out of scope; QEMU will be configured with a modern device exposing the common configuration structure via PCI or MMIO.

## Transport and Discovery
- Initial bring-up assumes a VirtIO-MMIO device mapped by the bootloader (address + IRQ via device tree or static config). PCI enumeration remains future work once the bus layer is ready.
- The bus layer must expose a typed accessor for the VirtIO common/config/notification/isr regions; `device::bus` will grow a thin wrapper so the block driver can obtain register handles without duplicating unsafe code.

## DMA and Memory Requirements
- Queue structures (descriptor table, avail, used) must live in contiguous, DMA-coherent physical memory. They can share a single `PageSize::SIZE_4K` region aligned to the queue size; additional queues allocate independent regions.
- Request payload buffers require guest-physical addresses; the driver will request frames via `mem::manager::frame_allocator()` and map them into the owning address space with the appropriate permissions.
- If contiguous allocations fail, the fallback is to allocate per-page and aggregate scatter/gather segments; packed queues and IOMMU bounce buffers are future enhancements noted in this document.

## Driver/Interface Contracts
- Introduce a `BlockDevice` trait exposing `read_at`, `write_at`, and `flush` operations with sector-level granularity. Error types will carry transport-specific context while implementing `core::fmt::Display`.
- `virtio-blk` will implement this trait and register itself with the device registry once discovery succeeds. `BlockDeviceId` will encapsulate the VirtIO device ID for matching.
- Completions will initially be polled by the driver; interrupt-driven paths require the interrupt subsystem to surface a shared handler registration API (tracked separately).

## Testing and Instrumentation
- Unit tests validate virtqueue initialisation, descriptor chaining, and status flag handling in a host-only environment using fake MMIO windows.
- Integration tests boot QEMU with `-device virtio-blk-device,drive=...` and verify that a known sector reads back the expected signature, logging via the UART console for automated checks.

## Known Open Questions
- How to expose multi-queue scaling (per-CPU virtqueues) once SMP lands; requires revisiting the queue allocator to avoid contention.
- Precise placement of the VirtIO transport helpers (shared with future net driver) so the block implementation reuses code rather than re-creating device negotiation.
- Error policy for flush failures when the backend emulates volatile caches; currently documented as fatal until journaling semantics are designed.

This document will evolve alongside the driver implementation; revisit after each milestone to keep contracts and assumptions accurate.
