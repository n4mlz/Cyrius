# Block Device Layer Design Notes

## Role and Scope
- Provide the `BlockDevice` trait so higher layers depend on capability-based contracts instead of concrete drivers.
- Host the initial `virtio-blk` driver while keeping the surface general enough for future SATA/NVMe backends or mock implementations.
- Offer synchronous request primitives first; async/multi-queue paths will be layered on later once the scheduler primitives mature.

## Trait Surface
- `BlockDevice` extends `Device` and currently exposes `block_size`, `read_at`, `write_at`, and `flush`.
- Driver specific error types implement `core::fmt::Display` and are propagated directly to callers.
- `BlockDeviceId` tags instances with the source ID discovered by the bus layer (e.g. VirtIO device id).

## VirtIO-blk Overview
- Targets the VirtIO 1.1 specification using the split virtqueue layout (descriptor table, available ring, used ring) and modern feature negotiation (`VIRTIO_F_VERSION_1`).
- Negotiates `VIRTIO_F_VERSION_1` unconditionally, enables the write-back cache bit when offered, and advertises flush support only if `VIRTIO_BLK_F_FLUSH` is present.
- Reads capacity (512-byte sectors) and block size (guarded by `VIRTIO_BLK_F_BLK_SIZE`) from the device configuration space via the mmio helper.
- Legacy transport quirks remain out of scope; the driver assumes a modern device exposed through VirtIO-MMIO for now.

## Transport and Discovery
- Initial bring-up assumes a VirtIO-MMIO device mapped by the bootloader (address + IRQ via device tree or static config). PCI enumeration remains future work once the bus layer is ready.
- The bus layer must expose a typed accessor for the VirtIO common/config/notification/isr regions; `device::bus` will grow a thin wrapper so the block driver can obtain register handles without duplicating unsafe code.

## DMA and Memory Requirements
- Queue structures (descriptor table, avail, used) are backed by a `DmaRegion` allocated through `device::virtio::dma::DmaAllocator`. The queue depth is currently clamped to eight entries (or the device maximum) to keep the region small and ensure descriptor chaining for header/data/status fits.
- Synchronous I/O paths stage data through per-request DMA buffers. Reads copy out of the bounce buffer after completion; writes copy caller data into the DMA buffer before submitting the request. This avoids assumptions about physical contiguity of kernel stack/heap allocations.
- Allocations rely on contiguous 4 KiB frames. Packed queues and scatter/gather fallbacks are future work if large contiguous regions become scarce.

## Driver/Interface Contracts
- `VirtioBlockDevice` implements `BlockDevice`, retains negotiated feature bits, and exposes helper methods (`block_size`, `capacity_sectors`) for higher layers.
- Requests are issued synchronously, polling the used index until completion, and the queue lock serialises access so callers can hold only `&self`.
- Flush requests are only accepted when `VIRTIO_BLK_F_FLUSH` was negotiated; otherwise `flush()` returns `FlushUnsupported`.
- Error cases surface as `VirtioBlockError`, covering MMIO failures, DMA allocation issues, buffer alignment mistakes, and device-reported status codes.

## Testing and Instrumentation
- Unit tests validate virtqueue initialisation, descriptor chaining, and status flag handling in a host-only environment using fake MMIO windows.
- Integration tests boot QEMU with `-device virtio-blk-device,drive=...` and verify that a known sector reads back the expected signature, logging via the UART console for automated checks.

## Known Open Questions
- Multi-queue scaling (per-CPU virtqueues) will require a queue allocator that can hand out distinct rings and DmaRegions per CPU.
- Descriptor recycling currently depends on single outstanding requests; layered async support needs a free-list implementation.
- Error policy for non-zero status codes is still coarse (returns raw status); refining retry/backoff strategies is future work.

This document will evolve alongside the driver implementation; revisit after each milestone to keep contracts and assumptions accurate.
