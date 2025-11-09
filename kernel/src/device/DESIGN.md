# Device Layer Design Notes

## Role and Scope
- Provide lightweight abstractions around hardware devices so higher layers can operate on capability traits rather than concrete drivers.
- Categorise devices via `DeviceType` and a common `Device` trait (`name`, `device_type`).
- Houses submodules for register buses and character devices; block/network placeholders highlight expected future expansion.

## Design Principles
- Keep traits minimal and composable so drivers can be reused across architectures (e.g. UARTs over either port I/O or MMIO register buses).
- Prefer trait bounds (`ReadOps`, `WriteOps`) to enforce capability checks at compile time.
- Encourage drivers to surface transport errors via structured enums instead of panicking, leaving policy decisions to callers.

## Block Devices (`device::block`)
- Defines the synchronous `BlockDevice` trait used by storage drivers. Consumers operate on logical block addresses and supply buffers that are multiples of the advertised block size.
- The trait is intentionally narrow (read/write/flush plus metadata) so that VFS/paging code can compose higher-level semantics without being tied to the transport.
- `device::virtio::block` provides the first concrete implementation using the VirtIO PCI transport. Devices are discovered through `probe_pci_devices`, stored in a simple registry guarded by a `SpinLock`, and surfaced to future subsystems via helper callbacks.
- The driver keeps virtqueue plumbing and DMA buffer management self-contained, reusing the generic `QueueMemory` + `DmaRegionProvider` so other transports can follow the same pattern.

## Future Work
- Introduce registry infrastructure to enumerate devices discovered during boot.
- Extend to block devices (storage) and network adapters, aligning with the project goal of container-native workloads.
- Provide mock implementations for unit tests and simulation environments.

## VirtIO Block Baseline
- Targeting VirtIO 1.1 modern PCI devices (`Vendor 0x1AF4`, device IDs `0x1040 + x`) with the block function (`0x1042`).
- Drivers interact with vendor capabilities exposed through the standard `virtio_pci_cap` header; we currently care about:
  - `CommonCfg` (queue lifecycle & feature negotiation)
  - `NotifyCfg` (per-queue doorbells via notify-off multiplier)
  - `IsrCfg` (interrupt status byte)
  - `DeviceCfg` (virtio-blk config exposing capacity, geometry, status)
- Queue shared memory areas are provisioned via a transport-agnostic DMA allocator so descriptor/avail/used regions share a contiguous physical window suitable for device DMA.
- Interrupt/notification surfacing is channelled through a transport trait so future transports (e.g. MMIO, CCW) can integrate without rewriting queue logic.

## Block Device Abstraction Roadmap
- `device::block` module hosts the upcoming `BlockDevice` trait with read/write/flush primitives that are synchronous-by-default for ease of bring-up.
- VirtIO-blk will be the initial concrete driver; the trait is intentionally transport-agnostic so SCSI/NVMe shims can coexist later.
- Capability discovery results will later be registered in a lightweight global table so subsystems (VFS, swap) can request handles without scanning PCI each time.
