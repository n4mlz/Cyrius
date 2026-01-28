# Device Layer Design Notes

## Role and Scope
- Provide lightweight abstractions around hardware devices so higher layers can operate on capability traits rather than concrete drivers.
- Categorise devices via `DeviceType` and a common `Device` trait (`name`, `device_type`).
- Houses submodules for register buses, block devices, and network devices so higher layers can bind to capability traits.

## Design Principles
- Keep traits minimal and composable so drivers can be reused across architectures (e.g. UARTs over either port I/O or MMIO register buses).
- Prefer trait bounds (`ReadOps`, `WriteOps`) to enforce capability checks at compile time.
- Encourage drivers to surface transport errors via structured enums instead of panicking, leaving policy decisions to callers.

## Block Devices (`device::block`)
- Defines the synchronous `BlockDevice` trait used by storage drivers. Consumers operate on logical block addresses and supply buffers that are multiples of the advertised block size.
- The trait is intentionally narrow (read/write/flush plus metadata) so that VFS/paging code can compose higher-level semantics without being tied to the transport.
- `BlockDeviceProvider` abstracts discovery and enumeration so boot-time consumers can probe without binding to a specific transport.
- `device::virtio::block` provides the first concrete implementation using the VirtIO PCI transport. Devices are discovered through `device::probe::probe_block_devices`, stored in a simple registry guarded by a `SpinLock`, and surfaced to future subsystems via helper callbacks.
- The driver keeps virtqueue plumbing and DMA buffer management self-contained, reusing the generic `QueueMemory` + `DmaRegionProvider` so other transports can follow the same pattern.
- Modern VirtIO devices expose MSI-X vectors; the driver now programs a per-queue vector via the shared interrupt allocator so completions arrive asynchronously instead of pure polling.

## Network Devices (`device::net`)
- Defines the `NetworkDevice` trait for raw Ethernet frame I/O (MAC/MTU/link state + transmit/receive).
- Mirrors the block provider pattern so network devices can be discovered during boot without binding to a transport.
- The trait remains synchronous for deterministic bring-up; async adapters will be layered later with the TCP/IP stack.
- The smoltcp adapter lives under `net::smoltcp` and consumes `NetworkDevice` implementations.

## Future Work
- Introduce registry infrastructure to enumerate devices discovered during boot.
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
- MSI-X programming rides on the same trait: transports that cannot wire interrupts simply return `Unsupported`, allowing the block layer to fall back to spin-based completion while x86_64 PCI parts opt into the interrupt path automatically.

## Block Device Abstraction Roadmap
- `device::block` module hosts the upcoming `BlockDevice` trait with read/write/flush primitives that are synchronous-by-default for ease of bring-up.
- VirtIO-blk will be the initial concrete driver; the trait is intentionally transport-agnostic so SCSI/NVMe shims can coexist later.
- Capability discovery results will later be registered in a lightweight global table so subsystems (VFS, swap) can request handles without scanning PCI each time.

## Network Device Baseline
- VirtIO-net is the first concrete network driver; it exposes raw Ethernet frames and relies on virtqueue-backed DMA buffers for RX/TX paths.
- Discovery is wired through `device::probe::probe_network_devices`, mirroring the block-device probe flow.
