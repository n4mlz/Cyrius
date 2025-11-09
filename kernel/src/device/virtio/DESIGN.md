# VirtIO Transport Design Notes

## Role and Scope
- Provide transport-level helpers shared by VirtIO device drivers (block, network, etc.).
- Expose a modern PCI transport wrapper alongside common DMA and queue layout utilities so higher layers avoid duplicating low-level arithmetic.
- Keep the surface minimal and extensible; additional transports (e.g. MMIO for non-PCI SoCs) or packed queues can join later without breaking existing APIs.
- Surface common status/feature constants so drivers share a single definition of VirtIO handshakes.

## PCI Transport (`pci.rs`)
- `PciTransport` discovers VirtIO devices by walking the PCI capability list via `device::bus::pci::PciAddress`. It requires the common, notify, ISR, and device-specific capabilities and rejects devices that expose only the legacy interface.
- Each capability is range-checked before mapping; BAR resolution relies on `mem::manager::phys_mapper()` providing an offset mapping for PCI apertures. This implicit dependency is documented in the module docs.
- Notify doorbells are pre-computed per queue using the capability's `notify_off_multiplier`, which allows callers to trigger notifications without touching the common configuration registers during steady-state I/O.
- The transport exposes high-level helpers (`read_device_features`, `configure_queue`, `notify_queue`, `read_config`, etc.) so device drivers never perform raw pointer arithmetic or replicate feature-negotiation sequences.
- Interrupt acknowledgement reads the ISR capability lazily; once the interrupt subsystem exposes shared handler registration the helper can be wired into callbacks instead of polling.

## DMA Helpers (`dma.rs`)
- `DmaAllocator` wraps the global frame allocator to provide contiguous, DMA-coherent regions backed by 4 KiB frames. Allocations return a `DmaRegion` that frees frames on drop.
- `DmaRegion` exposes helpers to access virtual/physical offsets and mutable slices, simplifying queue initialisation and temporary bounce buffers for drivers.
- The helper currently assumes an identity-style physical mapping via `mem::manager::phys_mapper`; this implicit dependency is documented in the module-level docs and is enforced by construction of `DmaRegion`.

## Queue Layout Helpers (`queue.rs`)
- `VirtQueueLayout` computes descriptor/avail/used offsets for the split-queue format, enforcing power-of-two queue sizes and 4 KiB alignment for the used ring as mandated by the spec.
- `VirtQueueRegion` packages the physical addresses derived from an allocation; `into_virtual` aids in mapping the same buffer into a virtual address space for CPU access.
- Descriptor definitions (`Descriptor`) mirror the on-wire layout and expose flag constants (`F_NEXT`, `F_WRITE`, `F_INDIRECT`) for clarity.

## Testing
- Unit tests in `queue.rs` assert that split-queue layout offsets preserve the required alignment invariants.
- Integration coverage is provided indirectly by the virtio-blk tests, which now boot QEMU with `virtio-blk-pci,disable-legacy=on` to exercise the modern PCI transport end-to-end.

## Extensibility Notes
- Packed queues and event indices are intentionally omitted for now. Their introduction will likely add new layout helpers rather than widening existing structs.
- Shared-memory capabilities and advanced PCI features (e.g. MSI-X steering) are detected but unused; once the interrupt subsystem supports MSI routing these hooks can be expanded without changing the driver surface.
- MMIO transport support can be reintroduced in a separate module if required for non-PCI platforms without affecting existing drivers.

Keep this document synchronized with driver implementations so transport contracts remain accurate.
