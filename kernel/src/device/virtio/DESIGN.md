# VirtIO Device Layer Notes

## Scope
- Host transport-neutral logic for VirtIO devices (PCI today, MMIO/others later).
- Provide safe wrappers for common configuration structures (feature negotiation, queue lifecycle, notify/isr registers).
- Keep descriptor-ring orchestration (`queue.rs`) independent from the concrete transport so virtio-blk/net/etc. can reuse it.

## PCI Transport (`pci.rs`)
- Enumerates the PCI bus for `Vendor 0x1AF4` devices and filters by virtio block class (`Device ID 0x1042`, class `0x01/0x80`).
- Parses vendor capabilities via the standard `virtio_pci_cap` header to locate the Common/Notify/ISR/Device configuration windows.
- Exposes `VirtioPciTransport` which implements the shared `Transport` trait, handling queue selection, feature registers, and doorbell writes.
- BAR addresses are translated through the global `PhysMapper`, allowing the driver to interact with MMIO registers without duplicating mapping logic per transport.

## Queue Abstraction (`queue.rs`)
- `VirtQueueLayout` encapsulates descriptor, available, and used rings that live inside a contiguous DMA region supplied by `mem::dma`.
- Provides typed accessors for descriptor flags (`NEXT`, `WRITE`, `INDIRECT`) and enforces wrap-around arithmetic on the avail/used indices.
- Queue notification entry points (`QueueNotifier`) delegate to the active transport, keeping IRQ/polling policies outside of queue bookkeeping.

## DMA Interaction
- Each virtqueue is backed by a `DmaRegion` allocated via the shared `DmaRegionProvider`, guaranteeing physical contiguity and cache-line alignment.
- The provider returns both physical and virtual views so queue initialisation can zero buffers and program physical addresses without extra helpers.

## VirtIO Block Driver (`block.rs`)
- Implements the `BlockDevice` trait on top of `Transport`, negotiating only the features currently supported (read-only flag, flush, block-size reporting) and rejecting devices with incompatible block sizes.
- Uses a single virtqueue and busy-wait completion path for now; each request builds a descriptor chain of `{header, data, status}` buffers allocated from the DMA provider to satisfy contiguous DMA requirements.
- Discovery (`probe_pci_devices`) scans the PCI transport helper, instantiates `VirtioBlkDevice` objects with human-readable names, and logs failures without panicking so other devices can continue initialising.
- Unit tests rely on a mock transport plus a test-only completion hook that simulates device acknowledgements by directly mutating the used ring, enabling deterministic verification of descriptor layout and data copying without QEMU.

## Testing Strategy
- Unit tests cover descriptor layout calculations and DMA region accounting.
- Integration tests (QEMU) will later validate that virtio-blk negotiation succeeds and that read requests complete.
