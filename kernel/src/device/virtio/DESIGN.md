# VirtIO Transport Design Notes

## Role and Scope
- Provide transport-level helpers shared by VirtIO device drivers (block, network, etc.).
- Offer a safe wrapper around the MMIO register map alongside queue layout utilities so higher layers avoid duplicating low-level arithmetic.
- Keep the surface minimal and extensible; features such as PCI transport or packed queues can join later without breaking existing APIs.

## MMIO Wrapper (`mmio.rs`)
- `MmioConfig` captures the guest virtual mapping of the device header. Construction is `unsafe` to reflect the requirement that callers ensure correct MMIO mapping and exclusivity.
- `MmioDevice` validates the magic value and version before exposing typed operations (feature negotiation, queue configuration, status updates, interrupt handling, notifications).
- All register accesses go through range-checked helpers that rely on `read_volatile`/`write_volatile`. The helper emits descriptive errors (`OutOfRange`, `UnexpectedMagic`, etc.) so discovery code can log precise failures.
- Queue address programming accepts a `VirtQueueRegion`, ensuring descriptor/driver/device pointers stay in sync with the allocator that built the underlying memory.

## Queue Layout Helpers (`queue.rs`)
- `VirtQueueLayout` computes descriptor/avail/used offsets for the split-queue format, enforcing power-of-two queue sizes and 4 KiB alignment for the used ring as mandated by the spec.
- `VirtQueueRegion` packages the physical addresses derived from an allocation; `into_virtual` aids in mapping the same buffer into a virtual address space for CPU access.
- Descriptor definitions (`Descriptor`) mirror the on-wire layout and expose flag constants (`F_NEXT`, `F_WRITE`, `F_INDIRECT`) for clarity.

## Extensibility Notes
- PCI transport support will share the same queue abstractions; only the register access code will differ. The module layout keeps `mmio` and `queue` separate to accommodate additional transports.
- Interrupt management currently relies on polling acknowledgement. Once the interrupt subsystem exposes shared handler registration, `MmioDevice::acknowledge_interrupts` can integrate with per-queue callbacks.
- Packed queues and event indices are intentionally omitted for now. Their introduction will likely add new layout helpers rather than widening existing structs.

Keep this document synchronized with driver implementations so transport contracts remain accurate.
