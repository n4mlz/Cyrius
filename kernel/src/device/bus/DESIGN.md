# Bus Abstraction Design Notes

## Role and Scope
- Provide reusable traits for devices that expose register-style semantics over various hardware interconnects (PIO, MMIO, PCI BARs, etc.).
- Offer common numeric bounds (`RegSizeBound`) to ensure register accesses are well-typed and trivially convertible between host integer sizes.

## RegBus Trait
- Encapsulates byte/word register access with typed offsets and explicit error reporting.
- Abstracts over transport differences so higher-level drivers (e.g. UARTs) do not care whether registers are reached via port I/O or memory-mapped mechanisms.

## Error Handling
- `RegBus::Error` must implement `Display` and `Debug`, enabling propagation into higher layers and logging without formatting hurdles.
- Drivers should convert raw transport failures into richer error types (e.g. `StreamError::Transport`).

## Future Work
- Add helper implementations for common buses (e.g. memory-mapped register windows, PCI config space) and fall back to the same trait.
- Explore batched read/write APIs for performance-sensitive drivers once needed.
