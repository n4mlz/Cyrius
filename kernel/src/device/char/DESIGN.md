# Character Device Design Notes

## Role and Scope
- Define shared interfaces for byte-oriented character devices (UARTs, serial consoles, debug ports).
- Extend the base `Device` trait with streaming operations by inheriting from `ReadOps` and `WriteOps`.

## Trait Structure
- `CharDevice` supplies a single associated `Error` type, unifying read/write error handling for simplicity.
- Implementations are expected to be lightweight wrappers around lower-level transports (PIO, MMIO, virtual consoles).

## Integration
- The `ArchDevice` trait chooses a concrete `CharDevice` implementation for the global console.
- Higher-level facilities (`println!`, logging) rely on the trait to abstract away device-specific flow control.

## Future Work
- Add device capability flags (e.g. blocking vs non-blocking) or termios-like configuration surfaces.
- Provide loopback/mock devices to support kernel tests that exercise logging without touching hardware.
