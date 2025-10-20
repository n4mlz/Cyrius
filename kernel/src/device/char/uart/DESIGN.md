# UART Submodule Design Notes

## Role and Scope
- Provide UART-specific capabilities atop generic character devices, supporting polling-based serial output during early boot.
- Currently ships with an `Ns16550` driver parameterised over a register bus abstraction.

## Abstractions
- `Uart` trait extends `CharDevice` with minimal control operations: initialise hardware, check TX/RX readiness.
- Drivers are expected to remain `no_std` compliant and avoid allocations, making them safe for early boot execution.

## Ns16550 Driver
- Generic over both register width (`RegSizeBound`) and bus implementation (`RegBus`), enabling reuse for PIO and MMIO mappings.
- Implements polled read/write loops with simple spin waiting; callers may layer interrupts or FIFOs later.
- Exposes low-level register operations for integration/testing while hiding hardware-specific magic numbers inside the driver.

## Future Work
- Introduce interrupt-driven or DMA-capable UART variants once the interrupt subsystem matures.
- Provide configuration hooks for baud rate calculation derived from clock sources and divisor latches.
- Add runtime detection to choose between PIO and MMIO transports depending on firmware configuration.
