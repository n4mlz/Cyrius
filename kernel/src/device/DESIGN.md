# Device Layer Design Notes

## Role and Scope
- Provide lightweight abstractions around hardware devices so higher layers can operate on capability traits rather than concrete drivers.
- Categorise devices via `DeviceType` and a common `Device` trait (`name`, `device_type`).
- Houses submodules for register buses, character devices, and block devices. Character devices expose UART implementations; block devices expose VirtIO-backed storage.

## Design Principles
- Keep traits minimal and composable so drivers can be reused across architectures (e.g. UARTs over either port I/O or MMIO register buses).
- Prefer trait bounds (`ReadOps`, `WriteOps`) to enforce capability checks at compile time.
- Encourage drivers to surface transport errors via structured enums instead of panicking, leaving policy decisions to callers.

## Future Work
- Introduce registry infrastructure to enumerate devices discovered during boot.
- Extend to network adapters, aligning with the project goal of container-native workloads.
- Provide mock implementations for unit tests and simulation environments.
- Consolidate VirtIO transport helpers shared by `virtio-blk` and future network drivers to avoid duplicating queue/DMA setup logic.
