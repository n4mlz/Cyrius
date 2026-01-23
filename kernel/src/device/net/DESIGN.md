# Network Device Design Notes

## Scope
- Define the minimal trait surface for Ethernet-like devices so higher layers (smoltcp, socket syscalls) can remain transport-agnostic.
- Provide synchronous transmit/receive operations suitable for early bring-up and deterministic testing.

## `NetworkDevice` Trait
- Exposes MAC address, MTU, and link state as lightweight metadata.
- Uses `transmit_frame` / `receive_frame` for raw Ethernet frame I/O to avoid baking protocol choices into the device layer.
- Defaults to `LinkState::Unknown` when a device cannot report link status.

## Provider Pattern
- `NetworkDeviceProvider` mirrors the block device provider so boot-time probing can discover devices without binding to a transport.
- `SharedNetworkDevice` wraps a `SpinLock`-guarded device in an `Arc` so upper layers can clone handles safely.

## Future Work
- Add queueing/async wrappers once the network stack is in place.
- Extend metadata with offload capabilities when smoltcp integration begins.
