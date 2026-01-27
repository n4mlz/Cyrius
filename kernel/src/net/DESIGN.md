# Network Stack Design Notes

## Scope
- Provide a smoltcp-backed network stack that binds to `device::net::NetworkDevice`.
- Expose address types using `no_std_net` so higher layers can use std-like networking types.

## smoltcp Integration
- `SmoltcpDevice` adapts a `NetworkDevice` into the `smoltcp::phy::Device` trait using heap-backed RX/TX buffers sized from the device MTU.
- `SmoltcpStack` owns the smoltcp `Interface` + `SocketSet` and must be polled explicitly; no interrupt-driven wakeups are wired yet.
- The time source for smoltcp is derived from `SYSTEM_TIMER.observed_ticks`; the current implementation treats ticks as milliseconds and expects a monotonic counter.
- The current build enables IPv4 only; IPv6 CIDRs are skipped until `proto-ipv6` is enabled.

## no_std_net Boundary
- `NetCidr` and public re-exports (e.g. `IpAddr`, `SocketAddr`) are defined in `net::mod` to keep smoltcp types out of higher layers.
- Conversions into smoltcp wire types are handled inside the smoltcp adapter module.

## Future Work
- Add socket wrappers that map smoltcp handles to `no_std_net`-style APIs.
- Replace the polling-only scheduler integration with interrupt-driven notification once device IRQ handling is wired into the network loop.
