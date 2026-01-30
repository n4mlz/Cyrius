# Network Stack Design Notes

## Scope
- Provide a smoltcp-backed network stack that binds to `device::net::NetworkDevice`.
- Expose address types using `no_std_net` so higher layers can use std-like networking types.
- Offer a minimal TCP API (`TcpListener`, `TcpStream`) suitable for kernel-resident services.

## smoltcp Integration
- `SmoltcpDevice` adapts a `NetworkDevice` into the `smoltcp::phy::Device` trait using heap-backed RX/TX buffers sized from the device MTU.
- `SmoltcpStack` owns the smoltcp `Interface` + `SocketSet` and must be polled explicitly; no interrupt-driven wakeups are wired yet.
- The time source for smoltcp is derived from `SYSTEM_TIMER.observed_ticks`; the current implementation treats ticks as milliseconds and expects a monotonic counter.
- The current build enables IPv4 only; IPv6 CIDRs are skipped until `proto-ipv6` is enabled.
- `smoltcp.rs` also hosts the crate-local conversion helpers that translate between `no_std_net` and smoltcp wire types.

## Runtime and Polling
- `runtime.rs` owns the global `SmoltcpStack` instance behind a `SpinLock<Option<_>>`.
- The runtime is intentionally monomorphic by wrapping devices in a `NetDevice` enum, keeping the smoltcp type stable while still allowing test-only injection.
- Default IPv4 configuration targets QEMU user networking (`10.0.2.15/24` with gateway `10.0.2.2`).
- `net::spawn_background_tasks` creates a dedicated kernel process/thread that continuously polls the runtime once the scheduler is ready.
- TCP socket handles are not removed immediately on close. `runtime` keeps a small “closing” list and reaps handles only after the smoltcp socket reaches `Closed` or `TimeWait` (and has no pending send queue), providing a best-effort drain before teardown.

## TCP Wrapper
- `tcp.rs` maps smoltcp TCP sockets to a std-like blocking interface:
- `TcpListener::bind` creates and listens on a smoltcp socket handle.
- `TcpListener::accept` is built on `try_accept`, which performs a single poll step and enables cooperative testing without threads.
- `TcpStream::{read, write_all}` spin using corresponding `try_*` methods to avoid monopolising the runtime lock.
- Accepting a connection replaces the listener’s socket handle with a fresh listening socket, mirroring std’s “accept returns a stream while the listener keeps listening” contract.

## Socket Files
- `socket.rs` bridges Linux TCP socket syscalls into the VFS by exposing `TcpSocketFile`, a `File`
  implementation with a small state machine (init → bound → listening → stream).
- `socket/bind/listen/accept` operate on the per-FD `TcpSocketFile` instance; accepted streams are
  wrapped in a fresh `TcpSocketFile` so read/write can reuse the existing FD table paths.

## Test Strategy
- TCP integration tests use a test-only virtual wire device pair (`runtime::TestNetworkDevice`) to drive both client and server stacks deterministically inside QEMU.
- The server side uses the public TCP wrapper while the client side drives a raw smoltcp socket, with explicit interleaved polling on both stacks.

## no_std_net Boundary
- `NetCidr` and public re-exports (e.g. `IpAddr`, `SocketAddr`) are defined in `net::mod` to keep smoltcp types out of higher layers.
- Conversions into smoltcp wire types are handled inside the smoltcp adapter module.

## Future Work
- Replace the polling-only scheduler integration with interrupt-driven notification once device IRQ handling is wired into the network loop.
