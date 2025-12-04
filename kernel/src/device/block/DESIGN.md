# Block Device Layer Design Notes

## Goals
- Offer a single synchronous trait (`BlockDevice`) that captures the minimal contract storage
  drivers must satisfy: fixed block size, total capacity, optional read-only flag, and read/write/
  flush operations.
- Keep the trait transport-agnostic so VirtIO, NVMe, SCSI, or mock devices can implement it without
  leaking protocol-specific details to higher layers.
- Avoid prescribing buffering or scheduling policies; those belong to future layers such as the
  I/O scheduler or VFS cache.

## Trait Expectations
- `read_blocks`/`write_blocks` transfer whole multiples of the reported block size. Callers must
  enforce alignment before invoking the methods; drivers validate this and return descriptive
  errors when constraints are violated.
- `flush` is synchronous and only required to succeed if the hardware advertises explicit flush
  support. Drivers are allowed to return `Error::Unsupported` when the device lacks the feature.
- `is_read_only` enables higher layers to short-circuit write attempts without probing error paths.
- `SharedBlockDevice` wraps an `Arc<SpinLock<T>>` to share a single driver instance across
  subsystems (e.g. VFS) without moving it out of the device registry.

## Future Work
- Introduce asynchronous submission helpers (e.g. futures/channel based) built on top of the
  synchronous primitive to overlap I/O when the scheduler grows more sophisticated.
- Add capability descriptors (max transfer size, optimal alignment) so filesystems can optimise
  request batching.
- Integrate with a device registry that exposes discovered block devices to the VFS layer.
