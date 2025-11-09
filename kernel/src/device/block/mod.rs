use crate::device::Device;

/// Common contract for byte-addressable block devices.
///
/// Implementations expose synchronous read/write/flush primitives so higher layers (e.g. VFS,
/// paging) can rely on deterministic completion before issuing the next request. The trait keeps
/// the surface minimal on purpose; asynchronous dispatch and request batching will be layered on
/// later via wrapper types.
pub trait BlockDevice: Device {
    type Error: core::fmt::Debug;

    /// Logical block size in bytes.
    fn block_size(&self) -> u32;

    /// Number of addressable blocks (LBA capacity).
    fn num_blocks(&self) -> u64;

    /// Whether the device rejects write operations.
    fn is_read_only(&self) -> bool {
        false
    }

    /// Read blocks starting at `lba` (Logical Block Address) into `buffer`.
    ///
    /// Callers must provide a buffer whose length is a multiple of [`Self::block_size`].
    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error>;

    /// Write blocks starting at `lba` from `buffer`.
    fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error>;

    /// Flush volatile caches to persistent media.
    fn flush(&mut self) -> Result<(), Self::Error>;
}
