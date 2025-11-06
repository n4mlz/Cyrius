pub mod virtio;

use crate::device::Device;

pub use virtio::{VirtioBlockDevice, VirtioBlockError};

/// Common abstraction for block-oriented storage backends.
pub trait BlockDevice: Device {
    type Error: core::fmt::Debug;

    /// Return the logical block size in bytes.
    fn block_size(&self) -> usize;

    /// Read blocks starting at `lba` into `buffer`.
    fn read_at(&self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error>;

    /// Write blocks starting at `lba` from `buffer`.
    fn write_at(&self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error>;

    /// Flush any buffered data to persistent media.
    fn flush(&self) -> Result<(), Self::Error>;
}

/// Identifier coupling a block device instance to a discovery source (e.g. VirtIO ID).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockDeviceId(pub u32);
