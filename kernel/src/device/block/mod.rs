use alloc::sync::Arc;

use crate::device::Device;
use crate::util::spinlock::SpinLock;

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

pub trait BlockDeviceProvider {
    type Device: BlockDevice + Device;

    fn probe(&self) -> usize;
    fn with_devices<R>(&self, f: impl FnOnce(&[Arc<SpinLock<Self::Device>>]) -> R) -> R;
}

#[derive(Clone)]
pub struct SharedBlockDevice<T> {
    inner: Arc<SpinLock<T>>,
    name: Arc<str>,
    device_type: crate::device::DeviceType,
}

impl<T> SharedBlockDevice<T> {
    pub fn from_arc(inner: Arc<SpinLock<T>>) -> Self
    where
        T: Device,
    {
        let guard = inner.lock();
        let name: Arc<str> = Arc::from(guard.name());
        let device_type = guard.device_type();
        drop(guard);
        Self {
            inner,
            name,
            device_type,
        }
    }

    pub fn inner(&self) -> Arc<SpinLock<T>> {
        self.inner.clone()
    }

    pub fn label(&self) -> &str {
        &self.name
    }
}

impl<T: Device> Device for SharedBlockDevice<T> {
    fn name(&self) -> &str {
        &self.name
    }

    fn device_type(&self) -> crate::device::DeviceType {
        self.device_type
    }
}

impl<T: BlockDevice> BlockDevice for SharedBlockDevice<T> {
    type Error = T::Error;

    fn block_size(&self) -> u32 {
        self.inner.lock().block_size()
    }

    fn num_blocks(&self) -> u64 {
        self.inner.lock().num_blocks()
    }

    fn is_read_only(&self) -> bool {
        self.inner.lock().is_read_only()
    }

    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.lock().read_blocks(lba, buffer)
    }

    fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        self.inner.lock().write_blocks(lba, buffer)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.lock().flush()
    }
}
