use alloc::sync::Arc;

use crate::device::block::{BlockDevice, SharedBlockDevice};
use crate::device::Device;

use super::{Directory, VfsError, fat32::FatFileSystem};

pub trait FileSystemProbe<D: BlockDevice + Device + Send> {
    fn probe(&self, device: SharedBlockDevice<D>) -> Result<Arc<dyn Directory>, VfsError>;
}

pub struct Fat32Probe;

impl<D: BlockDevice + Device + Send + 'static> FileSystemProbe<D> for Fat32Probe {
    fn probe(&self, device: SharedBlockDevice<D>) -> Result<Arc<dyn Directory>, VfsError> {
        let fs = FatFileSystem::new(device)?;
        Ok(fs.root_dir())
    }
}
