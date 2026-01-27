use alloc::vec::Vec;

use super::{DirEntry, VfsError};
use crate::util::stream::{ControlError, ControlRequest};

/// Per-open handle that performs I/O and control operations.
pub trait File: Send + Sync {
    fn read(&self, buf: &mut [u8]) -> Result<usize, VfsError>;

    fn write(&self, _data: &[u8]) -> Result<usize, VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn readdir(&self) -> Result<Vec<DirEntry>, VfsError> {
        Err(VfsError::NotDirectory)
    }

    fn ioctl(&self, _request: &ControlRequest<'_>) -> Result<u64, ControlError> {
        Err(ControlError::Unsupported)
    }
}
