use alloc::vec::Vec;
use core::any::Any;

use super::{DirEntry, VfsError};
use crate::util::stream::{ControlError, ControlRequest};

/// Per-open handle that performs I/O and control operations.
pub trait File: Send + Sync + Any {
    fn read(&self, buf: &mut [u8]) -> Result<usize, VfsError>;

    fn write(&self, _data: &[u8]) -> Result<usize, VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn readdir(&self) -> Result<Vec<DirEntry>, VfsError> {
        Err(VfsError::NotDirectory)
    }

    fn seek(&self, _offset: i64, _whence: u32) -> Result<u64, VfsError> {
        Err(VfsError::NotFile)
    }

    fn ioctl(&self, _request: &ControlRequest<'_>) -> Result<u64, ControlError> {
        Err(ControlError::Unsupported)
    }

    fn as_any(&self) -> &dyn Any;
}
