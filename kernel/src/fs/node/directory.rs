use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{DirEntry, Node};
use crate::fs::{PathComponent, VfsError};

/// Directory-specific operations. Only directory nodes implement this trait.
pub trait DirNode: Send + Sync {
    fn lookup(&self, name: &PathComponent) -> Result<Arc<dyn Node>, VfsError>;
    fn read_dir(&self) -> Result<Vec<DirEntry>, VfsError>;

    fn create_file(&self, _name: &str) -> Result<Arc<dyn Node>, VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn create_dir(&self, _name: &str) -> Result<Arc<dyn Node>, VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn unlink(&self, _name: &str) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn create_symlink(&self, _name: &str, _target: &str) -> Result<Arc<dyn Node>, VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn link(&self, _name: &str, _node: Arc<dyn Node>) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }
}
