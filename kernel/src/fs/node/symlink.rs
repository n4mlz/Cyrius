use alloc::string::String;

use crate::fs::VfsError;

/// Symlink-specific operations. Only symlink nodes implement this trait.
pub trait SymlinkNode: Send + Sync {
    fn readlink(&self) -> Result<String, VfsError>;
}
