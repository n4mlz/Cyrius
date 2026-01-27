use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{PathComponent, VfsError};
use crate::util::stream::{ControlError, ControlRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    /// Planned but not implemented yet.
    BlockDevice,
    /// Planned but not implemented yet.
    Pipe,
    /// Planned but not implemented yet.
    Socket,
}

/// Minimal stat-like metadata for nodes.
///
/// # Note
/// Several fields (mode/uid/gid/timestamps) are currently placeholders in most
/// implementations. They are kept here to stabilise the interface and will be
/// populated with real permission and time metadata later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeStat {
    pub kind: NodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub stat: NodeStat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenOptions {
    pub flags: u64,
}

impl OpenOptions {
    pub const fn new(flags: u64) -> Self {
        Self { flags }
    }
}

/// Inode-like persistent object. It does not perform I/O directly.
pub trait Node: Send + Sync {
    fn kind(&self) -> NodeKind;
    fn stat(&self) -> Result<NodeStat, VfsError>;
    fn open(self: Arc<Self>, options: OpenOptions) -> Result<Arc<dyn File>, VfsError>;

    /// Returns a directory view if this node is a directory.
    fn as_dir(&self) -> Option<&dyn DirNode> {
        None
    }

    /// Returns a symlink view if this node is a symlink.
    fn as_symlink(&self) -> Option<&dyn SymlinkNode> {
        None
    }
}

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

/// Symlink-specific operations. Only symlink nodes implement this trait.
pub trait SymlinkNode: Send + Sync {
    fn readlink(&self) -> Result<String, VfsError>;
}

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
