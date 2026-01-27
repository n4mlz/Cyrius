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
    BlockDevice,
    Pipe,
    Socket,
}

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

pub trait Node: Send + Sync {
    fn kind(&self) -> NodeKind;
    fn stat(&self) -> Result<NodeStat, VfsError>;
    fn open(self: Arc<Self>, options: OpenOptions) -> Result<Arc<dyn File>, VfsError>;

    fn read_dir(&self) -> Result<Vec<DirEntry>, VfsError> {
        Err(VfsError::NotDirectory)
    }

    fn lookup(&self, _name: &PathComponent) -> Result<Arc<dyn Node>, VfsError> {
        Err(VfsError::NotDirectory)
    }

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

    fn readlink(&self) -> Result<String, VfsError> {
        Err(VfsError::InvalidPath)
    }
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
