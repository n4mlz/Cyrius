use alloc::string::String;
use alloc::sync::Arc;

use super::VfsError;
use super::file::File;

mod char_device;
mod directory;
mod symlink;

pub use char_device::CharDeviceNode;
pub use directory::DirNode;
pub use symlink::SymlinkNode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    /// Planned but not implemented yet (BlockDeviceNode will live here).
    BlockDevice,
    /// Planned but not implemented yet (PipeNode will be created by `pipe`).
    Pipe,
    /// Planned but not implemented yet (SocketNode will be created by `socket`).
    Socket,
}

/// Minimal stat-like metadata for nodes.
///
/// # Note
/// Permission/user/timestamp metadata is intentionally omitted for now. Those
/// fields will be added once ownership, rwx permissions, and time tracking are
/// implemented end-to-end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeStat {
    pub kind: NodeKind,
    pub size: u64,
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
