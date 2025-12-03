use alloc::sync::Arc;

use super::{PathComponent, VfsError};

#[derive(Clone)]
pub enum NodeRef {
    File(Arc<dyn File>),
    Directory(Arc<dyn Directory>),
}

impl NodeRef {
    pub fn metadata(&self) -> Result<Metadata, VfsError> {
        match self {
            NodeRef::File(f) => f.metadata(),
            NodeRef::Directory(d) => d.metadata(),
        }
    }

    pub fn kind(&self) -> FileType {
        match self {
            NodeRef::File(_) => FileType::File,
            NodeRef::Directory(_) => FileType::Directory,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    pub file_type: FileType,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: alloc::string::String,
    pub metadata: Metadata,
}

pub trait File: Send + Sync {
    fn metadata(&self) -> Result<Metadata, VfsError>;

    /// Reads up to `buf.len()` bytes starting from `offset`. Returns the number of bytes read.
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, VfsError>;
}

pub trait Directory: Send + Sync {
    fn metadata(&self) -> Result<Metadata, VfsError>;

    /// Lists entries for this directory.
    fn read_dir(&self) -> Result<alloc::vec::Vec<DirEntry>, VfsError>;

    /// Locates a child entry by name.
    fn lookup(&self, name: &PathComponent) -> Result<NodeRef, VfsError>;
}
