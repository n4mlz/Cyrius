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

    /// Writes up to `data.len()` bytes starting from `offset`. Returns the number of bytes written.
    fn write_at(&self, _offset: usize, _data: &[u8]) -> Result<usize, VfsError> {
        Err(VfsError::ReadOnly)
    }

    /// Truncates or extends the file to `len` bytes.
    fn truncate(&self, _len: usize) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }
}

pub trait Directory: Send + Sync {
    fn metadata(&self) -> Result<Metadata, VfsError>;

    /// Lists entries for this directory.
    fn read_dir(&self) -> Result<alloc::vec::Vec<DirEntry>, VfsError>;

    /// Locates a child entry by name.
    fn lookup(&self, name: &PathComponent) -> Result<NodeRef, VfsError>;

    /// Creates a new empty file entry and returns its handle.
    fn create_file(&self, _name: &str) -> Result<Arc<dyn File>, VfsError> {
        Err(VfsError::ReadOnly)
    }

    /// Creates a new directory and returns it.
    fn create_dir(&self, _name: &str) -> Result<Arc<dyn Directory>, VfsError> {
        Err(VfsError::ReadOnly)
    }

    /// Removes a file or directory entry.
    fn remove(&self, _name: &str) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }
}
