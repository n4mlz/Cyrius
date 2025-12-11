use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use crate::util::spinlock::SpinLock;

use super::{
    DirEntry, Directory, File, FileType, Metadata, NodeRef, PathComponent, Symlink, VfsError,
};

/// Simple in-memory writable filesystem backed by a tree of nodes.
pub struct MemDirectory {
    inner: SpinLock<DirInner>,
}

struct DirInner {
    entries: BTreeMap<String, NodeRef>,
}

impl MemDirectory {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: SpinLock::new(DirInner {
                entries: BTreeMap::new(),
            }),
        })
    }
}

struct MemFile {
    data: SpinLock<Vec<u8>>,
}

impl MemFile {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            data: SpinLock::new(Vec::new()),
        })
    }
}

struct MemSymlink {
    target: String,
}

impl MemSymlink {
    fn new(target: &str) -> Arc<Self> {
        Arc::new(Self {
            target: target.to_string(),
        })
    }
}

impl File for MemFile {
    fn metadata(&self) -> Result<Metadata, VfsError> {
        let data = self.data.lock();
        Ok(Metadata {
            file_type: FileType::File,
            size: data.len() as u64,
        })
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, VfsError> {
        let data = self.data.lock();
        if offset >= data.len() {
            return Ok(0);
        }
        let available = data.len() - offset;
        let to_copy = available.min(buf.len());
        buf[..to_copy].copy_from_slice(&data[offset..offset + to_copy]);
        Ok(to_copy)
    }

    fn write_at(&self, offset: usize, payload: &[u8]) -> Result<usize, VfsError> {
        let mut data = self.data.lock();
        let target = offset
            .checked_add(payload.len())
            .ok_or(VfsError::Corrupted)?;
        if target > data.len() {
            data.resize(target, 0);
        }
        data[offset..offset + payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }

    fn truncate(&self, len: usize) -> Result<(), VfsError> {
        let mut data = self.data.lock();
        data.resize(len, 0);
        Ok(())
    }
}

impl Symlink for MemSymlink {
    fn metadata(&self) -> Result<Metadata, VfsError> {
        Ok(Metadata {
            file_type: FileType::Symlink,
            size: self.target.len() as u64,
        })
    }

    fn target(&self) -> Result<String, VfsError> {
        Ok(self.target.clone())
    }
}

impl Directory for MemDirectory {
    fn metadata(&self) -> Result<Metadata, VfsError> {
        Ok(Metadata {
            file_type: FileType::Directory,
            size: 0,
        })
    }

    fn read_dir(&self) -> Result<Vec<DirEntry>, VfsError> {
        let inner = self.inner.lock();
        let mut out = Vec::with_capacity(inner.entries.len());
        for (name, node) in inner.entries.iter() {
            out.push(DirEntry {
                name: name.clone(),
                metadata: node.metadata()?,
            });
        }
        Ok(out)
    }

    fn lookup(&self, name: &PathComponent) -> Result<NodeRef, VfsError> {
        let inner = self.inner.lock();
        inner
            .entries
            .get(name.as_str())
            .cloned()
            .ok_or(VfsError::NotFound)
    }

    fn create_file(&self, name: &str) -> Result<Arc<dyn File>, VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let file = MemFile::new();
        inner
            .entries
            .insert(name.to_string(), NodeRef::File(file.clone()));
        Ok(file)
    }

    fn create_dir(&self, name: &str) -> Result<Arc<dyn Directory>, VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let dir = MemDirectory::new();
        inner
            .entries
            .insert(name.to_string(), NodeRef::Directory(dir.clone()));
        Ok(dir)
    }

    fn remove(&self, name: &str) -> Result<(), VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.remove(name).is_some() {
            Ok(())
        } else {
            Err(VfsError::NotFound)
        }
    }

    fn create_symlink(&self, name: &str, target: &str) -> Result<Arc<dyn Symlink>, VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let link = MemSymlink::new(target);
        inner
            .entries
            .insert(name.to_string(), NodeRef::Symlink(link.clone()));
        Ok(link)
    }

    fn link(&self, name: &str, node: NodeRef) -> Result<(), VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        inner.entries.insert(name.to_string(), node);
        Ok(())
    }
}
