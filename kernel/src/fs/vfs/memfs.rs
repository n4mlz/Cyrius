use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use crate::util::spinlock::SpinLock;

use crate::fs::{
    DirEntry, DirNode, File, Node, NodeKind, NodeStat, OpenOptions, PathComponent, SymlinkNode,
    VfsError,
};

/// Simple in-memory writable filesystem backed by a tree of nodes.
pub struct MemDirectory {
    inner: SpinLock<DirInner>,
}

struct DirInner {
    entries: BTreeMap<String, Arc<dyn Node>>,
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

struct MemFileNode {
    data: SpinLock<Vec<u8>>,
}

impl MemFileNode {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            data: SpinLock::new(Vec::new()),
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

    fn size(&self) -> u64 {
        let data = self.data.lock();
        data.len() as u64
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

struct MemFileHandle {
    node: Arc<MemFileNode>,
    pos: SpinLock<usize>,
    _flags: OpenOptions,
}

impl MemFileHandle {
    fn new(node: Arc<MemFileNode>, flags: OpenOptions) -> Self {
        Self {
            node,
            pos: SpinLock::new(0),
            _flags: flags,
        }
    }
}

impl File for MemFileHandle {
    fn read(&self, buf: &mut [u8]) -> Result<usize, VfsError> {
        let mut guard = self.pos.lock();
        let read = self.node.read_at(*guard, buf)?;
        *guard = guard.checked_add(read).ok_or(VfsError::Corrupted)?;
        Ok(read)
    }

    fn write(&self, data: &[u8]) -> Result<usize, VfsError> {
        let mut guard = self.pos.lock();
        let written = self.node.write_at(*guard, data)?;
        *guard = guard.checked_add(written).ok_or(VfsError::Corrupted)?;
        Ok(written)
    }
}

struct MemDirFile {
    node: Arc<MemDirectory>,
    _flags: OpenOptions,
}

impl MemDirFile {
    fn new(node: Arc<MemDirectory>, flags: OpenOptions) -> Self {
        Self {
            node,
            _flags: flags,
        }
    }
}

impl File for MemDirFile {
    fn read(&self, _buf: &mut [u8]) -> Result<usize, VfsError> {
        Err(VfsError::NotFile)
    }

    fn readdir(&self) -> Result<Vec<DirEntry>, VfsError> {
        self.node.read_dir()
    }
}

impl Node for MemFileNode {
    fn kind(&self) -> NodeKind {
        NodeKind::Regular
    }

    fn stat(&self) -> Result<NodeStat, VfsError> {
        Ok(NodeStat {
            kind: NodeKind::Regular,
            size: self.size(),
        })
    }

    fn open(self: Arc<Self>, options: OpenOptions) -> Result<Arc<dyn File>, VfsError> {
        Ok(Arc::new(MemFileHandle::new(self, options)))
    }
}

impl Node for MemDirectory {
    fn kind(&self) -> NodeKind {
        NodeKind::Directory
    }

    fn stat(&self) -> Result<NodeStat, VfsError> {
        Ok(NodeStat {
            kind: NodeKind::Directory,
            size: 0,
        })
    }

    fn open(self: Arc<Self>, options: OpenOptions) -> Result<Arc<dyn File>, VfsError> {
        Ok(Arc::new(MemDirFile::new(self, options)))
    }

    fn as_dir(&self) -> Option<&dyn DirNode> {
        Some(self)
    }
}

impl DirNode for MemDirectory {
    fn read_dir(&self) -> Result<Vec<DirEntry>, VfsError> {
        let inner = self.inner.lock();
        let mut out = Vec::with_capacity(inner.entries.len());
        for (name, node) in inner.entries.iter() {
            out.push(DirEntry {
                name: name.clone(),
                stat: node.stat()?,
            });
        }
        Ok(out)
    }

    fn lookup(&self, name: &PathComponent) -> Result<Arc<dyn Node>, VfsError> {
        let inner = self.inner.lock();
        inner
            .entries
            .get(name.as_str())
            .cloned()
            .ok_or(VfsError::NotFound)
    }

    fn create_file(&self, name: &str) -> Result<Arc<dyn Node>, VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let file = MemFileNode::new();
        inner.entries.insert(name.to_string(), file.clone());
        Ok(file)
    }

    fn create_dir(&self, name: &str) -> Result<Arc<dyn Node>, VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let dir = MemDirectory::new();
        inner.entries.insert(name.to_string(), dir.clone());
        Ok(dir)
    }

    fn unlink(&self, name: &str) -> Result<(), VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.remove(name).is_some() {
            Ok(())
        } else {
            Err(VfsError::NotFound)
        }
    }

    fn create_symlink(&self, name: &str, target: &str) -> Result<Arc<dyn Node>, VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let link = MemSymlink::new(target);
        inner.entries.insert(name.to_string(), link.clone());
        Ok(link)
    }

    fn link(&self, name: &str, node: Arc<dyn Node>) -> Result<(), VfsError> {
        let mut inner = self.inner.lock();
        if inner.entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        inner.entries.insert(name.to_string(), node);
        Ok(())
    }
}

impl Node for MemSymlink {
    fn kind(&self) -> NodeKind {
        NodeKind::Symlink
    }

    fn stat(&self) -> Result<NodeStat, VfsError> {
        Ok(NodeStat {
            kind: NodeKind::Symlink,
            size: self.target.len() as u64,
        })
    }

    fn open(self: Arc<Self>, _options: OpenOptions) -> Result<Arc<dyn File>, VfsError> {
        Err(VfsError::NotFile)
    }

    fn as_symlink(&self) -> Option<&dyn SymlinkNode> {
        Some(self)
    }
}

impl SymlinkNode for MemSymlink {
    fn readlink(&self) -> Result<String, VfsError> {
        Ok(self.target.clone())
    }
}
