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

    fn seek(&self, offset: i64, whence: u32) -> Result<u64, VfsError> {
        let mut guard = self.pos.lock();
        let base = match whence {
            0 => 0i64,
            1 => *guard as i64,
            2 => self.node.size() as i64,
            _ => return Err(VfsError::InvalidPath),
        };
        let next = base.checked_add(offset).ok_or(VfsError::Corrupted)?;
        if next < 0 {
            return Err(VfsError::InvalidPath);
        }
        let next = usize::try_from(next).map_err(|_| VfsError::Corrupted)?;
        *guard = next;
        Ok(next as u64)
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
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

    fn as_any(&self) -> &dyn core::any::Any {
        self
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::println;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn memfs_seek_updates_offset() {
        println!("[test] memfs_seek_updates_offset");

        let root = MemDirectory::new();
        let root_view = root.as_dir().expect("root dir");
        let file_node = root_view.create_file("note").expect("create file");
        let file = file_node.open(OpenOptions::new(0)).expect("open file");

        let _ = file.write(b"abcd").expect("write");
        let pos = file.seek(1, 0).expect("seek");
        assert_eq!(pos, 1);

        let mut buf = [0u8; 2];
        let read = file.read(&mut buf).expect("read");
        assert_eq!(read, 2);
        assert_eq!(&buf[..read], b"bc");
    }
}

impl SymlinkNode for MemSymlink {
    fn readlink(&self) -> Result<String, VfsError> {
        Ok(self.target.clone())
    }
}
