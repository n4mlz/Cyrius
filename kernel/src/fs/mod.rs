//! Virtual filesystem scaffolding with a minimal mount tree and file descriptor table.
//!
//! The VFS keeps the surface small on purpose: read-only traversal, basic metadata, and sequential
//! reads through a per-table offset. Future write/mmap extensions can hang off the existing traits.

use alloc::sync::Arc;

use crate::util::lazylock::LazyLock;
use crate::util::spinlock::{SpinLock, SpinLockGuard};

pub mod fat32;
mod fd;
mod node;
mod path;

pub use fd::{Fd, FdTable, OPEN_FILE_TABLE};
pub use node::{DirEntry, Directory, File, FileType, Metadata, NodeRef};
pub use path::{PathComponent, VfsPath};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NotInitialised,
    AlreadyMounted,
    InvalidPath,
    NotFound,
    NotDirectory,
    NotFile,
    ReadOnly,
    UnexpectedEof,
    NameTooLong,
    UnderlyingDevice,
    Corrupted,
}

/// Global VFS instance. Initialised by mounting a root filesystem.
static VFS: LazyLock<SpinLock<Option<Vfs>>> = LazyLock::new_const(|| SpinLock::new(None));

pub struct Vfs {
    root: Arc<dyn Directory>,
}

impl Vfs {
    pub fn new(root: Arc<dyn Directory>) -> Self {
        Self { root }
    }

    pub fn root(&self) -> Arc<dyn Directory> {
        self.root.clone()
    }

    pub fn open(&self, path: &VfsPath) -> Result<NodeRef, VfsError> {
        if !path.is_absolute() {
            return Err(VfsError::InvalidPath);
        }
        self.resolve(self.root.clone(), path.components())
    }

    pub fn open_file(&self, path: &VfsPath) -> Result<Arc<dyn File>, VfsError> {
        match self.open(path)? {
            NodeRef::File(file) => Ok(file),
            NodeRef::Directory(_) => Err(VfsError::NotFile),
        }
    }

    fn resolve(
        &self,
        mut current: Arc<dyn Directory>,
        components: &[PathComponent],
    ) -> Result<NodeRef, VfsError> {
        if components.is_empty() {
            return Ok(NodeRef::Directory(current));
        }

        for (index, component) in components.iter().enumerate() {
            let node = current.lookup(component)?;
            if index + 1 == components.len() {
                return Ok(node);
            }
            current = match node {
                NodeRef::Directory(dir) => dir,
                NodeRef::File(_) => return Err(VfsError::NotDirectory),
            };
        }

        Err(VfsError::NotFound)
    }
}

pub fn mount_root(root: Arc<dyn Directory>) -> Result<(), VfsError> {
    let mut guard = VFS.get().lock();
    if guard.is_some() {
        return Err(VfsError::AlreadyMounted);
    }
    *guard = Some(Vfs::new(root));
    Ok(())
}

pub fn with_vfs<R>(f: impl FnOnce(&Vfs) -> Result<R, VfsError>) -> Result<R, VfsError> {
    let guard = VFS.get().lock();
    let vfs = guard.as_ref().ok_or(VfsError::NotInitialised)?;
    f(vfs)
}

pub fn vfs_guard() -> Result<SpinLockGuard<'static, Option<Vfs>>, VfsError> {
    Ok(VFS.get().lock())
}

#[cfg(test)]
pub fn force_replace_root(root: Arc<dyn Directory>) {
    let mut guard = VFS.get().lock();
    *guard = Some(Vfs::new(root));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::block::SharedBlockDevice;
    use crate::device::virtio::block::with_devices;
    use crate::fs::fat32::FatFileSystem;
    use crate::println;
    use crate::test::kernel_test_case;
    use alloc::{boxed::Box, vec, vec::Vec};

    struct MemFile {
        data: Box<[u8]>,
    }

    impl File for MemFile {
        fn metadata(&self) -> Result<Metadata, VfsError> {
            Ok(Metadata {
                file_type: FileType::File,
                size: self.data.len() as u64,
            })
        }

        fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, VfsError> {
            if offset >= self.data.len() {
                return Ok(0);
            }
            let available = self.data.len() - offset;
            let to_copy = available.min(buf.len());
            buf[..to_copy].copy_from_slice(&self.data[offset..offset + to_copy]);
            Ok(to_copy)
        }
    }

    struct MemDir {
        children: Vec<(alloc::string::String, NodeRef)>,
    }

    impl Directory for MemDir {
        fn metadata(&self) -> Result<Metadata, VfsError> {
            Ok(Metadata {
                file_type: FileType::Directory,
                size: 0,
            })
        }

        fn read_dir(&self) -> Result<alloc::vec::Vec<DirEntry>, VfsError> {
            let mut entries = Vec::new();
            for (name, node) in &self.children {
                let meta = node.metadata()?;
                entries.push(DirEntry {
                    name: name.clone(),
                    metadata: meta,
                });
            }
            Ok(entries)
        }

        fn lookup(&self, name: &PathComponent) -> Result<NodeRef, VfsError> {
            for (n, node) in &self.children {
                let raw = name.as_str();
                if n == raw {
                    return Ok(node.clone());
                }
            }
            Err(VfsError::NotFound)
        }
    }

    #[kernel_test_case]
    fn vfs_resolves_absolute_path() {
        println!("[test] vfs_resolves_absolute_path");

        let file = NodeRef::File(Arc::new(MemFile {
            data: Box::new([0xAA, 0xBB]),
        }));
        let root = Arc::new(MemDir {
            children: vec![(alloc::string::String::from("foo"), file)],
        });
        force_replace_root(root);

        let path = VfsPath::parse("/foo").expect("parse path");
        let resolved = with_vfs(|vfs| vfs.open(&path)).expect("open");
        assert!(matches!(resolved, NodeRef::File(_)));
    }

    #[kernel_test_case]
    fn fat32_reads_known_file() {
        println!("[test] fat32_reads_known_file");

        let mut mounted = false;
        with_devices(|devices| {
            for dev in devices {
                let shared = SharedBlockDevice::from_arc(dev.clone());
                if let Ok(fs) = FatFileSystem::new(shared) {
                    let root: Arc<dyn Directory> = fs.root_dir();
                    force_replace_root(root);
                    mounted = true;
                    break;
                }
            }
        });
        assert!(mounted, "no FAT32-capable block device found");

        let path = VfsPath::parse("/HELLO.TXT").expect("parse path");
        let table = OPEN_FILE_TABLE.get();
        let fd = table.open_at_root(&path).expect("open fd");
        let mut buf = [0u8; 64];
        let read = table.read(fd, &mut buf).expect("read file");
        let payload = b"Hello from FAT32!\n";
        assert_eq!(read, payload.len());
        assert_eq!(&buf[..read], payload);
        let _ = table.close(fd);
    }
}
