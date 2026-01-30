//! Virtual filesystem scaffolding with mount support and per-process FD tables.

use alloc::{string::ToString, sync::Arc, vec, vec::Vec};

use crate::util::lazylock::LazyLock;
use crate::util::spinlock::{SpinLock, SpinLockGuard};

pub mod devfs;
mod fd;
mod file;
pub mod init;
mod node;
pub mod ops;
mod path;
pub mod probe;
pub mod vfs;

pub use fd::{Fd, FdTable};
pub use file::File;
pub use node::{
    CharDeviceNode, DirEntry, DirNode, Node, NodeKind, NodeStat, OpenOptions, SymlinkNode,
};
use path::normalize_components;
pub use path::{Path, PathComponent};
pub use vfs::{fat32, memfs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NotInitialised,
    AlreadyMounted,
    AlreadyExists,
    InvalidPath,
    BadFd,
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

#[derive(Clone)]
struct Mount {
    path: Path,
    root: Arc<dyn Node>,
}

pub struct Vfs {
    mounts: Vec<Mount>,
}

impl Vfs {
    pub fn new(root: Arc<dyn Node>) -> Self {
        assert!(root.as_dir().is_some(), "root must be a directory node");
        Self {
            mounts: vec![Mount {
                path: Path::root(),
                root,
            }],
        }
    }

    pub fn mount(&mut self, path: Path, root: Arc<dyn Node>) -> Result<(), VfsError> {
        if !path.is_absolute() {
            return Err(VfsError::InvalidPath);
        }
        if self.mounts.iter().any(|m| m.path == path) {
            return Err(VfsError::AlreadyMounted);
        }
        self.mounts.push(Mount { path, root });
        self.mounts
            .sort_by(|a, b| b.path.components().len().cmp(&a.path.components().len()));
        Ok(())
    }

    pub fn root(&self) -> Arc<dyn Node> {
        self.mounts
            .iter()
            .find(|m| m.path.components().is_empty())
            .expect("root mount must exist")
            .root
            .clone()
    }

    pub fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>, VfsError> {
        if !path.is_absolute() {
            return Err(VfsError::InvalidPath);
        }
        let (mount, tail) = self.select_mount(path)?;
        let node = self.resolve_from(mount.root.clone(), Vec::new(), tail, 0)?;
        let dir = node.as_dir().ok_or(VfsError::NotDirectory)?;
        let mut entries = dir.read_dir()?;
        self.inject_mount_points(path, &mut entries);
        Ok(entries)
    }

    pub fn open_absolute(
        &self,
        path: &Path,
        options: OpenOptions,
    ) -> Result<Arc<dyn File>, VfsError> {
        let node = self.resolve_absolute(path, 0)?;
        node.clone().open(options)
    }

    pub fn stat_absolute(&self, path: &Path) -> Result<NodeStat, VfsError> {
        let node = self.resolve_absolute(path, 0)?;
        node.stat()
    }

    pub fn resolve_node(&self, path: &Path) -> Result<Arc<dyn Node>, VfsError> {
        self.resolve_absolute(path, 0)
    }

    pub fn mount_path_for_node(&self, node: &Arc<dyn Node>) -> Option<Path> {
        self.mounts
            .iter()
            .find(|mount| Arc::ptr_eq(&mount.root, node))
            .map(|mount| mount.path.clone())
    }

    fn inject_mount_points(&self, path: &Path, entries: &mut Vec<DirEntry>) {
        let base_components = path.components();
        for mount in &self.mounts {
            let mount_components = mount.path.components();
            if mount_components.len() != base_components.len() + 1 {
                continue;
            }
            if !mount_components.starts_with(base_components) {
                continue;
            }
            let name = mount_components[base_components.len()].as_str();
            let present = entries.iter().any(|entry| entry.name == name);
            if present {
                continue;
            }
            entries.push(DirEntry {
                name: name.to_string(),
                stat: NodeStat {
                    kind: NodeKind::Directory,
                    size: 0,
                },
            });
        }
    }

    fn select_mount<'a, 'b>(
        &'a self,
        path: &'b Path,
    ) -> Result<(&'a Mount, &'b [PathComponent]), VfsError> {
        for mount in &self.mounts {
            let mp = mount.path.components();
            if path.components().starts_with(mp) {
                let tail = &path.components()[mp.len()..];
                return Ok((mount, tail));
            }
        }
        Err(VfsError::NotFound)
    }

    fn resolve_absolute(&self, path: &Path, depth: u8) -> Result<Arc<dyn Node>, VfsError> {
        if !path.is_absolute() {
            return Err(VfsError::InvalidPath);
        }
        let (mount, tail) = self.select_mount(path)?;
        self.resolve_from(mount.root.clone(), Vec::new(), tail, depth)
    }

    fn resolve_from(
        &self,
        current: Arc<dyn Node>,
        mut current_path: Vec<PathComponent>,
        components: &[PathComponent],
        depth: u8,
    ) -> Result<Arc<dyn Node>, VfsError> {
        if depth >= 16 {
            return Err(VfsError::InvalidPath);
        }

        if components.is_empty() {
            return Ok(current);
        }

        let dir = current.as_dir().ok_or(VfsError::NotDirectory)?;

        let (first, rest) = components.split_first().expect("components not empty");
        let node = dir.lookup(first)?;

        if node.as_dir().is_some() {
            current_path.push(first.clone());
            self.resolve_from(node, current_path, rest, depth)
        } else if let Some(link) = node.as_symlink() {
            let target_raw = link.readlink()?;
            let mut combined_components = resolve_link_components(&current_path, &target_raw)?;
            if !rest.is_empty() {
                combined_components.extend(rest.iter().cloned());
            }
            let combined = Path::from_components(true, combined_components);
            self.resolve_absolute(&combined, depth + 1)
        } else if rest.is_empty() {
            Ok(node)
        } else {
            Err(VfsError::NotDirectory)
        }
    }
}

fn resolve_link_components(
    base: &[PathComponent],
    target: &str,
) -> Result<Vec<PathComponent>, VfsError> {
    let components = if target.starts_with('/') {
        Vec::new()
    } else {
        base.to_vec()
    };
    normalize_components(components, target, true)
}

pub fn mount_root(root: Arc<dyn Node>) -> Result<(), VfsError> {
    let mut guard = VFS.get().lock();
    if guard.is_some() {
        return Err(VfsError::AlreadyMounted);
    }
    *guard = Some(Vfs::new(root));
    Ok(())
}

pub fn mount_at(path: Path, root: Arc<dyn Node>) -> Result<(), VfsError> {
    let mut guard = VFS.get().lock();
    let vfs = guard.as_mut().ok_or(VfsError::NotInitialised)?;
    vfs.mount(path, root)
}

pub fn with_vfs<R>(f: impl FnOnce(&Vfs) -> Result<R, VfsError>) -> Result<R, VfsError> {
    let guard = VFS.get().lock();
    let vfs = guard.as_ref().ok_or(VfsError::NotInitialised)?;
    f(vfs)
}

pub fn read_to_end(path: &Path) -> Result<Vec<u8>, VfsError> {
    with_vfs(|vfs| read_to_end_with_vfs(vfs, path))
}

pub fn read_to_end_with_vfs(vfs: &Vfs, path: &Path) -> Result<Vec<u8>, VfsError> {
    let stat = vfs.stat_absolute(path)?;
    if stat.kind != NodeKind::Regular {
        return Err(VfsError::NotFile);
    }

    let file = vfs.open_absolute(path, OpenOptions::new(0))?;
    let size = usize::try_from(stat.size).map_err(|_| VfsError::Corrupted)?;
    let mut buf = vec![0u8; size];
    let mut offset = 0usize;
    while offset < size {
        let read = file.read(&mut buf[offset..])?;
        if read == 0 {
            return Err(VfsError::UnexpectedEof);
        }
        offset = offset.saturating_add(read);
    }
    Ok(buf)
}

pub fn vfs_guard() -> Result<SpinLockGuard<'static, Option<Vfs>>, VfsError> {
    Ok(VFS.get().lock())
}

#[cfg(test)]
pub fn force_replace_root(root: Arc<dyn Node>) {
    let mut guard = VFS.get().lock();
    *guard = Some(Vfs::new(root));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::block::SharedBlockDevice;
    use crate::device::virtio::block::with_devices;
    use crate::fs::fat32::FatFileSystem;
    use crate::fs::memfs::MemDirectory;
    use crate::println;
    use crate::process::PROCESS_TABLE;
    use crate::process::fs as proc_fs;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn vfs_resolves_absolute_path() {
        println!("[test] vfs_resolves_absolute_path");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        let file = root.create_file("foo").expect("create file entry");
        let handle = file.open(OpenOptions::new(0)).expect("open file");
        let _ = handle.write(&[0xAA, 0xBB]).expect("write");

        let path = Path::parse("/foo").expect("parse path");
        let stat = with_vfs(|vfs| vfs.stat_absolute(&path)).expect("stat");
        assert_eq!(stat.kind, NodeKind::Regular);
    }

    #[kernel_test_case]
    fn fat32_reads_known_file() {
        println!("[test] fat32_reads_known_file");

        let _ = PROCESS_TABLE.init_kernel();
        let mut mounted = false;
        with_devices(|devices| {
            for dev in devices {
                let shared = SharedBlockDevice::from_arc(dev.clone());
                if let Ok(fs) = FatFileSystem::new(shared) {
                    let root: Arc<dyn Node> = fs.root_dir();
                    force_replace_root(MemDirectory::new());
                    mount_at(Path::parse("/mnt").unwrap(), root).expect("mount fat");
                    mounted = true;
                    break;
                }
            }
        });
        assert!(mounted, "no FAT32-capable block device found");

        let path = "/mnt/HELLO.TXT";
        let pid = PROCESS_TABLE.kernel_process_id().expect("kernel pid");
        let fd = proc_fs::open_path(pid, path, 0).expect("open fd");
        let mut buf = [0u8; 64];
        let read = proc_fs::read_fd(pid, fd, &mut buf).expect("read file");
        let payload = b"Hello from FAT32!\n";
        assert_eq!(read, payload.len());
        assert_eq!(&buf[..read], payload);
        let _ = proc_fs::close_fd(pid, fd);
    }
}
