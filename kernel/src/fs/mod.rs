//! Virtual filesystem scaffolding with mount support and per-process FD tables.

use alloc::{string::ToString, sync::Arc, vec, vec::Vec};

use crate::util::lazylock::LazyLock;
use crate::util::spinlock::{SpinLock, SpinLockGuard};

pub mod fat32;
mod fd;
pub mod memfs;
mod node;
mod path;

pub use fd::{Fd, FdTable};
pub use node::{DirEntry, Directory, File, FileType, Metadata, NodeRef, Symlink};
pub use path::{PathComponent, VfsPath};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NotInitialised,
    AlreadyMounted,
    AlreadyExists,
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

#[derive(Clone)]
struct Mount {
    path: VfsPath,
    root: Arc<dyn Directory>,
}

pub struct Vfs {
    mounts: Vec<Mount>,
}

impl Vfs {
    pub fn new(root: Arc<dyn Directory>) -> Self {
        Self {
            mounts: vec![Mount {
                path: VfsPath::root(),
                root,
            }],
        }
    }

    pub fn mount(&mut self, path: VfsPath, root: Arc<dyn Directory>) -> Result<(), VfsError> {
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

    pub fn root(&self) -> Arc<dyn Directory> {
        self.mounts
            .iter()
            .find(|m| m.path.components().is_empty())
            .expect("root mount must exist")
            .root
            .clone()
    }

    pub fn read_dir(&self, path: &VfsPath) -> Result<Vec<DirEntry>, VfsError> {
        if !path.is_absolute() {
            return Err(VfsError::InvalidPath);
        }
        let (mount, tail) = self.select_mount(path)?;
        let node = self.resolve_from(mount.root.clone(), Vec::new(), tail, 0)?;
        let dir = match node {
            NodeRef::Directory(dir) => dir,
            NodeRef::File(_) | NodeRef::Symlink(_) => return Err(VfsError::NotDirectory),
        };

        let mut entries = dir.read_dir()?;
        self.inject_mount_points(path, &mut entries);
        Ok(entries)
    }

    pub fn open_absolute(&self, path: &VfsPath) -> Result<NodeRef, VfsError> {
        self.resolve_absolute(path, 0)
    }

    fn inject_mount_points(&self, path: &VfsPath, entries: &mut Vec<DirEntry>) {
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
                metadata: Metadata {
                    file_type: FileType::Directory,
                    size: 0,
                },
            });
        }
    }

    fn select_mount<'a, 'b>(
        &'a self,
        path: &'b VfsPath,
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

    fn resolve_absolute(&self, path: &VfsPath, depth: u8) -> Result<NodeRef, VfsError> {
        if !path.is_absolute() {
            return Err(VfsError::InvalidPath);
        }
        let (mount, tail) = self.select_mount(path)?;
        self.resolve_from(mount.root.clone(), Vec::new(), tail, depth)
    }

    fn resolve_from(
        &self,
        current: Arc<dyn Directory>,
        mut current_path: Vec<PathComponent>,
        components: &[PathComponent],
        depth: u8,
    ) -> Result<NodeRef, VfsError> {
        if depth >= 16 {
            return Err(VfsError::InvalidPath);
        }

        if components.is_empty() {
            return Ok(NodeRef::Directory(current));
        }

        let (first, rest) = components.split_first().expect("components not empty");
        let node = current.lookup(first)?;

        match node {
            NodeRef::Directory(dir) => {
                current_path.push(first.clone());
                self.resolve_from(dir, current_path, rest, depth)
            }
            NodeRef::Symlink(link) => {
                let target_raw = link.target()?;
                let mut combined_components = resolve_link_components(&current_path, &target_raw)?;
                if !rest.is_empty() {
                    combined_components.extend(rest.iter().cloned());
                }
                let combined = VfsPath::from_components(true, combined_components);
                self.resolve_absolute(&combined, depth + 1)
            }
            NodeRef::File(file) => {
                if rest.is_empty() {
                    Ok(NodeRef::File(file))
                } else {
                    Err(VfsError::NotDirectory)
                }
            }
        }
    }
}

fn resolve_link_components(
    base: &[PathComponent],
    target: &str,
) -> Result<Vec<PathComponent>, VfsError> {
    let mut components = if target.starts_with('/') {
        Vec::new()
    } else {
        base.to_vec()
    };

    for part in target.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            components.pop().ok_or(VfsError::InvalidPath)?;
            continue;
        }
        if part.len() > 255 {
            return Err(VfsError::NameTooLong);
        }
        components.push(PathComponent::new(part));
    }

    Ok(components)
}

pub fn mount_root(root: Arc<dyn Directory>) -> Result<(), VfsError> {
    let mut guard = VFS.get().lock();
    if guard.is_some() {
        return Err(VfsError::AlreadyMounted);
    }
    *guard = Some(Vfs::new(root));
    Ok(())
}

pub fn mount_at(path: VfsPath, root: Arc<dyn Directory>) -> Result<(), VfsError> {
    let mut guard = VFS.get().lock();
    let vfs = guard.as_mut().ok_or(VfsError::NotInitialised)?;
    vfs.mount(path, root)
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
    use crate::fs::memfs::MemDirectory;
    use crate::println;
    use crate::process::PROCESS_TABLE;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn vfs_resolves_absolute_path() {
        println!("[test] vfs_resolves_absolute_path");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        let file = root.create_file("foo").expect("create file entry");
        let _ = file.write_at(0, &[0xAA, 0xBB]).expect("write");

        let path = VfsPath::parse("/foo").expect("parse path");
        let resolved = with_vfs(|vfs| vfs.open_absolute(&path)).expect("open");
        assert!(matches!(resolved, NodeRef::File(_)));
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
                    let root: Arc<dyn Directory> = fs.root_dir();
                    force_replace_root(MemDirectory::new());
                    mount_at(VfsPath::parse("/mnt").unwrap(), root).expect("mount fat");
                    mounted = true;
                    break;
                }
            }
        });
        assert!(mounted, "no FAT32-capable block device found");

        let path = "/mnt/HELLO.TXT";
        let pid = PROCESS_TABLE.kernel_process_id().expect("kernel pid");
        let fd = PROCESS_TABLE.open_path(pid, path).expect("open fd");
        let mut buf = [0u8; 64];
        let read = PROCESS_TABLE.read_fd(pid, fd, &mut buf).expect("read file");
        let payload = b"Hello from FAT32!\n";
        assert_eq!(read, payload.len());
        assert_eq!(&buf[..read], payload);
        let _ = PROCESS_TABLE.close_fd(pid, fd);
    }

    #[kernel_test_case]
    fn memfs_write_read_remove() {
        println!("[test] memfs_write_read_remove");

        let root = MemDirectory::new();
        force_replace_root(root.clone());

        let file = root.create_file("note").expect("create file");
        let payload = b"memfs contents";
        let _ = file.write_at(0, payload).expect("write");

        let mut buf = [0u8; 32];
        let resolved = with_vfs(|vfs| vfs.open_absolute(&VfsPath::parse("/note").unwrap()))
            .expect("open note");
        match resolved {
            NodeRef::File(f) => {
                let read = f.read_at(0, &mut buf).expect("read");
                assert_eq!(&buf[..read], payload);
            }
            _ => panic!("expected file"),
        }

        root.remove("note").expect("remove file");
        assert!(matches!(
            root.lookup(&PathComponent::new("note")),
            Err(VfsError::NotFound)
        ));
    }

    #[kernel_test_case]
    fn mount_points_visible_in_parent_listing() {
        println!("[test] mount_points_visible_in_parent_listing");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        let mounted = MemDirectory::new();
        mount_at(VfsPath::parse("/mnt").unwrap(), mounted).expect("mount memfs at /mnt");

        let pid = PROCESS_TABLE.init_kernel().expect("kernel init");
        let entries = PROCESS_TABLE.list_dir(pid, "/").expect("list root");
        let has_mnt = entries.iter().any(|entry| entry.name == "mnt");
        assert!(
            has_mnt,
            "mount point not visible in / listing: {:?}",
            entries
        );
    }

    #[kernel_test_case]
    fn mount_selection_prefers_longest_match() {
        println!("[test] mount_selection_prefers_longest_match");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        let fat = MemDirectory::new();
        mount_at(VfsPath::parse("/mnt").unwrap(), fat.clone()).expect("mount fat");

        let root_file = root.create_file("root.txt").expect("root file");
        let fat_file = fat.create_file("fat.txt").expect("fat file");
        let _ = root_file.write_at(0, b"root").expect("write root");
        let _ = fat_file.write_at(0, b"fat").expect("write fat");

        let root_read =
            with_vfs(
                |vfs| match vfs.open_absolute(&VfsPath::parse("/root.txt").unwrap())? {
                    NodeRef::File(f) => {
                        let mut buf = [0u8; 8];
                        let n = f.read_at(0, &mut buf)?;
                        Ok(buf[..n].to_vec())
                    }
                    _ => Err(VfsError::NotFile),
                },
            )
            .expect("read root");
        assert_eq!(root_read, b"root".to_vec());

        let fat_read =
            with_vfs(
                |vfs| match vfs.open_absolute(&VfsPath::parse("/mnt/fat.txt").unwrap())? {
                    NodeRef::File(f) => {
                        let mut buf = [0u8; 8];
                        let n = f.read_at(0, &mut buf)?;
                        Ok(buf[..n].to_vec())
                    }
                    _ => Err(VfsError::NotFile),
                },
            )
            .expect("read fat");
        assert_eq!(fat_read, b"fat".to_vec());
    }
}
