use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::{
    DirEntry, Fd, File, Node, NodeKind, OpenOptions, Path, PathComponent, Vfs, VfsError,
    read_to_end_with_vfs, with_vfs,
};
use crate::util::stream::{ControlError, ControlRequest};

use super::{PROCESS_TABLE, ProcessHandle, ProcessId, ProcessVfs};

pub const AT_FDCWD: i32 = -100;

fn process_handle(pid: ProcessId) -> Result<ProcessHandle, VfsError> {
    PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| VfsError::NotFound)
}

/// Resolve VFS access based on the process domain contract.
///
/// Host/HostLinux use the global VFS, while Container uses its private VFS.
fn with_process_vfs<R>(
    process: &ProcessHandle,
    f: impl FnOnce(&Vfs) -> Result<R, VfsError>,
) -> Result<R, VfsError> {
    match process.domain().vfs() {
        ProcessVfs::Host => with_vfs(f),
        ProcessVfs::Container(vfs) => f(vfs.as_ref()),
    }
}

pub fn open_path(pid: ProcessId, raw_path: &str, flags: u64) -> Result<Fd, VfsError> {
    open_path_with_options(pid, raw_path, flags, false)
}

pub fn open_path_with_options(
    pid: ProcessId,
    raw_path: &str,
    flags: u64,
    close_on_exec: bool,
) -> Result<Fd, VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    let file = with_process_vfs(&process, |vfs| {
        vfs.open_absolute(&abs, OpenOptions::new(flags))
    })?;
    process.fd_table().open_file_with_flags(file, close_on_exec)
}

pub fn open_file(pid: ProcessId, file: Arc<dyn File>) -> Result<Fd, VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().open_file(file)
}

pub fn open_file_with_flags(
    pid: ProcessId,
    file: Arc<dyn File>,
    close_on_exec: bool,
) -> Result<Fd, VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().open_file_with_flags(file, close_on_exec)
}

pub fn open_path_with_create(pid: ProcessId, raw_path: &str, flags: u64) -> Result<Fd, VfsError> {
    open_path_with_create_and_options(pid, raw_path, flags, false)
}

pub fn open_path_with_create_and_options(
    pid: ProcessId,
    raw_path: &str,
    flags: u64,
    close_on_exec: bool,
) -> Result<Fd, VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    match with_process_vfs(&process, |vfs| {
        vfs.open_absolute(&abs, OpenOptions::new(flags))
    }) {
        Ok(file) => process.fd_table().open_file_with_flags(file, close_on_exec),
        Err(VfsError::NotFound) => {
            let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
            let name = abs
                .components()
                .last()
                .ok_or(VfsError::InvalidPath)?
                .as_str()
                .to_string();
            let dir = with_process_vfs(&process, |vfs| vfs.resolve_node(&parent))?;
            let dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
            let file_node = dir_view.create_file(&name)?;
            let file = file_node.clone().open(OpenOptions::new(flags))?;
            process.fd_table().open_file_with_flags(file, close_on_exec)
        }
        Err(err) => Err(err),
    }
}

pub fn open_path_at(
    pid: ProcessId,
    dirfd: i32,
    raw_path: &str,
    flags: u64,
) -> Result<Fd, VfsError> {
    open_path_at_with_options(pid, dirfd, raw_path, flags, false)
}

pub fn open_path_at_with_options(
    pid: ProcessId,
    dirfd: i32,
    raw_path: &str,
    flags: u64,
    close_on_exec: bool,
) -> Result<Fd, VfsError> {
    let abs = resolve_path_at(pid, dirfd, raw_path)?;
    let process = process_handle(pid)?;
    let file = with_process_vfs(&process, |vfs| {
        vfs.open_absolute(&abs, OpenOptions::new(flags))
    })?;
    process.fd_table().open_file_with_flags(file, close_on_exec)
}

pub fn open_path_at_with_create(
    pid: ProcessId,
    dirfd: i32,
    raw_path: &str,
    flags: u64,
) -> Result<Fd, VfsError> {
    open_path_at_with_create_and_options(pid, dirfd, raw_path, flags, false)
}

pub fn open_path_at_with_create_and_options(
    pid: ProcessId,
    dirfd: i32,
    raw_path: &str,
    flags: u64,
    close_on_exec: bool,
) -> Result<Fd, VfsError> {
    let abs = resolve_path_at(pid, dirfd, raw_path)?;
    let process = process_handle(pid)?;
    match with_process_vfs(&process, |vfs| {
        vfs.open_absolute(&abs, OpenOptions::new(flags))
    }) {
        Ok(file) => process.fd_table().open_file_with_flags(file, close_on_exec),
        Err(VfsError::NotFound) => {
            let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
            let name = abs
                .components()
                .last()
                .ok_or(VfsError::InvalidPath)?
                .as_str()
                .to_string();
            let dir = with_process_vfs(&process, |vfs| vfs.resolve_node(&parent))?;
            let dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
            let file_node = dir_view.create_file(&name)?;
            let file = file_node.clone().open(OpenOptions::new(flags))?;
            process.fd_table().open_file_with_flags(file, close_on_exec)
        }
        Err(err) => Err(err),
    }
}

pub fn read_fd(pid: ProcessId, fd: Fd, buf: &mut [u8]) -> Result<usize, VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().read(fd, buf)
}

pub fn read_dir_fd(pid: ProcessId, fd: Fd) -> Result<Vec<DirEntry>, VfsError> {
    let process = process_handle(pid)?;
    let entry = process.fd_table().entry(fd)?;
    entry.file().readdir()
}

pub fn dir_offset(pid: ProcessId, fd: Fd) -> Result<u64, VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().dir_offset(fd)
}

pub fn set_dir_offset(pid: ProcessId, fd: Fd, offset: u64) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().set_dir_offset(fd, offset)
}

pub fn write_fd(pid: ProcessId, fd: Fd, data: &[u8]) -> Result<usize, VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().write(fd, data)
}

pub fn seek_fd(pid: ProcessId, fd: Fd, offset: i64, whence: u32) -> Result<u64, VfsError> {
    let process = process_handle(pid)?;
    let entry = process.fd_table().entry(fd)?;
    entry.file().seek(offset, whence)
}

pub fn close_fd(pid: ProcessId, fd: Fd) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().close(fd)
}

pub fn dup_fd_min(pid: ProcessId, fd: Fd, min: Fd, close_on_exec: bool) -> Result<Fd, VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().dup_min(fd, min, close_on_exec)
}

pub fn get_fd_flags(pid: ProcessId, fd: Fd) -> Result<u32, VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().get_fd_flags(fd)
}

pub fn set_fd_flags(pid: ProcessId, fd: Fd, flags: u32) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().set_fd_flags(fd, flags)
}

pub fn control_fd(
    pid: ProcessId,
    fd: Fd,
    request: &ControlRequest<'_>,
) -> Result<u64, ControlError> {
    let process = process_handle(pid).map_err(|_| ControlError::Invalid)?;
    let entry = match process.fd_table().entry(fd) {
        Ok(entry) => entry,
        Err(_) => {
            return Err(ControlError::Invalid);
        }
    };
    entry.file().ioctl(request)
}

pub fn fd_file(pid: ProcessId, fd: Fd) -> Result<Arc<dyn File>, VfsError> {
    let process = process_handle(pid)?;
    let entry = process.fd_table().entry(fd)?;
    Ok(entry.file().clone())
}

pub fn change_dir(pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    let dir = with_process_vfs(&process, |vfs| vfs.resolve_node(&abs))?;
    let _dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
    process.set_cwd(abs);
    drop(dir);
    Ok(())
}

pub fn list_dir(pid: ProcessId, raw_path: &str) -> Result<Vec<DirEntry>, VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    with_process_vfs(&process, |vfs| vfs.read_dir(&abs))
}

pub fn stat_path(pid: ProcessId, raw_path: &str) -> Result<crate::fs::NodeStat, VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    with_process_vfs(&process, |vfs| vfs.stat_absolute(&abs))
}

pub fn stat_path_no_follow(
    pid: ProcessId,
    raw_path: &str,
) -> Result<crate::fs::NodeStat, VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    stat_path_no_follow_abs(&process, &abs)
}

pub fn stat_path_at(
    pid: ProcessId,
    dirfd: i32,
    raw_path: &str,
) -> Result<crate::fs::NodeStat, VfsError> {
    let abs = resolve_path_at(pid, dirfd, raw_path)?;
    let process = process_handle(pid)?;
    with_process_vfs(&process, |vfs| vfs.stat_absolute(&abs))
}

pub fn stat_path_no_follow_at(
    pid: ProcessId,
    dirfd: i32,
    raw_path: &str,
) -> Result<crate::fs::NodeStat, VfsError> {
    let abs = resolve_path_at(pid, dirfd, raw_path)?;
    let process = process_handle(pid)?;
    stat_path_no_follow_abs(&process, &abs)
}

fn stat_path_no_follow_abs(
    process: &ProcessHandle,
    abs: &Path,
) -> Result<crate::fs::NodeStat, VfsError> {
    if abs.components().is_empty() {
        return with_process_vfs(process, |vfs| vfs.stat_absolute(abs));
    }
    let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
    let name = abs
        .components()
        .last()
        .ok_or(VfsError::InvalidPath)?
        .clone();
    with_process_vfs(process, |vfs| {
        let dir = vfs.resolve_node(&parent)?;
        let dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
        let node = dir_view.lookup(&name)?;
        node.stat()
    })
}

fn resolve_path_at(pid: ProcessId, dirfd: i32, raw_path: &str) -> Result<Path, VfsError> {
    let process = process_handle(pid)?;
    if raw_path.is_empty() {
        return Err(VfsError::InvalidPath);
    }
    if raw_path.starts_with('/') {
        return Path::resolve(raw_path, &process.cwd());
    }
    if dirfd == AT_FDCWD {
        return Path::resolve(raw_path, &process.cwd());
    }
    if dirfd < 0 {
        return Err(VfsError::InvalidPath);
    }

    let base = dirfd_base_path(pid, dirfd as u32)?;
    Path::resolve(raw_path, &base)
}

fn dirfd_base_path(pid: ProcessId, fd: Fd) -> Result<Path, VfsError> {
    let process = process_handle(pid)?;
    let entry = process.fd_table().entry(fd).map_err(|_| VfsError::BadFd)?;
    let file = entry.file().clone();
    let node = file.dir_node().ok_or(VfsError::NotDirectory)?;
    with_process_vfs(&process, |vfs| dir_node_base_path(vfs, node))
}

fn dir_node_base_path(vfs: &Vfs, node: Arc<dyn Node>) -> Result<Path, VfsError> {
    let mut components = Vec::new();
    let mut current = node;
    loop {
        if let Some(mount_path) = vfs.mount_path_for_node(&current) {
            let mut base_components = mount_path.components().to_vec();
            components.reverse();
            base_components.extend(components);
            return Ok(Path::from_components(true, base_components));
        }
        let current_dir = current.as_dir().ok_or(VfsError::NotDirectory)?;
        if let Some(name) = current_dir.name() {
            components.push(PathComponent::new(name));
        } else if current_dir.parent().is_some() {
            return Err(VfsError::InvalidPath);
        }
        match current_dir.parent() {
            Some(parent) => {
                current = parent;
            }
            None => break,
        }
    }
    components.reverse();
    Ok(Path::from_components(true, components))
}

pub fn remove_path(pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
    let name = abs
        .components()
        .last()
        .ok_or(VfsError::InvalidPath)?
        .as_str()
        .to_string();
    let dir = with_process_vfs(&process, |vfs| vfs.resolve_node(&parent))?;
    let dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
    dir_view.unlink(&name)
}

pub fn write_path(pid: ProcessId, raw_path: &str, data: &[u8]) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    match with_process_vfs(&process, |vfs| vfs.open_absolute(&abs, OpenOptions::new(0))) {
        Ok(file) => {
            let _ = file.write(data)?;
            Ok(())
        }
        Err(VfsError::NotFound) => {
            let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
            let name = abs
                .components()
                .last()
                .ok_or(VfsError::InvalidPath)?
                .as_str()
                .to_string();
            let dir = with_process_vfs(&process, |vfs| vfs.resolve_node(&parent))?;
            let dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
            let file_node = dir_view.create_file(&name)?;
            let file = file_node.clone().open(OpenOptions::new(0))?;
            let _ = file.write(data)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub fn create_dir(pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
    let name = abs
        .components()
        .last()
        .ok_or(VfsError::InvalidPath)?
        .as_str()
        .to_string();
    let dir = with_process_vfs(&process, |vfs| vfs.resolve_node(&parent))?;
    let dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
    match dir_view.create_dir(&name) {
        Ok(_) => Ok(()),
        Err(VfsError::AlreadyExists) => Ok(()),
        Err(err) => Err(err),
    }
}

pub fn symlink(pid: ProcessId, target: &str, link_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let link_abs = Path::resolve(link_path, &process.cwd())?;
    let parent = link_abs.parent().ok_or(VfsError::InvalidPath)?;
    let name = link_abs
        .components()
        .last()
        .ok_or(VfsError::InvalidPath)?
        .as_str()
        .to_string();

    let dir = with_process_vfs(&process, |vfs| vfs.resolve_node(&parent))?;
    let dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
    dir_view.create_symlink(&name, target)?;
    Ok(())
}

pub fn hard_link(pid: ProcessId, existing_path: &str, link_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let src_abs = Path::resolve(existing_path, &process.cwd())?;
    let link_abs = Path::resolve(link_path, &process.cwd())?;

    let parent = link_abs.parent().ok_or(VfsError::InvalidPath)?;
    let name = link_abs
        .components()
        .last()
        .ok_or(VfsError::InvalidPath)?
        .as_str()
        .to_string();

    let (node, dir) = with_process_vfs(&process, |vfs| {
        let node = vfs.resolve_node(&src_abs)?;
        if node.kind() == NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let dir = vfs.resolve_node(&parent)?;
        let _dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
        Ok((node, dir))
    })?;

    let dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
    dir_view.link(&name, node)
}

pub fn read_to_end(pid: ProcessId, raw_path: &str) -> Result<Vec<u8>, VfsError> {
    let process = process_handle(pid)?;
    let abs = Path::resolve(raw_path, &process.cwd())?;
    read_to_end_at(pid, &abs)
}

pub fn read_to_end_at(pid: ProcessId, path: &Path) -> Result<Vec<u8>, VfsError> {
    let process = process_handle(pid)?;
    with_process_vfs(&process, |vfs| read_to_end_with_vfs(vfs, path))
}

pub fn cwd(pid: ProcessId) -> Result<Path, VfsError> {
    let process = process_handle(pid)?;
    Ok(process.cwd())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::CONTAINER_TABLE;
    use crate::fs::DirNode;
    use crate::fs::force_replace_root;
    use crate::fs::memfs::MemDirectory;
    use crate::println;
    use crate::process::PROCESS_TABLE;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn container_process_reads_container_vfs() {
        println!("[test] container_process_reads_container_vfs");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        CONTAINER_TABLE.clear_for_tests();

        let bundle_dir = root.create_dir("bundle").expect("create bundle dir");
        let bundle_dir_view = bundle_dir.as_dir().expect("bundle is dir");
        let rootfs_dir = bundle_dir_view
            .create_dir("rootfs")
            .expect("create rootfs dir");
        let rootfs_dir_view = rootfs_dir.as_dir().expect("rootfs is dir");
        let container_file = rootfs_dir_view
            .create_file("shadow.txt")
            .expect("create container file");
        let file = container_file
            .open(OpenOptions::new(0))
            .expect("open container file");
        let _ = file.write(b"container").expect("write container file");

        let host_file = root.create_file("shadow.txt").expect("create host file");
        let host_handle = host_file.open(OpenOptions::new(0)).expect("open host file");
        let _ = host_handle.write(b"host").expect("write host file");

        let config = bundle_dir_view
            .create_file("config.json")
            .expect("create config");
        let handle = config.open(OpenOptions::new(0)).expect("open config");
        handle
            .write(br#"{"ociVersion":"1.0.2","root":{"path":"rootfs"}}"#)
            .expect("write config");

        let host_pid = PROCESS_TABLE.init_kernel().expect("kernel pid");
        let container = CONTAINER_TABLE
            .create("test", "/bundle")
            .expect("create container");
        let pid = PROCESS_TABLE
            .create_user_process(
                "container-proc",
                crate::process::ProcessDomain::Container(container),
            )
            .expect("create container process");
        assert_ne!(host_pid, pid);

        let fd = open_path(pid, "/shadow.txt", 0).expect("open container file");
        let mut buf = [0u8; 16];
        let read = read_fd(pid, fd, &mut buf).expect("read container file");
        assert_eq!(&buf[..read], b"container");
        close_fd(pid, fd).expect("close container fd");

        let fd = open_path(host_pid, "/shadow.txt", 0).expect("open host file");
        let read = read_fd(host_pid, fd, &mut buf).expect("read host file");
        assert_eq!(&buf[..read], b"host");
        close_fd(host_pid, fd).expect("close host fd");
    }
}
