use alloc::string::ToString;
use alloc::vec::Vec;

use crate::fs::{DirEntry, Fd, NodeRef, Vfs, VfsError, VfsPath, read_to_end_with_vfs, with_vfs};

use super::{PROCESS_TABLE, ProcessHandle, ProcessId};

fn process_handle(pid: ProcessId) -> Result<ProcessHandle, VfsError> {
    PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| VfsError::NotFound)
}

fn with_process_vfs<R>(
    process: &ProcessHandle,
    f: impl FnOnce(&Vfs) -> Result<R, VfsError>,
) -> Result<R, VfsError> {
    if let Some(container) = process.container() {
        return f(container.vfs().as_ref());
    }
    with_vfs(f)
}

pub fn open_path(pid: ProcessId, raw_path: &str) -> Result<Fd, VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    let file = with_process_vfs(&process, |vfs| match vfs.open_absolute(&abs)? {
        NodeRef::File(file) => Ok(file),
        NodeRef::Directory(_) | NodeRef::Symlink(_) => Err(VfsError::NotFile),
    })?;
    process.fd_table().open_file(file)
}

pub fn open_path_with_create(pid: ProcessId, raw_path: &str) -> Result<Fd, VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    match with_process_vfs(&process, |vfs| vfs.open_absolute(&abs)) {
        Ok(NodeRef::File(file)) => process.fd_table().open_file(file),
        Ok(NodeRef::Directory(_)) | Ok(NodeRef::Symlink(_)) => Err(VfsError::NotFile),
        Err(VfsError::NotFound) => {
            let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
            let name = abs
                .components()
                .last()
                .ok_or(VfsError::InvalidPath)?
                .as_str()
                .to_string();
            let dir = with_process_vfs(&process, |vfs| match vfs.open_absolute(&parent)? {
                NodeRef::Directory(dir) => Ok(dir),
                NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
            })?;
            let file = dir.create_file(&name)?;
            process.fd_table().open_file(file)
        }
        Err(err) => Err(err),
    }
}

pub fn read_fd(pid: ProcessId, fd: Fd, buf: &mut [u8]) -> Result<usize, VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().read(fd, buf)
}

pub fn write_fd(pid: ProcessId, fd: Fd, data: &[u8]) -> Result<usize, VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().write(fd, data)
}

pub fn close_fd(pid: ProcessId, fd: Fd) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    process.fd_table().close(fd)
}

pub fn change_dir(pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    let dir = with_process_vfs(&process, |vfs| match vfs.open_absolute(&abs)? {
        NodeRef::Directory(dir) => Ok(dir),
        NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
    })?;
    process.set_cwd(abs);
    // Keep dir alive by ensuring mount lookup remains valid; cwd path suffices.
    drop(dir);
    Ok(())
}

pub fn list_dir(pid: ProcessId, raw_path: &str) -> Result<Vec<DirEntry>, VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    with_process_vfs(&process, |vfs| vfs.read_dir(&abs))
}

pub fn remove_path(pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
    let name = abs
        .components()
        .last()
        .ok_or(VfsError::InvalidPath)?
        .as_str()
        .to_string();
    let dir = with_process_vfs(&process, |vfs| match vfs.open_absolute(&parent)? {
        NodeRef::Directory(dir) => Ok(dir),
        NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
    })?;
    dir.remove(&name)
}

pub fn write_path(pid: ProcessId, raw_path: &str, data: &[u8]) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    match with_process_vfs(&process, |vfs| vfs.open_absolute(&abs)) {
        Ok(NodeRef::File(f)) => {
            f.truncate(0)?;
            let _ = f.write_at(0, data)?;
            Ok(())
        }
        Ok(NodeRef::Directory(_)) | Ok(NodeRef::Symlink(_)) => Err(VfsError::NotFile),
        Err(VfsError::NotFound) => {
            let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
            let name = abs
                .components()
                .last()
                .ok_or(VfsError::InvalidPath)?
                .as_str()
                .to_string();
            let dir = with_process_vfs(&process, |vfs| match vfs.open_absolute(&parent)? {
                NodeRef::Directory(dir) => Ok(dir),
                NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
            })?;
            let file = dir.create_file(&name)?;
            file.truncate(0)?;
            let _ = file.write_at(0, data)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub fn create_dir(pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
    let name = abs
        .components()
        .last()
        .ok_or(VfsError::InvalidPath)?
        .as_str()
        .to_string();
    let dir = with_process_vfs(&process, |vfs| match vfs.open_absolute(&parent)? {
        NodeRef::Directory(dir) => Ok(dir),
        NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
    })?;
    match dir.create_dir(&name) {
        Ok(_) => Ok(()),
        Err(VfsError::AlreadyExists) => Ok(()),
        Err(err) => Err(err),
    }
}

pub fn symlink(pid: ProcessId, target: &str, link_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let link_abs = VfsPath::resolve(link_path, &process.cwd())?;
    let parent = link_abs.parent().ok_or(VfsError::InvalidPath)?;
    let name = link_abs
        .components()
        .last()
        .ok_or(VfsError::InvalidPath)?
        .as_str()
        .to_string();

    let dir = with_process_vfs(&process, |vfs| match vfs.open_absolute(&parent)? {
        NodeRef::Directory(dir) => Ok(dir),
        NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
    })?;

    dir.create_symlink(&name, target)?;
    Ok(())
}

pub fn hard_link(pid: ProcessId, existing_path: &str, link_path: &str) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let src_abs = VfsPath::resolve(existing_path, &process.cwd())?;
    let link_abs = VfsPath::resolve(link_path, &process.cwd())?;

    let parent = link_abs.parent().ok_or(VfsError::InvalidPath)?;
    let name = link_abs
        .components()
        .last()
        .ok_or(VfsError::InvalidPath)?
        .as_str()
        .to_string();

    let (node, dir) = with_process_vfs(&process, |vfs| {
        let node = match vfs.open_absolute(&src_abs)? {
            NodeRef::File(f) => NodeRef::File(f),
            NodeRef::Directory(_) => return Err(VfsError::NotDirectory),
            NodeRef::Symlink(_) => return Err(VfsError::NotFile),
        };
        let dir = match vfs.open_absolute(&parent)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
        }?;
        Ok((node, dir))
    })?;

    dir.link(&name, node)
}

pub fn read_to_end(pid: ProcessId, raw_path: &str) -> Result<Vec<u8>, VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    read_to_end_at(pid, &abs)
}

pub fn read_to_end_at(pid: ProcessId, path: &VfsPath) -> Result<Vec<u8>, VfsError> {
    let process = process_handle(pid)?;
    with_process_vfs(&process, |vfs| read_to_end_with_vfs(vfs, path))
}

pub fn cwd(pid: ProcessId) -> Result<VfsPath, VfsError> {
    let process = process_handle(pid)?;
    Ok(process.cwd())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::CONTAINER_TABLE;
    use crate::fs::Directory;
    use crate::fs::force_replace_root;
    use crate::fs::memfs::MemDirectory;
    use crate::println;
    use crate::process::PROCESS_TABLE;
    use crate::syscall::Abi;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn container_process_reads_container_vfs() {
        println!("[test] container_process_reads_container_vfs");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        CONTAINER_TABLE.clear_for_tests();

        let bundle_dir = root.create_dir("bundle").expect("create bundle dir");
        let rootfs_dir = bundle_dir.create_dir("rootfs").expect("create rootfs dir");
        let container_file = rootfs_dir
            .create_file("shadow.txt")
            .expect("create container file");
        let _ = container_file
            .write_at(0, b"container")
            .expect("write container file");

        let host_file = root
            .create_file("shadow.txt")
            .expect("create host file");
        let _ = host_file.write_at(0, b"host").expect("write host file");

        let config = bundle_dir
            .create_file("config.json")
            .expect("create config");
        config
            .write_at(0, br#"{"ociVersion":"1.0.2","root":{"path":"rootfs"}}"#)
            .expect("write config");

        let container = CONTAINER_TABLE
            .create("demo", "/bundle")
            .expect("create container");

        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process_with_abi_in_container("cont-proc", Abi::Linux, container)
            .expect("create container process");

        let fd = open_path(pid, "/shadow.txt").expect("open container file");
        let mut buf = [0u8; 16];
        let read = read_fd(pid, fd, &mut buf).expect("read container file");
        let _ = close_fd(pid, fd);
        assert_eq!(&buf[..read], b"container");
    }
}
