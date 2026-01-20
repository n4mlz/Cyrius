use alloc::string::ToString;
use alloc::vec::Vec;

use crate::fs::{DirEntry, Fd, NodeRef, VfsError, VfsPath, with_vfs};

use super::{PROCESS_TABLE, ProcessHandle, ProcessId};

fn process_handle(pid: ProcessId) -> Result<ProcessHandle, VfsError> {
    PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| VfsError::NotFound)
}

pub fn open_path(pid: ProcessId, raw_path: &str) -> Result<Fd, VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    let file = with_vfs(|vfs| match vfs.open_absolute(&abs)? {
        NodeRef::File(file) => Ok(file),
        NodeRef::Directory(_) | NodeRef::Symlink(_) => Err(VfsError::NotFile),
    })?;
    process.fd_table().open_file(file)
}

pub fn open_path_with_create(pid: ProcessId, raw_path: &str) -> Result<Fd, VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    match with_vfs(|vfs| vfs.open_absolute(&abs)) {
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
            let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
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
    let dir = with_vfs(|vfs| match vfs.open_absolute(&abs)? {
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
    with_vfs(|vfs| vfs.read_dir(&abs))
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
    let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
        NodeRef::Directory(dir) => Ok(dir),
        NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
    })?;
    dir.remove(&name)
}

pub fn write_path(pid: ProcessId, raw_path: &str, data: &[u8]) -> Result<(), VfsError> {
    let process = process_handle(pid)?;
    let abs = VfsPath::resolve(raw_path, &process.cwd())?;
    match with_vfs(|vfs| vfs.open_absolute(&abs)) {
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
            let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
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
    let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
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

    let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
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

    let (node, dir) = with_vfs(|vfs| {
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

pub fn cwd(pid: ProcessId) -> Result<VfsPath, VfsError> {
    let process = process_handle(pid)?;
    Ok(process.cwd())
}
