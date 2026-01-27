use alloc::{collections::BTreeMap, sync::Arc};

use super::{File, Node, NodeKind, OpenOptions, PathComponent, VfsError};

pub fn copy_directory_recursive(
    source: Arc<dyn Node>,
    dest: Arc<dyn Node>,
) -> Result<(), VfsError> {
    let mut hardlink_map = BTreeMap::new();
    copy_directory_recursive_inner(source, dest, &mut hardlink_map)
}

fn copy_directory_recursive_inner(
    source: Arc<dyn Node>,
    dest: Arc<dyn Node>,
    hardlink_map: &mut BTreeMap<usize, Arc<dyn Node>>,
) -> Result<(), VfsError> {
    let src_dir = source.as_dir().ok_or(VfsError::NotDirectory)?;
    let dest_dir = dest.as_dir().ok_or(VfsError::NotDirectory)?;

    let entries = src_dir.read_dir()?;
    for entry in entries {
        let name = entry.name;
        let node = src_dir.lookup(&PathComponent::new(&name))?;
        if node.as_dir().is_some() {
            let new_dir = dest_dir.create_dir(&name)?;
            copy_directory_recursive_inner(node, new_dir, hardlink_map)?;
            continue;
        }

        match node.kind() {
            NodeKind::Regular => {
                let key = Arc::as_ptr(&node) as *const () as usize;
                if let Some(existing) = hardlink_map.get(&key) {
                    dest_dir.link(&name, existing.clone())?;
                    continue;
                }

                let stat = node.stat()?;
                let new_file = dest_dir.create_file(&name)?;
                let size = usize::try_from(stat.size).map_err(|_| VfsError::Corrupted)?;
                copy_file_contents(&node, &new_file, size)?;
                hardlink_map.insert(key, new_file);
            }
            NodeKind::Symlink => {
                let link = node.as_symlink().ok_or(VfsError::InvalidPath)?;
                let target = link.readlink()?;
                let _ = dest_dir.create_symlink(&name, &target)?;
            }
            NodeKind::CharDevice | NodeKind::BlockDevice | NodeKind::Pipe | NodeKind::Socket => {
                // Skip special nodes while copying into container-owned filesystems.
            }
            NodeKind::Directory => return Err(VfsError::Corrupted),
        }
    }
    Ok(())
}

pub fn copy_file_contents(
    source: &Arc<dyn Node>,
    dest: &Arc<dyn Node>,
    size: usize,
) -> Result<(), VfsError> {
    let src_file = source.clone().open(OpenOptions::new(0))?;
    let dst_file = dest.clone().open(OpenOptions::new(0))?;
    copy_file_contents_with_files(&src_file, &dst_file, size)
}

pub fn copy_file_contents_with_files(
    source: &Arc<dyn File>,
    dest: &Arc<dyn File>,
    size: usize,
) -> Result<(), VfsError> {
    let mut remaining = size;
    let mut buf = [0u8; 4096];
    while remaining > 0 {
        let to_read = core::cmp::min(buf.len(), remaining);
        let read = source.read(&mut buf[..to_read])?;
        if read == 0 {
            return Err(VfsError::UnexpectedEof);
        }
        let mut written = 0usize;
        while written < read {
            let chunk = dest.write(&buf[written..read])?;
            if chunk == 0 {
                return Err(VfsError::UnexpectedEof);
            }
            written += chunk;
        }
        remaining -= read;
    }
    Ok(())
}
