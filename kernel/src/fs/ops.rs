use alloc::{collections::BTreeMap, sync::Arc};

use super::{Directory, File, NodeRef, PathComponent, VfsError};

pub fn copy_directory_recursive(
    source: Arc<dyn Directory>,
    dest: Arc<dyn Directory>,
) -> Result<(), VfsError> {
    let mut hardlink_map = BTreeMap::new();
    copy_directory_recursive_inner(source, dest, &mut hardlink_map)
}

fn copy_directory_recursive_inner(
    source: Arc<dyn Directory>,
    dest: Arc<dyn Directory>,
    hardlink_map: &mut BTreeMap<usize, Arc<dyn File>>,
) -> Result<(), VfsError> {
    let entries = source.read_dir()?;
    for entry in entries {
        let name = entry.name;
        let node = source.lookup(&PathComponent::new(&name))?;
        match node {
            NodeRef::Directory(dir) => {
                let new_dir = dest.create_dir(&name)?;
                copy_directory_recursive_inner(dir, new_dir, hardlink_map)?;
            }
            NodeRef::File(file) => {
                let key = Arc::as_ptr(&file) as *const () as usize;
                if let Some(existing) = hardlink_map.get(&key) {
                    dest.link(&name, NodeRef::File(existing.clone()))?;
                    continue;
                }

                let size = file.metadata()?.size;
                let new_file = dest.create_file(&name)?;
                let size = usize::try_from(size).map_err(|_| VfsError::Corrupted)?;
                copy_file_contents(&file, &new_file, size)?;
                hardlink_map.insert(key, new_file);
            }
            NodeRef::Symlink(link) => {
                let target = link.target()?;
                let _ = dest.create_symlink(&name, &target)?;
            }
            NodeRef::Device(_) => {
                // Skip device nodes while copying into container-owned filesystems.
            }
        }
    }
    Ok(())
}

pub fn copy_file_contents(
    source: &Arc<dyn File>,
    dest: &Arc<dyn File>,
    size: usize,
) -> Result<(), VfsError> {
    let mut offset = 0usize;
    let mut buf = [0u8; 4096];
    while offset < size {
        let to_read = core::cmp::min(buf.len(), size - offset);
        let read = source.read_at(offset, &mut buf[..to_read])?;
        if read == 0 {
            return Err(VfsError::UnexpectedEof);
        }
        dest.write_at(offset, &buf[..read])?;
        offset += read;
    }
    Ok(())
}
