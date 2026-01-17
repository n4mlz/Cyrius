use alloc::sync::Arc;

use super::{Directory, File, NodeRef, PathComponent, VfsError};

pub fn copy_directory_recursive(
    source: Arc<dyn Directory>,
    dest: Arc<dyn Directory>,
) -> Result<(), VfsError> {
    let entries = source.read_dir()?;
    for entry in entries {
        let name = entry.name;
        let node = source.lookup(&PathComponent::new(&name))?;
        match node {
            NodeRef::Directory(dir) => {
                let new_dir = dest.create_dir(&name)?;
                copy_directory_recursive(dir, new_dir)?;
            }
            NodeRef::File(file) => {
                let new_file = dest.create_file(&name)?;
                copy_file_contents(&file, &new_file)?;
            }
            NodeRef::Symlink(link) => {
                let target = link.target()?;
                let _ = dest.create_symlink(&name, &target)?;
            }
        }
    }
    Ok(())
}

pub fn copy_file_contents(source: &Arc<dyn File>, dest: &Arc<dyn File>) -> Result<(), VfsError> {
    let size = usize::try_from(source.metadata()?.size).map_err(|_| VfsError::Corrupted)?;
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
