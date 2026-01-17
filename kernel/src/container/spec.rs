use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use oci_spec::runtime::Spec;
use serde_json::Value;

use crate::fs::memfs::MemDirectory;
use crate::fs::{
    Directory, File, NodeRef, PathComponent, Vfs, VfsError, VfsPath, read_to_end, with_vfs,
};

use super::ContainerError;

pub struct SpecLoader;

#[derive(Debug, Clone)]
pub struct SpecMetadata {
    pub oci_version: String,
    pub annotations: BTreeMap<String, String>,
}

impl SpecLoader {
    pub fn load(bundle_path: &VfsPath) -> Result<Spec, ContainerError> {
        let config_path = bundle_path.join(&VfsPath::parse("config.json")?)?;
        let bytes = read_to_end(&config_path)?;
        let text = core::str::from_utf8(&bytes).map_err(|_| ContainerError::ConfigNotUtf8)?;

        // Parse JSON into a Value first, then deserialize into Spec to reduce stack usage.
        let json_value: Value =
            serde_json::from_str(text).map_err(|_| ContainerError::ConfigParseFailed)?;
        let spec: Spec =
            serde_json::from_value(json_value).map_err(|_| ContainerError::ConfigParseFailed)?;

        Ok(spec)
    }

    /// Builds a container-scoped VFS rooted at the bundle's rootfs directory.
    ///
    /// This uses the global VFS to locate the rootfs entry inside the bundle, then copies the
    /// directory tree into a container-owned memfs instance so storage is fully isolated.
    pub fn build_container_vfs(
        bundle_path: &VfsPath,
        spec: &Spec,
    ) -> Result<Arc<Vfs>, ContainerError> {
        let root = spec.root().as_ref().ok_or(ContainerError::MissingRoot)?;
        let root_path = VfsPath::parse(root.path())?;
        let abs = if root_path.is_absolute() {
            root_path
        } else {
            bundle_path.join(&root_path)?
        };

        let rootfs = with_vfs(|vfs| match vfs.open_absolute(&abs)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
        })
        .map_err(ContainerError::Vfs)?;

        let container_root = MemDirectory::new();
        copy_directory_recursive(rootfs, container_root.clone()).map_err(ContainerError::Vfs)?;

        Ok(Arc::new(Vfs::new(container_root)))
    }

    pub fn metadata(spec: &Spec) -> SpecMetadata {
        SpecMetadata {
            oci_version: spec.version().to_string(),
            annotations: spec.annotations().clone().unwrap_or_default(),
        }
    }
}

fn copy_directory_recursive(
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

fn copy_file_contents(source: &Arc<dyn File>, dest: &Arc<dyn File>) -> Result<(), VfsError> {
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
