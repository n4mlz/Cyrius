use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use oci_spec::runtime::Spec;
use serde_json::Value;

use crate::fs::memfs::MemDirectory;
use crate::fs::ops::copy_directory_recursive;
use crate::fs::{NodeRef, Vfs, VfsError, VfsPath, read_to_end, with_vfs};

use super::{CONTAINER_VFS_BACKING, ContainerError, ContainerVfsBacking};

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

        let container_root = match CONTAINER_VFS_BACKING {
            ContainerVfsBacking::Ramfs => MemDirectory::new(),
        };
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
