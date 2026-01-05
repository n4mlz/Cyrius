use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use oci_spec::runtime::Spec;
use serde_json::Value;

use crate::container::{Container, ContainerContext, ContainerState, ContainerStatus};
use crate::fs::{Directory, NodeRef, VfsError, VfsPath, with_vfs};
use crate::util::spinlock::SpinLock;

#[derive(Debug)]
pub enum ContainerError {
    DuplicateId,
    InvalidId,
    BundlePathNotAbsolute,
    MissingRoot,
    Vfs(VfsError),
    ConfigNotUtf8,
    ConfigParseFailed,
}

impl From<VfsError> for ContainerError {
    fn from(err: VfsError) -> Self {
        Self::Vfs(err)
    }
}

pub struct ContainerTable {
    inner: SpinLock<BTreeMap<String, Arc<Container>>>,
}

impl ContainerTable {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Create a container from an OCI bundle and store it in the global table.
    ///
    /// The bundle path must be absolute and must contain a readable `config.json` file in the
    /// global VFS. The config is parsed using `oci-spec` in `no_std` mode and stored as static
    /// metadata.
    pub fn create(&self, id: &str, bundle_path: &str) -> Result<Arc<Container>, ContainerError> {
        if id.is_empty() {
            return Err(ContainerError::InvalidId);
        }

        let bundle = VfsPath::parse(bundle_path)?;
        if !bundle.is_absolute() {
            return Err(ContainerError::BundlePathNotAbsolute);
        }

        let spec = load_spec(&bundle)?;
        let state = ContainerState {
            oci_version: spec_oci_version(&spec),
            id: id.to_string(),
            status: ContainerStatus::Created,
            pid: None,
            bundle_path: bundle.to_string(),
            annotations: spec_annotations(&spec),
        };
        let rootfs = resolve_rootfs(&bundle, &spec)?;
        let context = ContainerContext::new(rootfs);
        let container = Arc::new(Container::new(state, spec, context));

        let mut guard = self.inner.lock();
        if guard.contains_key(id) {
            return Err(ContainerError::DuplicateId);
        }
        guard.insert(id.to_string(), container.clone());
        Ok(container)
    }

    pub fn get(&self, id: &str) -> Option<Arc<Container>> {
        let guard = self.inner.lock();
        guard.get(id).cloned()
    }

    #[cfg(test)]
    pub fn clear_for_tests(&self) {
        let mut guard = self.inner.lock();
        guard.clear();
    }
}

impl Default for ContainerTable {
    fn default() -> Self {
        Self::new()
    }
}

pub static CONTAINER_TABLE: ContainerTable = ContainerTable::new();

fn load_spec(bundle_path: &VfsPath) -> Result<Spec, ContainerError> {
    let config_path = bundle_path.join(&VfsPath::parse("config.json")?)?;
    let bytes = read_file(&config_path)?;
    let text = core::str::from_utf8(&bytes).map_err(|_| ContainerError::ConfigNotUtf8)?;

    // Parse JSON into a Value first, then deserialize into Spec.
    // This two-step approach avoids stack overflow issues that occur when
    // deserializing directly from a string into Spec.
    let json_value: Value =
        serde_json::from_str(text).map_err(|_| ContainerError::ConfigParseFailed)?;
    let spec: Spec =
        serde_json::from_value(json_value).map_err(|_| ContainerError::ConfigParseFailed)?;

    Ok(spec)
}

fn resolve_rootfs(
    bundle_path: &VfsPath,
    spec: &Spec,
) -> Result<Arc<dyn Directory>, ContainerError> {
    let root = spec.root().as_ref().ok_or(ContainerError::MissingRoot)?;
    let root_path = VfsPath::parse(root.path())?;
    let abs = if root_path.is_absolute() {
        root_path
    } else {
        bundle_path.join(&root_path)?
    };

    with_vfs(|vfs| match vfs.open_absolute(&abs)? {
        NodeRef::Directory(dir) => Ok(dir),
        NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
    })
    .map_err(ContainerError::Vfs)
}

fn read_file(path: &VfsPath) -> Result<Vec<u8>, ContainerError> {
    let file = with_vfs(|vfs| match vfs.open_absolute(path)? {
        NodeRef::File(file) => Ok(file),
        NodeRef::Directory(_) | NodeRef::Symlink(_) => Err(VfsError::NotFile),
    })?;
    let meta = file.metadata()?;
    let size = usize::try_from(meta.size).map_err(|_| ContainerError::Vfs(VfsError::Corrupted))?;
    let mut buf = vec![0u8; size];
    let mut offset = 0usize;
    while offset < size {
        let read = file.read_at(offset, &mut buf[offset..])?;
        if read == 0 {
            break;
        }
        offset = offset.saturating_add(read);
    }
    buf.truncate(offset);
    Ok(buf)
}

fn spec_oci_version(spec: &Spec) -> String {
    spec.version().to_string()
}

fn spec_annotations(spec: &Spec) -> BTreeMap<String, String> {
    spec.annotations().clone().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Directory;
    use crate::fs::force_replace_root;
    use crate::fs::memfs::MemDirectory;
    use crate::println;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn create_container_reads_spec_and_initializes_state() {
        println!("[test] create_container_reads_spec_and_initializes_state");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        CONTAINER_TABLE.clear_for_tests();

        let bundle_dir = root.create_dir("bundle").expect("create bundle dir");
        let _ = bundle_dir.create_dir("rootfs").expect("create rootfs dir");
        let config = bundle_dir
            .create_file("config.json")
            .expect("create config");
        let json =
            br#"{"ociVersion":"1.0.2","root":{"path":"rootfs"},"annotations":{"org.example/foo":"bar"}}"#;
        config.write_at(0, json).expect("write config");

        let container = CONTAINER_TABLE
            .create("demo", "/bundle")
            .expect("create container");
        assert_eq!(container.id(), "demo");

        let state = container.state();
        assert_eq!(state.status, ContainerStatus::Created);
        assert_eq!(state.bundle_path, "/bundle");
        assert_eq!(state.oci_version, "1.0.2");
        assert_eq!(
            state.annotations.get("org.example/foo"),
            Some(&"bar".to_string())
        );
        assert!(state.pid.is_none());
    }

    #[kernel_test_case]
    fn create_rejects_duplicate_ids() {
        println!("[test] create_rejects_duplicate_ids");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        CONTAINER_TABLE.clear_for_tests();

        let bundle_dir = root.create_dir("bundle").expect("create bundle dir");
        let _ = bundle_dir.create_dir("rootfs").expect("create rootfs dir");
        let config = bundle_dir
            .create_file("config.json")
            .expect("create config");
        config
            .write_at(0, br#"{"ociVersion":"1.0.2","root":{"path":"rootfs"}}"#)
            .expect("write config");

        CONTAINER_TABLE
            .create("dup", "/bundle")
            .expect("create container");
        match CONTAINER_TABLE.create("dup", "/bundle") {
            Err(ContainerError::DuplicateId) => {}
            _ => panic!("unexpected result"),
        }
    }
}
