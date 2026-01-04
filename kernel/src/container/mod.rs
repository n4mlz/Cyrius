use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use oci_spec::runtime::Spec;

use crate::fs::memfs::MemDirectory;
use crate::fs::{Directory, NodeRef, VfsError, VfsPath, with_vfs};
use crate::process::ProcessId;
use crate::util::spinlock::SpinLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStatus {
    Created,
    Running,
    Stopped,
}

impl ContainerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerState {
    pub oci_version: String,
    pub id: String,
    pub status: ContainerStatus,
    pub pid: Option<ProcessId>,
    pub bundle_path: String,
    pub annotations: BTreeMap<String, String>,
}

pub struct Container {
    id: String,
    info: ContainerInfo,
    state: SpinLock<ContainerState>,
}

struct ContainerInfo {
    bundle_path: String,
    spec: Spec,
    rootfs: Arc<dyn Directory>,
}

impl Container {
    fn new(id: String, bundle_path: String, spec: Spec, rootfs: Arc<dyn Directory>) -> Self {
        let annotations = spec_annotations(&spec);
        let state = ContainerState {
            oci_version: spec_oci_version(&spec),
            id: id.clone(),
            status: ContainerStatus::Created,
            pid: None,
            bundle_path: bundle_path.clone(),
            annotations,
        };
        Self {
            id,
            info: ContainerInfo {
                bundle_path,
                spec,
                rootfs,
            },
            state: SpinLock::new(state),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn bundle_path(&self) -> &str {
        &self.info.bundle_path
    }

    pub fn spec(&self) -> &Spec {
        &self.info.spec
    }

    pub fn rootfs(&self) -> Arc<dyn Directory> {
        self.info.rootfs.clone()
    }

    pub fn state(&self) -> ContainerState {
        self.state.lock().clone()
    }
}

#[derive(Debug)]
pub enum ContainerError {
    DuplicateId,
    InvalidId,
    BundlePathNotAbsolute,
    Vfs(VfsError),
    ConfigNotUtf8,
    ConfigParseFailed,
}

impl From<VfsError> for ContainerError {
    fn from(err: VfsError) -> Self {
        Self::Vfs(err)
    }
}

pub struct ContainerRegistry {
    inner: SpinLock<BTreeMap<String, Arc<Container>>>,
}

impl ContainerRegistry {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Create a container from an OCI bundle and register it in the global table.
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
        let rootfs = MemDirectory::new();
        let container = Arc::new(Container::new(
            id.to_string(),
            bundle.to_string(),
            spec,
            rootfs,
        ));

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

pub static CONTAINERS: ContainerRegistry = ContainerRegistry::new();

fn load_spec(bundle_path: &VfsPath) -> Result<Spec, ContainerError> {
    let config_path = bundle_path.join(&VfsPath::parse("config.json")?)?;
    let bytes = read_file(&config_path)?;
    let text = core::str::from_utf8(&bytes).map_err(|_| ContainerError::ConfigNotUtf8)?;
    serde_json::from_str(text).map_err(|_| ContainerError::ConfigParseFailed)
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
    use crate::fs::force_replace_root;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn create_container_reads_spec_and_initializes_state() {
        let root = MemDirectory::new();
        force_replace_root(root.clone());
        CONTAINERS.clear_for_tests();

        let bundle_dir = root.create_dir("bundle").expect("create bundle dir");
        let config = bundle_dir
            .create_file("config.json")
            .expect("create config");
        let json = br#"{"ociVersion":"1.0.2","annotations":{"org.example/foo":"bar"}}"#;
        config.write_at(0, json).expect("write config");

        let container = CONTAINERS
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
        let root = MemDirectory::new();
        force_replace_root(root.clone());
        CONTAINERS.clear_for_tests();

        let bundle_dir = root.create_dir("bundle").expect("create bundle dir");
        let config = bundle_dir
            .create_file("config.json")
            .expect("create config");
        config
            .write_at(0, br#"{"ociVersion":"1.0.2"}"#)
            .expect("write config");

        CONTAINERS
            .create("dup", "/bundle")
            .expect("create container");
        match CONTAINERS.create("dup", "/bundle") {
            Err(ContainerError::DuplicateId) => {}
            _ => panic!("unexpected result"),
        }
    }
}
