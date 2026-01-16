use alloc::string::ToString;
use alloc::sync::Arc;

use crate::container::{Container, ContainerContext, ContainerState, ContainerStatus};
use crate::fs::VfsPath;

use super::ContainerError;
use super::repository::ContainerRepository;
use super::spec::SpecLoader;

pub struct ContainerTable {
    repo: ContainerRepository,
}

impl ContainerTable {
    pub const fn new() -> Self {
        Self {
            repo: ContainerRepository::new(),
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

        let spec = SpecLoader::load(&bundle)?;
        let meta = SpecLoader::metadata(&spec);
        let state = ContainerState {
            oci_version: meta.oci_version,
            id: id.to_string(),
            status: ContainerStatus::Created,
            pid: None,
            bundle_path: bundle.to_string(),
            annotations: meta.annotations,
        };
        let rootfs = SpecLoader::resolve_rootfs(&bundle, &spec)?;
        let context = ContainerContext::new(rootfs);
        let container = Arc::new(Container::new(state, spec, context));

        self.repo.insert(id, container)
    }

    pub fn get(&self, id: &str) -> Option<Arc<Container>> {
        self.repo.get(id)
    }

    #[cfg(test)]
    pub fn clear_for_tests(&self) {
        self.repo.clear_for_tests();
    }
}

impl Default for ContainerTable {
    fn default() -> Self {
        Self::new()
    }
}

pub static CONTAINER_TABLE: ContainerTable = ContainerTable::new();

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
