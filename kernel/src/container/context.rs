use alloc::sync::Arc;

use crate::fs::Directory;

#[derive(Clone)]
pub struct ContainerContext {
    rootfs: Arc<dyn Directory>,
}

impl ContainerContext {
    pub fn new(rootfs: Arc<dyn Directory>) -> Self {
        Self { rootfs }
    }

    pub fn rootfs(&self) -> Arc<dyn Directory> {
        self.rootfs.clone()
    }
}
