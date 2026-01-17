use alloc::sync::Arc;

use crate::fs::{Directory, Vfs};

#[derive(Clone)]
pub struct ContainerContext {
    vfs: Arc<Vfs>,
}

impl ContainerContext {
    pub fn new(vfs: Arc<Vfs>) -> Self {
        Self { vfs }
    }

    pub fn rootfs(&self) -> Arc<dyn Directory> {
        self.vfs.root()
    }

    pub fn vfs(&self) -> Arc<Vfs> {
        self.vfs.clone()
    }
}
