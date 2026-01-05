use alloc::string::String;
use alloc::sync::Arc;

use crate::util::spinlock::SpinLock;
use oci_spec::runtime::Spec;

pub mod context;
pub mod state;
mod table;

pub use context::ContainerContext;
pub use state::{ContainerState, ContainerStatus};
pub use table::{CONTAINER_TABLE, ContainerError, ContainerTable};

pub struct Container {
    state: SpinLock<ContainerState>,
    spec: Spec,
    context: SpinLock<ContainerContext>,
}

impl Container {
    pub fn new(state: ContainerState, spec: Spec, context: ContainerContext) -> Self {
        Self {
            state: SpinLock::new(state),
            spec,
            context: SpinLock::new(context),
        }
    }

    pub fn id(&self) -> String {
        self.state.lock().id.clone()
    }

    pub fn state(&self) -> ContainerState {
        self.state.lock().clone()
    }

    pub fn spec(&self) -> &Spec {
        &self.spec
    }

    pub fn context(&self) -> ContainerContext {
        self.context.lock().clone()
    }

    pub fn rootfs(&self) -> Arc<dyn crate::fs::Directory> {
        self.context.lock().rootfs()
    }
}
