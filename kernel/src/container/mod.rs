use alloc::string::String;
use alloc::sync::Arc;

use crate::util::spinlock::SpinLock;
use oci_spec::runtime::Spec;

pub mod runtime;
pub mod state;
mod table;

pub use runtime::ContainerRuntime;
pub use state::{ContainerState, ContainerStatus};
pub use table::{CONTAINER_TABLE, ContainerError, ContainerTable};

pub struct Container {
    state: SpinLock<ContainerState>,
    spec: Spec,
    runtime: SpinLock<ContainerRuntime>,
}

impl Container {
    pub fn new(state: ContainerState, spec: Spec, runtime: ContainerRuntime) -> Self {
        Self {
            state: SpinLock::new(state),
            spec,
            runtime: SpinLock::new(runtime),
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

    pub fn runtime(&self) -> ContainerRuntime {
        self.runtime.lock().clone()
    }

    pub fn rootfs(&self) -> Arc<dyn crate::fs::Directory> {
        self.runtime.lock().rootfs()
    }
}
