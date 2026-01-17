use alloc::string::String;
use alloc::sync::Arc;

use crate::util::spinlock::SpinLock;
use oci_spec::runtime::Spec;

pub mod context;
mod error;
mod repository;
mod spec;
pub mod state;
mod table;

pub use context::ContainerContext;
pub use error::ContainerError;
pub use repository::ContainerRepository;
pub use spec::{SpecLoader, SpecMetadata};
pub use state::{ContainerState, ContainerStatus};
pub use table::{CONTAINER_TABLE, ContainerTable};

struct ContainerMutable {
    state: ContainerState,
    context: ContainerContext,
}

pub struct Container {
    mutable: SpinLock<ContainerMutable>,
    spec: Arc<Spec>,
}

impl Container {
    pub fn new(state: ContainerState, spec: Spec, context: ContainerContext) -> Self {
        Self {
            mutable: SpinLock::new(ContainerMutable { state, context }),
            spec: Arc::new(spec),
        }
    }

    pub fn id(&self) -> String {
        self.mutable.lock().state.id.clone()
    }

    pub fn state(&self) -> ContainerState {
        self.mutable.lock().state.clone()
    }

    pub fn spec(&self) -> &Spec {
        self.spec.as_ref()
    }

    pub fn context(&self) -> ContainerContext {
        self.mutable.lock().context.clone()
    }

    pub fn vfs(&self) -> Arc<crate::fs::Vfs> {
        self.mutable.lock().context.vfs()
    }

    pub fn rootfs(&self) -> Arc<dyn crate::fs::Directory> {
        self.mutable.lock().context.rootfs()
    }
}
